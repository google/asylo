/*
 *
 * Copyright 2019 Asylo authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include "asylo/platform/primitives/sgx/untrusted_sgx.h"

#include <sys/mman.h>
#include <unistd.h>

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "asylo/platform/primitives/sgx/exit_handlers.h"
#include "asylo/platform/primitives/sgx/generated_bridge_u.h"
#include "asylo/platform/primitives/sgx/sgx_errors.h"
#include "asylo/platform/primitives/sgx/sgx_params.h"
#include "asylo/platform/primitives/sgx/signal_dispatcher.h"
#include "asylo/platform/primitives/untrusted_primitives.h"
#include "asylo/platform/primitives/util/message.h"
#include "asylo/util/cleanup.h"
#include "asylo/util/elf_reader.h"
#include "asylo/util/file_mapping.h"
#include "asylo/util/function_deleter.h"
#include "asylo/util/status.h"
#include "asylo/util/status_helpers.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace primitives {

namespace {

constexpr absl::string_view kCallingProcessBinaryFile = "/proc/self/exe";

// |forked_loader_callback| allows to statically store a callback function that
// is responsible for creating a new enclave in the forked child process. The
// callback should load the enclave with the provided enclave name, enclave size
// and virtual base address, which should be the same as the parent enclave. The
// child enclave's primitive client should not set the current_client to itself;
// that is the responsibility of the caller.
// We prefer a C-style function pointer for forked_loader_callback_t since it is
// trivially destructible when used statically.
forked_loader_callback_t forked_loader_callback;

constexpr int kMaxEnclaveCreateAttempts = 5;
constexpr size_t kPageSize = 4096;

// Enters the enclave and invokes the secure snapshot key transfer entry-point.
// If the ecall fails, return a non-OK status.
static Status TransferSecureSnapshotKey(sgx_enclave_id_t eid, const char *input,
                                        size_t input_len, char **output,
                                        size_t *output_len) {
  uint64_t bridge_output_len;
  int retval = 0;
  sgx_status_t sgx_status = ecall_transfer_secure_snapshot_key(
      eid, &retval, input, input_len, output, &bridge_output_len);
  if (output_len) {
    *output_len = static_cast<size_t>(bridge_output_len);
  }
  if (sgx_status != SGX_SUCCESS) {
    return SgxError(sgx_status, "Call to ecall_do_handshake failed");
  } else if (retval || !output_len || *output_len == 0) {
    // Ecall succeeded but did not return a value. This indicates that the
    // trusted code failed to propagate error information over the enclave
    // boundary.
    return absl::InternalError("No output from enclave");
  }
  return absl::OkStatus();
}

// Enters the enclave and invokes the snapshotting entry-point. If the ecall
// fails, return a non-OK status.
static Status TakeSnapshot(sgx_enclave_id_t eid, char **output,
                           size_t *output_len) {
  uint64_t bridge_output_len;
  int retval = 0;
  sgx_status_t sgx_status =
      ecall_take_snapshot(eid, &retval, output, &bridge_output_len);

  if (output_len) {
    *output_len = static_cast<size_t>(bridge_output_len);
  }
  if (sgx_status != SGX_SUCCESS) {
    return SgxError(sgx_status, "Call to ecall_take_snapshot failed");
  } else if (retval || !output_len || *output_len == 0) {
    // Ecall succeeded but did not return a value. This indicates that the
    // trusted code failed to propagate error information over the enclave
    // boundary.
    return absl::InternalError("No output from enclave");
  }

  return absl::OkStatus();
}

// Enters the enclave and invokes the restoring entry-point. If the ecall fails,
// return a non-OK status.
static Status Restore(sgx_enclave_id_t eid, const char *input, size_t input_len,
                      char **output, size_t *output_len) {
  uint64_t bridge_output_len;
  int retval = 0;
  sgx_status_t sgx_status =
      ecall_restore(eid, &retval, input, input_len, output, &bridge_output_len);
  if (output_len) {
    *output_len = static_cast<size_t>(bridge_output_len);
  }
  if (sgx_status != SGX_SUCCESS) {
    return SgxError(sgx_status, "Call to ecall_restore failed");
  } else if (retval || !output_len || *output_len == 0) {
    // Ecall succeeded but did not return a value. This indicates that the
    // trusted code failed to propagate error information over the enclave
    // boundary.
    return absl::InternalError("No output from enclave");
  }
  return absl::OkStatus();
}

}  // namespace

SgxEnclaveClient::~SgxEnclaveClient() = default;

StatusOr<std::shared_ptr<Client>> SgxBackend::Load(
    const absl::string_view enclave_name, void *base_address,
    absl::string_view enclave_path, size_t enclave_size,
    const EnclaveConfig &config, bool debug,
    std::unique_ptr<Client::ExitCallProvider> exit_call_provider) {
  std::shared_ptr<SgxEnclaveClient> client(
      new SgxEnclaveClient(enclave_name, std::move(exit_call_provider)));
  client->RegisterExitHandlers();
  client->base_address_ = base_address;

  int updated;
  sgx_status_t status;
  const uint32_t ex_features = SGX_CREATE_ENCLAVE_EX_ASYLO;
  asylo_sgx_config_t create_config = {
      .base_address = &client->base_address_,
      .enclave_size = enclave_size,
      .enable_user_utility = config.enable_fork()};
  const void *ex_features_p[32] = {nullptr};
  ex_features_p[SGX_CREATE_ENCLAVE_EX_ASYLO_BIT_IDX] = &create_config;
  for (int i = 0; i < kMaxEnclaveCreateAttempts; ++i) {
    status = sgx_create_enclave_ex(
        std::string(enclave_path).c_str(), debug, &client->token_, &updated,
        &client->id_, /*misc_attr=*/nullptr, ex_features, ex_features_p);

    LOG_IF(WARNING, status != SGX_SUCCESS)
        << "Failed to create an enclave, attempt=" << i
        << ", status=" << status;
    if (status != SGX_INTERNAL_ERROR_ENCLAVE_CREATE_INTERRUPTED) {
      break;
    }
  }

  if (status != SGX_SUCCESS) {
    return SgxError(
        status, absl::StrCat("Failed to create an enclave for ", enclave_path));
  }

  client->size_ = sgx_enclave_size(client->id_);
  client->is_destroyed_ = false;
  return client;
}

StatusOr<std::shared_ptr<Client>> SgxEmbeddedBackend::Load(
    const absl::string_view enclave_name, void *base_address,
    absl::string_view section_name, size_t enclave_size,
    const EnclaveConfig &config, bool debug,
    std::unique_ptr<Client::ExitCallProvider> exit_call_provider) {
  std::shared_ptr<SgxEnclaveClient> client(
      new SgxEnclaveClient(enclave_name, std::move(exit_call_provider)));
  client->RegisterExitHandlers();
  client->base_address_ = base_address;

  // If an address is specified to load the enclave, temporarily reserve it to
  // prevent these mappings from occupying that location.
  if (base_address && enclave_size > 0) {
    // Unmap the remaining memory in the space to load the child enclave,
    // because the in-kernel SGX driver leaves VMA pages in that address space
    // after fork().
    if (munmap(base_address, enclave_size) != 0) {
      return Status(absl::StatusCode::kInternal,
                    "Failed to release enclave memory");
    }
    if (mmap(base_address, enclave_size, PROT_NONE, MAP_SHARED | MAP_ANONYMOUS,
             -1, 0) != base_address) {
      return Status(absl::StatusCode::kInternal,
                    "Failed to reserve enclave memory");
    }
  }

  FileMapping self_binary_mapping;
  ASYLO_ASSIGN_OR_RETURN(self_binary_mapping, FileMapping::CreateFromFile(
                                                  kCallingProcessBinaryFile));

  ElfReader self_binary_reader;
  ASYLO_ASSIGN_OR_RETURN(self_binary_reader, ElfReader::CreateFromSpan(
                                                 self_binary_mapping.buffer()));

  absl::Span<const uint8_t> enclave_buffer;
  ASYLO_ASSIGN_OR_RETURN(enclave_buffer,
                         self_binary_reader.GetSectionData(section_name));
  // The enclave section should be page-aligned, which is ensured by the
  // embed_enclaves rule.
  if ((reinterpret_cast<uintptr_t>(enclave_buffer.data()) & (kPageSize - 1))) {
    return Status(absl::StatusCode::kFailedPrecondition,
                  absl::StrCat("Enclave section ", section_name,
                               " must be page-aligned"));
  }

  if (base_address && enclave_size > 0 &&
      munmap(base_address, enclave_size) < 0) {
    return Status(absl::StatusCode::kInternal,
                  "Failed to release enclave memory");
  }

  sgx_status_t status;
  const uint32_t ex_features = SGX_CREATE_ENCLAVE_EX_ASYLO;
  asylo_sgx_config_t create_config = {
      .base_address = &client->base_address_,
      .enclave_size = enclave_size,
      .enable_user_utility = config.enable_fork()};
  const void *ex_features_p[32] = {nullptr};
  ex_features_p[SGX_CREATE_ENCLAVE_EX_ASYLO_BIT_IDX] = &create_config;
  for (int i = 0; i < kMaxEnclaveCreateAttempts; ++i) {
    status = sgx_create_enclave_from_buffer_ex(
        const_cast<uint8_t *>(enclave_buffer.data()), enclave_buffer.size(),
        debug, &client->id_,
        /*misc_attr=*/nullptr, ex_features, ex_features_p);

    if (status != SGX_INTERNAL_ERROR_ENCLAVE_CREATE_INTERRUPTED) {
      break;
    }
  }

  client->size_ = sgx_enclave_size(client->id_);

  if (status != SGX_SUCCESS) {
    return SgxError(status, "Failed to create an enclave");
  }

  client->is_destroyed_ = false;
  return client;
}

Status SgxEnclaveClient::Destroy() {
  MessageReader output;
  ASYLO_RETURN_IF_ERROR(EnclaveCall(kSelectorAsyloFini, nullptr, &output));
  ScopedCurrentClient scoped_client(this);
  sgx_status_t status = sgx_destroy_enclave(id_);
  if (status != SGX_SUCCESS) {
    return SgxError(status, "Failed to destroy enclave");
  }
  is_destroyed_ = true;
  ASYLO_RETURN_IF_ERROR(
      EnclaveSignalDispatcher::GetInstance()->DeregisterAllSignalsForClient(
          this));
  return absl::OkStatus();
}

Status SgxEnclaveClient::RegisterExitHandlers() {
  return RegisterSgxExitHandlers(exit_call_provider());
}

sgx_enclave_id_t SgxEnclaveClient::GetEnclaveId() const { return id_; }

size_t SgxEnclaveClient::GetEnclaveSize() const { return size_; }

void *SgxEnclaveClient::GetBaseAddress() const { return base_address_; }

void SgxEnclaveClient::GetLaunchToken(sgx_launch_token_t *token) const {
  memcpy(token, &token_, sizeof(token_));
}

bool SgxEnclaveClient::IsClosed() const { return is_destroyed_; }

Status SgxEnclaveClient::EnclaveCallInternal(uint64_t selector,
                                             MessageWriter *input,
                                             MessageReader *output) {
  SgxParams params{};
  params.input_size = 0;
  params.input = nullptr;
  params.output = nullptr;
  params.output_size = 0;
  Cleanup clean_up([&params] {
    if (params.input) {
      free(const_cast<void *>(params.input));
    }
    if (params.output) {
      free(params.output);
    }
  });

  if (input) {
    params.input_size = input->MessageSize();
    if (params.input_size > 0) {
      params.input = malloc(static_cast<size_t>(params.input_size));
      input->Serialize(const_cast<void *>(params.input));
    }
  }
  int retval = 0;
  sgx_status_t status =
      ecall_dispatch_trusted_call(id_, &retval, selector, &params);
  if (status != SGX_SUCCESS) {
    return SgxError(status, "Call to primitives ecall endpoint failed");
  }
  if (retval) {
    return absl::InternalError("Enclave call failed inside enclave");
  }
  if (params.output) {
    output->Deserialize(params.output, static_cast<size_t>(params.output_size));
  }
  return absl::OkStatus();
}

int SgxEnclaveClient::EnterAndHandleSignal(int signum, int sigcode) {
  if (is_destroyed_) {
    return -1;
  }

  ScopedCurrentClient scoped_client(this);
  int retval = 0;
  sgx_status_t status = ecall_deliver_signal(id_, &retval, signum, sigcode);
  if (status != SGX_SUCCESS || retval) {
    return -1;
  }

  return 0;
}

Status SgxEnclaveClient::EnterAndTakeSnapshot(SnapshotLayout *snapshot_layout) {
  char *output_buf = nullptr;
  size_t output_len = 0;

  ScopedCurrentClient scoped_client(this);
  ASYLO_RETURN_IF_ERROR(TakeSnapshot(id_, &output_buf, &output_len));

  // Enclave entry-point was successfully invoked. |output_buf| is guaranteed to
  // have a value.
  EnclaveOutput local_output;
  local_output.ParseFromArray(output_buf, output_len);
  Status status = StatusFromProto(local_output.status());

  // If |output| is not null, then |output_buf| points to a memory buffer
  // allocated inside the enclave using
  // TrustedPrimitives::UntrustedLocalAlloc(). It is the caller's responsibility
  // to free this buffer.
  free(output_buf);

  // Set the output parameter if necessary.
  if (snapshot_layout) {
    *snapshot_layout = local_output.GetExtension(snapshot);
  }

  return status;
}

Status SgxEnclaveClient::EnterAndRestore(
    const SnapshotLayout &snapshot_layout) {
  std::string buf;
  if (!snapshot_layout.SerializeToString(&buf)) {
    return absl::InvalidArgumentError("Failed to serialize SnapshotLayout");
  }

  char *output = nullptr;
  size_t output_len = 0;

  ScopedCurrentClient scoped_client(this);
  ASYLO_RETURN_IF_ERROR(
      Restore(id_, buf.data(), buf.size(), &output, &output_len));

  // Enclave entry-point was successfully invoked. |output| is guaranteed to
  // have a value.
  StatusProto status_proto;
  status_proto.ParseFromArray(output, output_len);
  Status status = StatusFromProto(status_proto);

  // |output| points to an untrusted memory buffer allocated by the enclave. It
  // is the untrusted caller's responsibility to free this buffer.
  free(output);

  return status;
}

Status SgxEnclaveClient::EnterAndTransferSecureSnapshotKey(
    const ForkHandshakeConfig &fork_handshake_config) {
  std::string buf;
  if (!fork_handshake_config.SerializeToString(&buf)) {
    return absl::InvalidArgumentError(
        "Failed to serialize ForkHandshakeConfig");
  }

  char *output = nullptr;
  size_t output_len = 0;

  ScopedCurrentClient scoped_client(this);
  ASYLO_RETURN_IF_ERROR(TransferSecureSnapshotKey(id_, buf.data(), buf.size(),
                                                  &output, &output_len));

  // Enclave entry-point was successfully invoked. |output| is guaranteed to
  // have a value.
  StatusProto status_proto;
  status_proto.ParseFromArray(output, output_len);
  Status status = StatusFromProto(status_proto);

  // |output| points to an untrusted memory buffer allocated by the enclave. It
  // is the untrusted caller's responsibility to free this buffer.
  free(output);

  return status;
}

void SgxEnclaveClient::SetProcessId() { sgx_set_process_id(id_); }

void SgxEnclaveClient::SetForkedEnclaveLoader(
    forked_loader_callback_t callback) {
  forked_loader_callback = callback;
}

forked_loader_callback_t SgxEnclaveClient::GetForkedEnclaveLoader() {
  return forked_loader_callback;
}

}  // namespace primitives
}  // namespace asylo
