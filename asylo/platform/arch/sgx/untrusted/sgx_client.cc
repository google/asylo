/*
 *
 * Copyright 2017 Asylo authors
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

#include "asylo/platform/arch/sgx/untrusted/sgx_client.h"

#include <cstdint>
#include <string>

#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "asylo/util/logging.h"
#include "asylo/platform/arch/sgx/untrusted/generated_bridge_u.h"
#include "asylo/platform/common/bridge_functions.h"
#include "asylo/platform/common/bridge_types.h"
#include "asylo/platform/primitives/sgx/sgx_error_space.h"
#include "asylo/platform/primitives/sgx/untrusted_sgx.h"
#include "asylo/platform/primitives/untrusted_primitives.h"
#include "asylo/platform/primitives/util/dispatch_table.h"
#include "asylo/util/elf_reader.h"
#include "asylo/util/file_mapping.h"
#include "asylo/util/posix_error_space.h"
#include "asylo/util/status_macros.h"

namespace asylo {


// Enters the enclave and invokes the restoring entry-point. If the ecall fails,
// return a non-OK status.
static Status restore(sgx_enclave_id_t eid, const char *input, size_t input_len,
                      char **output, size_t *output_len) {
  int result;
  bridge_size_t bridge_output_len;
  sgx_status_t sgx_status =
      ecall_restore(eid, &result, input, static_cast<bridge_size_t>(input_len),
                    output, &bridge_output_len);
  if (output_len) {
    *output_len = static_cast<size_t>(bridge_output_len);
  }
  if (sgx_status != SGX_SUCCESS) {
    // Return a Status object in the SGX error space.
    return Status(sgx_status, "Call to ecall_restore failed");
  } else if (result || *output_len == 0) {
    // Ecall succeeded but did not return a value. This indicates that the
    // trusted code failed to propagate error information over the enclave
    // boundary.
    return Status(asylo::error::GoogleError::INTERNAL,
                  "No output from enclave");
  }

  return Status::OkStatus();
}

StatusOr<std::unique_ptr<EnclaveClient>> SgxLoader::LoadEnclave(
    const std::string &name, void *base_address, const size_t enclave_size,
    const EnclaveConfig &config) const {
  auto client = absl::make_unique<SgxClient>(name);

  ASYLO_ASSIGN_OR_RETURN(
      client->primitive_client_,
      primitives::LoadEnclave<primitives::SgxBackend>(
          name, base_address, enclave_path_, enclave_size, config, debug_,
          absl::make_unique<primitives::DispatchTable>()));

  return std::unique_ptr<EnclaveClient>(std::move(client));
}

StatusOr<std::unique_ptr<EnclaveLoader>> SgxLoader::Copy() const {
  std::unique_ptr<SgxLoader> loader(new SgxLoader(*this));
  if (!loader) {
    return Status(error::GoogleError::INTERNAL, "Failed to create self loader");
  }
  return std::unique_ptr<EnclaveLoader>(loader.release());
}

StatusOr<std::unique_ptr<EnclaveClient>> SgxEmbeddedLoader::LoadEnclave(
    const std::string &name, void *base_address, const size_t enclave_size,
    const EnclaveConfig &config) const {
  auto client = absl::make_unique<SgxClient>(name);

  ASYLO_ASSIGN_OR_RETURN(
      client->primitive_client_,
      primitives::LoadEnclave<primitives::SgxEmbeddedBackend>(
          name, base_address, section_name_, enclave_size, config, debug_,
          absl::make_unique<primitives::DispatchTable>()));

  return std::unique_ptr<EnclaveClient>(std::move(client));
}

StatusOr<std::unique_ptr<EnclaveLoader>> SgxEmbeddedLoader::Copy() const {
  std::unique_ptr<SgxEmbeddedLoader> loader(new SgxEmbeddedLoader(*this));
  if (!loader) {
    return Status(error::GoogleError::INTERNAL, "Failed to create self loader");
  }
  return std::unique_ptr<EnclaveLoader>(loader.release());
}

Status SgxClient::EnterAndTakeSnapshot(SnapshotLayout *snapshot_layout) {
  return GetPrimitiveClient()->EnterAndTakeSnapshot(snapshot_layout);
}

Status SgxClient::EnterAndRestore(const SnapshotLayout &snapshot_layout) {
  std::string buf;
  if (!snapshot_layout.SerializeToString(&buf)) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "Failed to serialize SnapshotLayout");
  }

  char *output = nullptr;
  size_t output_len = 0;

  ASYLO_RETURN_IF_ERROR(restore(GetPrimitiveClient()->GetEnclaveId(),
                                buf.data(), buf.size(), &output, &output_len));

  // Enclave entry-point was successfully invoked. |output| is guaranteed to
  // have a value.
  StatusProto status_proto;
  status_proto.ParseFromArray(output, output_len);
  Status status;
  status.RestoreFrom(status_proto);

  // |output| points to an untrusted memory buffer allocated by the enclave. It
  // is the untrusted caller's responsibility to free this buffer.
  free(output);

  return status;
}

Status SgxClient::EnterAndTransferSecureSnapshotKey(
    const ForkHandshakeConfig &fork_handshake_config) {
  return GetPrimitiveClient()->EnterAndTransferSecureSnapshotKey(
      fork_handshake_config);
}

bool SgxClient::IsTcsActive() {
  return (GetPrimitiveClient()->IsTcsActive());
}

void SgxClient::SetProcessId() {
  GetPrimitiveClient()->SetProcessId();
}

}  //  namespace asylo
