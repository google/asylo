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

#include <string>

#include "absl/strings/str_cat.h"
#include "asylo/enclave.pb.h"
#include "asylo/util/logging.h"
#include "asylo/platform/arch/sgx/sgx_error_space.h"
#include "asylo/platform/arch/sgx/untrusted/generated_bridge_u.h"
#include "asylo/platform/common/bridge_functions.h"
#include "asylo/platform/common/bridge_types.h"
#include "asylo/util/file_mapping.h"
#include "asylo/util/posix_error_space.h"
#include "asylo/util/status_macros.h"

namespace asylo {

constexpr int kMaxEnclaveCreateAttempts = 5;


// Enters the enclave and invokes the initialization entry-point. If the ecall
// fails, or the enclave does not return any output, returns a non-OK status. In
// this case, the caller cannot make any assumptions about the contents of
// |output|. Otherwise, |output| points to a buffer of length *|output_len| that
// contains output from the enclave.
static Status initialize(sgx_enclave_id_t eid, const char *name,
                         const char *input, size_t input_len, char **output,
                         size_t *output_len) {
  int result;
  sgx_status_t sgx_status = ecall_initialize(
      eid, &result, name, input, static_cast<bridge_size_t>(input_len), output,
      static_cast<bridge_size_t *>(output_len));
  if (sgx_status != SGX_SUCCESS) {
    // Return a Status object in the SGX error space.
    return Status(sgx_status, "Call to ecall_initialize failed");
  } else if (result || *output_len == 0) {
    // Non-zero return code indicates that the enclave was not able to return
    // any output from Initialize().
    return Status(error::GoogleError::INTERNAL, "No output from enclave");
  }

  return Status::OkStatus();
}

// Enters the enclave and invokes the execution entry-point. If the ecall fails,
// or the enclave does not return any output, returns a non-OK status. In this
// case, the caller cannot make any assumptions about the contents of |output|.
// Otherwise, |output| points to a buffer of length *|output_len| that contains
// output from the enclave.
static Status run(sgx_enclave_id_t eid, const char *input, size_t input_len,
                  char **output, size_t *output_len) {
  int result;
  sgx_status_t sgx_status =
      ecall_run(eid, &result, input, static_cast<bridge_size_t>(input_len),
                output, static_cast<bridge_size_t *>(output_len));
  if (sgx_status != SGX_SUCCESS) {
    // Return a Status object in the SGX error space.
    return Status(sgx_status, "Call to ecall_run failed");
  } else if (result || *output_len == 0) {
    // Ecall succeeded but did not return a value. The indicates that the
    // trusted code failed to propagate error information over the enclave
    // boundary (e.g. serialization failure).
    return Status(error::GoogleError::INTERNAL, "No output from enclave");
  }

  return Status::OkStatus();
}

// Enters the enclave and invokes the finalization entry-point. If the ecall
// fails, or the enclave does not return any output, returns a non-OK status. In
// this case, the caller cannot make any assumptions about the contents of
// |output|. Otherwise, |output| points to a buffer of length *|output_len| that
// contains output from the enclave.
static Status finalize(sgx_enclave_id_t eid, const char *input,
                       size_t input_len, char **output, size_t *output_len) {
  int result;
  sgx_status_t sgx_status =
      ecall_finalize(eid, &result, input, static_cast<bridge_size_t>(input_len),
                     output, static_cast<bridge_size_t *>(output_len));
  if (sgx_status != SGX_SUCCESS) {
    // Return a Status object in the SGX error space.
    return Status(sgx_status, "Call to ecall_finalize failed");
  } else if (result || *output_len == 0) {
    // Non-zero return code indicates that the enclave was not able to return
    // any output from Finalize().
    return Status(error::GoogleError::INTERNAL, "No output from enclave");
  }

  return Status::OkStatus();
}

static int donate_thread(sgx_enclave_id_t eid, sgx_status_t *status) {
  int result;
  sgx_status_t local_status = ecall_donate_thread(eid, &result);
  if (status) *status = local_status;
  if (local_status != SGX_SUCCESS) {
    return -1;
  }
  return result;
}

// Enters the enclave and invokes the signal handle entry-point. If the ecall
// fails, returns a non-OK status.
static Status handle_signal(sgx_enclave_id_t eid, const char *input,
                            size_t input_len) {
  int result;
  sgx_status_t sgx_status = ecall_handle_signal(
      eid, &result, input, static_cast<bridge_size_t>(input_len));
  if (sgx_status != SGX_SUCCESS) {
    // Return a Status object in the SGX error space.
    return Status(sgx_status, "Call to ecall_handle_signal failed");
  } else if (result) {
    std::string message;
    switch (result) {
      case 1:
        message = "Invalid or unregistered incoming signal";
        break;
      case 2:
        message = "Enclave unable to handle signal in current state";
        break;
      case -1:
        message = "Incoming signal is blocked inside the enclave";
        break;
      default:
        message = "Unexpected error while handling signal";
    }
    return Status(error::GoogleError::INTERNAL, message);
  }
  return Status::OkStatus();
}

StatusOr<std::unique_ptr<EnclaveClient>> SGXLoader::LoadEnclave(
    const std::string &name) const {
  std::unique_ptr<SGXClient> client(new SGXClient(name));
  if (!client) {
    return Status(error::GoogleError::RESOURCE_EXHAUSTED, "Out of memory");
  }

  FileMapping whole_file_mapping;
  absl::Span<uint8_t> enclave_buffer;
  switch (enclave_source_.index()) {
    case kBufferIndex:
      enclave_buffer = absl::get<kBufferIndex>(enclave_source_);
      break;
    case kWholeFileIndex:
      ASYLO_ASSIGN_OR_RETURN(whole_file_mapping,
                             FileMapping::CreateFromFile(
                                 absl::get<kWholeFileIndex>(enclave_source_)));
      enclave_buffer = whole_file_mapping.buffer();
      break;
    default:
      return Status(
          error::GoogleError::INTERNAL,
          absl::StrCat("Unknown enclave source: ", enclave_source_.index()));
  }

  int updated;
  sgx_status_t rc;
  int attempts = kMaxEnclaveCreateAttempts;
  do {
    rc = sgx_create_enclave_from_buffer(enclave_buffer.data(),
                                        enclave_buffer.size(), debug_,
                                        &client->token_, &updated, &client->id_,
                                        /*misc_attr=*/nullptr);
  } while (rc == SGX_INTERNAL_ERROR_ENCLAVE_CREATE_INTERRUPTED &&
           --attempts > 0);
  if (rc != SGX_SUCCESS) {
    return Status(rc, "Failed to create an enclave");
  }
  return std::unique_ptr<EnclaveClient>(client.release());
}

Status SGXClient::EnterAndInitialize(const EnclaveConfig &config) {
  std::string buf;
  if (!config.SerializeToString(&buf)) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "Failed to serialize EnclaveConfig");
  }

  char *output = nullptr;
  size_t output_len = 0;
  ASYLO_RETURN_IF_ERROR(initialize(id_, get_name().c_str(), buf.data(),
                                   buf.size(), &output, &output_len));

  // Enclave entry-point was successfully invoked. |output| is guaranteed to
  // have a value.
  StatusProto status_proto;
  if (!status_proto.ParseFromArray(output, output_len)) {
    return Status(error::GoogleError::INTERNAL,
                  "Failed to deserialize StatusProto");
  }
  Status status;
  status.RestoreFrom(status_proto);

  // |output| points to an untrusted memory buffer allocated by the enclave. It
  // is the untrusted caller's responsibility to free this buffer.
  free(output);

  return status;
}

Status SGXClient::EnterAndRun(const EnclaveInput &input,
                              EnclaveOutput *output) {
  std::string buf;
  if (!input.SerializeToString(&buf)) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "Failed to serialize EnclaveInput");
  }

  char *output_buf = nullptr;
  size_t output_len = 0;
  ASYLO_RETURN_IF_ERROR(
      run(id_, buf.data(), buf.size(), &output_buf, &output_len));

  // Enclave entry-point was successfully invoked. |output_buf| is guaranteed to
  // have a value.
  EnclaveOutput local_output;
  local_output.ParseFromArray(output_buf, output_len);
  Status status;
  status.RestoreFrom(local_output.status());

  // If |output| is not null, then |output_buf| points to a memory buffer
  // allocated inside the enclave using enc_untrusted_malloc(). It is the
  // caller's responsibility to free this buffer.
  free(output_buf);

  // Set the output parameter if necessary.
  if (output) {
    *output = local_output;
  }

  return status;
}

Status SGXClient::EnterAndFinalize(const EnclaveFinal &final_input) {
  std::string buf;
  if (!final_input.SerializeToString(&buf)) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "Failed to serialize EnclaveFinal");
  }

  char *output = nullptr;
  size_t output_len = 0;

  ASYLO_RETURN_IF_ERROR(
      finalize(id_, buf.data(), buf.size(), &output, &output_len));

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

Status SGXClient::EnterAndDonateThread() {
  sgx_status_t sgx_status;
  int result = donate_thread(id_, &sgx_status);
  Status status;
  if (sgx_status != SGX_SUCCESS) {
    status = Status(sgx_status, "Failed to donate thread to enclave");
  } else if (result) {
    status = Status(static_cast<error::PosixError>(result),
                    "Failed to donate thread to enclave");
  }
  if (!status.ok()) {
    LOG(ERROR) << "EnterAndDonateThread failed " << status;
  }
  return status;
}

Status SGXClient::EnterAndHandleSignal(const EnclaveSignal &signal) {
  EnclaveSignal enclave_signal;
  int bridge_signum = ToBridgeSignal(signal.signum());
  if (bridge_signum < 0) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  absl::StrCat("Failed to convert signum (", signal.signum(),
                               ") to bridge signum"));
  }
  enclave_signal.set_signum(bridge_signum);
  std::string serialized_enclave_signal;
  if (!enclave_signal.SerializeToString(&serialized_enclave_signal)) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "Failed to serialize EnclaveSignal");
  }
  return handle_signal(id_, serialized_enclave_signal.data(),
                       serialized_enclave_signal.size());
}

Status SGXClient::DestroyEnclave() {
  sgx_status_t rc = sgx_destroy_enclave(id_);
  if (rc != SGX_SUCCESS) {
    return Status(rc, "Failed to destroy an enclave");
  }
  return Status::OkStatus();
}

bool SGXClient::IsTcsActive() { return (sgx_is_tcs_active(id_) != 0); }

}  //  namespace asylo
