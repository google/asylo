/*
 * Copyright 2021 Asylo authors
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
 */

#include "asylo/platform/primitives/sgx/sgx_errors.h"

#include <string>

#include "absl/status/status.h"
#include "absl/strings/cord.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "asylo/platform/primitives/sgx/sgx_error_code.pb.h"
#include "asylo/util/status.h"
#include "asylo/util/status_helpers.h"
#include "include/sgx_error.h"

namespace asylo {
namespace {

// Converts an sgx_status_t to the corresponding absl::StatusCode.
absl::StatusCode ToAbslStatusCode(sgx_status_t sgx_status) {
  switch (sgx_status) {
    case SGX_SUCCESS:
      return absl::StatusCode::kOk;
    case SGX_ERROR_PCL_ENCRYPTED:
      return absl::StatusCode::kAlreadyExists;
    case SGX_ERROR_SERVICE_TIMEOUT:
      return absl::StatusCode::kDeadlineExceeded;
    case SGX_ERROR_ATT_KEY_UNINITIALIZED:
    case SGX_ERROR_FILE_CANT_OPEN_RECOVERY_FILE:
    case SGX_ERROR_FILE_CANT_WRITE_RECOVERY_FILE:
    case SGX_ERROR_FILE_NO_KEY_ID:
    case SGX_ERROR_FILE_NOT_SGX_FILE:
    case SGX_ERROR_FILE_RECOVERY_NEEDED:
    case SGX_ERROR_KDF_MISMATCH:
    case SGX_ERROR_PCL_GUID_MISMATCH:
    case SGX_ERROR_PCL_MAC_MISMATCH:
    case SGX_ERROR_PCL_SHA_MISMATCH:
    case SGX_ERROR_UNSUPPORTED_ATT_KEY_ID:
      return absl::StatusCode::kFailedPrecondition;
    case SGX_ERROR_AE_SESSION_INVALID:
    case SGX_ERROR_ATT_KEY_CERTIFICATION_FAILURE:
    case SGX_ERROR_ENCLAVE_CRASHED:
    case SGX_ERROR_ENCLAVE_FILE_ACCESS:
    case SGX_ERROR_ENCLAVE_LOST:
    case SGX_ERROR_FILE_BAD_STATUS:
    case SGX_ERROR_FILE_CLOSE_FAILED:
    case SGX_ERROR_FILE_FLUSH_FAILED:
    case SGX_ERROR_INVALID_FUNCTION:
    case SGX_ERROR_INVALID_STATE:
    case SGX_ERROR_MAC_MISMATCH:
    case SGX_ERROR_MEMORY_MAP_CONFLICT:
    case SGX_ERROR_NDEBUG_ENCLAVE:
    case SGX_ERROR_NETWORK_FAILURE:
    case SGX_ERROR_NO_DEVICE:
    case SGX_ERROR_UNDEFINED_SYMBOL:
    case SGX_ERROR_UNRECOGNIZED_PLATFORM:
    case SGX_ERROR_UPDATE_NEEDED:
    case SGX_INTERNAL_ERROR_ENCLAVE_CREATE_INTERRUPTED:
    case SGX_PTHREAD_EXIT:
      return absl::StatusCode::kInternal;
    case SGX_ERROR_AE_INVALID_EPIDBLOB:
    case SGX_ERROR_FEATURE_NOT_SUPPORTED:
    case SGX_ERROR_FILE_NAME_MISMATCH:
    case SGX_ERROR_INVALID_ATT_KEY_CERT_DATA:
    case SGX_ERROR_INVALID_ATTRIBUTE:
    case SGX_ERROR_INVALID_ENCLAVE:
    case SGX_ERROR_INVALID_ENCLAVE_ID:
    case SGX_ERROR_INVALID_KEYNAME:
    case SGX_ERROR_INVALID_LAUNCH_TOKEN:
    case SGX_ERROR_INVALID_METADATA:
    case SGX_ERROR_INVALID_MISC:
    case SGX_ERROR_INVALID_PARAMETER:
    case SGX_ERROR_INVALID_SIGNATURE:
    case SGX_ERROR_INVALID_VERSION:
    case SGX_ERROR_MODE_INCOMPATIBLE:
    case SGX_ERROR_PCL_NOT_ENCRYPTED:
    case SGX_ERROR_UNSUPPORTED_CONFIG:
      return absl::StatusCode::kInvalidArgument;
    case SGX_ERROR_MC_NOT_FOUND:
      return absl::StatusCode::kNotFound;
    case SGX_ERROR_ECALL_NOT_ALLOWED:
    case SGX_ERROR_EPID_MEMBER_REVOKED:
    case SGX_ERROR_INVALID_CPUSVN:
    case SGX_ERROR_INVALID_ISVSVN:
    case SGX_ERROR_MC_NO_ACCESS_RIGHT:
    case SGX_ERROR_NO_PRIVILEGE:
    case SGX_ERROR_OCALL_NOT_ALLOWED:
    case SGX_ERROR_SERVICE_INVALID_PRIVILEGE:
      return absl::StatusCode::kPermissionDenied;
    case SGX_ERROR_MC_USED_UP:
    case SGX_ERROR_OUT_OF_EPC:
    case SGX_ERROR_OUT_OF_MEMORY:
    case SGX_ERROR_OUT_OF_TCS:
    case SGX_ERROR_STACK_OVERRUN:
      return absl::StatusCode::kResourceExhausted;
    case SGX_ERROR_BUSY:
    case SGX_ERROR_DEVICE_BUSY:
    case SGX_ERROR_MC_OVER_QUOTA:
    case SGX_ERROR_PLATFORM_CERT_UNAVAILABLE:
    case SGX_ERROR_SERVICE_UNAVAILABLE:
      return absl::StatusCode::kUnavailable;
    case SGX_ERROR_UNEXPECTED:
    default:
      return absl::StatusCode::kUnknown;
  }
}

}  // namespace

std::string DescribeSgxStatus(sgx_status_t sgx_status) {
  switch (sgx_status) {
    case SGX_SUCCESS:
      return "OK";
    case SGX_ERROR_UNEXPECTED:
      return "Unexpected error";
    case SGX_ERROR_INVALID_PARAMETER:
      return "Invalid parameter";
    case SGX_ERROR_OUT_OF_MEMORY:
      return "Out of memory";
    case SGX_ERROR_ENCLAVE_LOST:
      return "Enclave lost after power transition or in child process";
    case SGX_ERROR_INVALID_STATE:
      return "SGX API invoked in incorrect order or state";
    case SGX_ERROR_FEATURE_NOT_SUPPORTED:
      return "Feature is not supported on this platform";
    case SGX_PTHREAD_EXIT:
      return "Enclave is exited with pthread_exit";
    case SGX_ERROR_INVALID_FUNCTION:
      return "Invalid ecall or ocall";
    case SGX_ERROR_OUT_OF_TCS:
      return "Out of TCS";
    case SGX_ERROR_ENCLAVE_CRASHED:
      return "Enclave crashed";
    case SGX_ERROR_ECALL_NOT_ALLOWED:
      return "Ecall not allowed";
    case SGX_ERROR_OCALL_NOT_ALLOWED:
      return "Ocall not allowed";
    case SGX_ERROR_STACK_OVERRUN:
      return "Out of stack";
    case SGX_ERROR_UNDEFINED_SYMBOL:
      return "Undefined symbol";
    case SGX_ERROR_INVALID_ENCLAVE:
      return "Invalid enclave image";
    case SGX_ERROR_INVALID_ENCLAVE_ID:
      return "Invalid enclave ID";
    case SGX_ERROR_INVALID_SIGNATURE:
      return "Invalid enclave signature";
    case SGX_ERROR_NDEBUG_ENCLAVE:
      return "Cannot create debug enclave";
    case SGX_ERROR_OUT_OF_EPC:
      return "Out of EPC";
    case SGX_ERROR_NO_DEVICE:
      return "Cannot open SGX device";
    case SGX_ERROR_MEMORY_MAP_CONFLICT:
      return "Memory map conflict";
    case SGX_ERROR_INVALID_METADATA:
      return "Invalid metadata";
    case SGX_ERROR_DEVICE_BUSY:
      return "Device busy";
    case SGX_ERROR_INVALID_VERSION:
      return "Invalid metadata version";
    case SGX_ERROR_MODE_INCOMPATIBLE:
      return "Mode incompatible";
    case SGX_ERROR_ENCLAVE_FILE_ACCESS:
      return "Cannot open enclave file";
    case SGX_ERROR_INVALID_MISC:
      return "Invalid MiscSelect/MiscMask settings";
    case SGX_ERROR_INVALID_LAUNCH_TOKEN:
      return "The launch token is not correct";
    case SGX_ERROR_MAC_MISMATCH:
      return "MAC verification failed";
    case SGX_ERROR_INVALID_ATTRIBUTE:
      return "Invalid attribute";
    case SGX_ERROR_INVALID_CPUSVN:
      return "Invalid CPUSVN";
    case SGX_ERROR_INVALID_ISVSVN:
      return "Invalid ISVSVN";
    case SGX_ERROR_INVALID_KEYNAME:
      return "Invalid keyname";
    case SGX_ERROR_SERVICE_UNAVAILABLE:
      return "AESM service unavailable";
    case SGX_ERROR_SERVICE_TIMEOUT:
      return "AESM service timeout";
    case SGX_ERROR_AE_INVALID_EPIDBLOB:
      return "Invalid EPID blob for architectural enclave";
    case SGX_ERROR_SERVICE_INVALID_PRIVILEGE:
      return "Invalid privilege for launch token";
    case SGX_ERROR_EPID_MEMBER_REVOKED:
      return "EPID group membership revoked";
    case SGX_ERROR_UPDATE_NEEDED:
      return "SGX update needed";
    case SGX_ERROR_NETWORK_FAILURE:
      return "Network failure";
    case SGX_ERROR_AE_SESSION_INVALID:
      return "Session invalid for architectural enclave";
    case SGX_ERROR_BUSY:
      return "Service busy";
    case SGX_ERROR_MC_NOT_FOUND:
      return "Monotonic counter not found";
    case SGX_ERROR_MC_NO_ACCESS_RIGHT:
      return "Access denied to monotonic counter";
    case SGX_ERROR_MC_USED_UP:
      return "Monotonic counter used up";
    case SGX_ERROR_MC_OVER_QUOTA:
      return "Monotonic counter over quota";
    case SGX_ERROR_KDF_MISMATCH:
      return "Key derivation function mismatch";
    case SGX_ERROR_UNRECOGNIZED_PLATFORM:
      return "EPID provisioning failed due to platform not "
             "recognized by backend server";
    case SGX_ERROR_UNSUPPORTED_CONFIG:
      return "The config for trigging EPID Provisiong or PSE "
             "Provisiong&LTP is invalid";
    case SGX_ERROR_NO_PRIVILEGE:
      return "Not enough privilege to perform the operation";
    case SGX_ERROR_PCL_ENCRYPTED:
      return "Trying to encrypt an already encrypted enclave";
    case SGX_ERROR_PCL_NOT_ENCRYPTED:
      return "Trying to load a plain enclave using "
             "sgx_create_encrypted_enclave";
    case SGX_ERROR_PCL_MAC_MISMATCH:
      return "Section mac result does not match build time mac";
    case SGX_ERROR_PCL_SHA_MISMATCH:
      return "Unsealed key MAC does not match MAC of key hardcoded in enclave "
             "binary";
    case SGX_ERROR_PCL_GUID_MISMATCH:
      return "GUID in sealed blob does not match GUID hardcoded in enclave "
             "binary";
    case SGX_ERROR_FILE_BAD_STATUS:
      return "The file is in bad status";
    case SGX_ERROR_FILE_NO_KEY_ID:
      return "The Key ID field is all zeros, can't re-generate the encryption "
             "key";
    case SGX_ERROR_FILE_NAME_MISMATCH:
      return "The current file name is different then the original file name "
             "(not allowed, substitution attack)";
    case SGX_ERROR_FILE_NOT_SGX_FILE:
      return "The file is not an SGX file";
    case SGX_ERROR_FILE_CANT_OPEN_RECOVERY_FILE:
      return "A recovery file can't be opened, so flush operation can't "
             "continue";
    case SGX_ERROR_FILE_CANT_WRITE_RECOVERY_FILE:
      return "A recovery file can't be written, so flush operation can't "
             "continue";
    case SGX_ERROR_FILE_RECOVERY_NEEDED:
      return "When opening the file, recovery is needed, but the recovery "
             "process failed";
    case SGX_ERROR_FILE_FLUSH_FAILED:
      return "fflush operation (to disk) failed";
    case SGX_ERROR_FILE_CLOSE_FAILED:
      return "fclose operation (to disk) failed";
    case SGX_ERROR_UNSUPPORTED_ATT_KEY_ID:
      return "Platform quoting infrastructure does not support the key";
    case SGX_ERROR_ATT_KEY_CERTIFICATION_FAILURE:
      return "Failed to generate and certify the attestation key";
    case SGX_ERROR_ATT_KEY_UNINITIALIZED:
      return "The platform quoting infrastructure does not have the "
             "attestation key available to generate quote";
    case SGX_ERROR_INVALID_ATT_KEY_CERT_DATA:
      return "The data returned by the platform library's "
             "sgx_get_quote_config() is invalid";
    case SGX_ERROR_PLATFORM_CERT_UNAVAILABLE:
      return "The PCK Cert for the platform is not available";
    case SGX_INTERNAL_ERROR_ENCLAVE_CREATE_INTERRUPTED:
      return "The ioctl for enclave_create unexpectedly failed with EINTR";
    default:
      return absl::StrCat("Unrecognized SGX status ", sgx_status);
  }
}

Status SgxError(sgx_status_t sgx_status, absl::string_view message) {
  Status status(ToAbslStatusCode(sgx_status), message);
  SgxErrorCode code;
  code.set_sgx_status_code(sgx_status);
  SetProtoPayload(code, status);
  return status;
}

sgx_status_t GetSgxErrorCode(const Status &status) {
  absl::optional<SgxErrorCode> code = GetProtoPayload<SgxErrorCode>(status);
  if (!code.has_value()) {
    return SGX_SUCCESS;
  }
  return static_cast<sgx_status_t>(code->sgx_status_code());
}

}  // namespace asylo
