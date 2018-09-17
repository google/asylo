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

#include "asylo/platform/arch/sgx/sgx_error_space.h"

namespace asylo {
namespace error {

ErrorSpace const *SgxErrorSpace::GetInstance() {
  static ErrorSpace const *instance = new SgxErrorSpace();
  return instance;
}

SgxErrorSpace::SgxErrorSpace()
    : ErrorSpaceImplementationHelper<SgxErrorSpace>(
          "::asylo::error::SgxErrorSpace") {
  AddTranslationMapEntry(SGX_SUCCESS, "SGX_SUCCESS", GoogleError::OK);
  AddTranslationMapEntry(SGX_ERROR_UNEXPECTED, "Unexpected error",
                         GoogleError::UNKNOWN);
  AddTranslationMapEntry(SGX_ERROR_INVALID_PARAMETER, "Invalid parameter",
                         GoogleError::INVALID_ARGUMENT);
  AddTranslationMapEntry(SGX_ERROR_OUT_OF_MEMORY, "Out of memory",
                         GoogleError::RESOURCE_EXHAUSTED);
  AddTranslationMapEntry(
      SGX_ERROR_ENCLAVE_LOST,
      "Enclave lost after power transition or in child process",
      GoogleError::INTERNAL);
  AddTranslationMapEntry(SGX_ERROR_INVALID_STATE,
                         "SGX API invoked in incorrect order or state",
                         GoogleError::INTERNAL);
  AddTranslationMapEntry(SGX_ERROR_INVALID_FUNCTION, "Invalid ecall or ocall",
                         GoogleError::INTERNAL);
  AddTranslationMapEntry(SGX_ERROR_OUT_OF_TCS, "Out of TCS",
                         GoogleError::RESOURCE_EXHAUSTED);
  AddTranslationMapEntry(SGX_ERROR_ENCLAVE_CRASHED, "Enclave crashed",
                         GoogleError::INTERNAL);
  AddTranslationMapEntry(SGX_ERROR_ECALL_NOT_ALLOWED, "Ecall not allowed",
                         GoogleError::PERMISSION_DENIED);
  AddTranslationMapEntry(SGX_ERROR_OCALL_NOT_ALLOWED, "Ocall not allowed",
                         GoogleError::PERMISSION_DENIED);
  AddTranslationMapEntry(SGX_ERROR_STACK_OVERRUN, "Out of stack",
                         GoogleError::RESOURCE_EXHAUSTED);
  AddTranslationMapEntry(SGX_ERROR_UNDEFINED_SYMBOL, "Undefined symbol",
                         GoogleError::INTERNAL);
  AddTranslationMapEntry(SGX_ERROR_INVALID_ENCLAVE, "Invalid enclave image",
                         GoogleError::INVALID_ARGUMENT);
  AddTranslationMapEntry(SGX_ERROR_INVALID_ENCLAVE_ID, "Invalid enclave ID",
                         GoogleError::INVALID_ARGUMENT);
  AddTranslationMapEntry(SGX_ERROR_INVALID_SIGNATURE,
                         "Invalid enclave signature",
                         GoogleError::INVALID_ARGUMENT);
  AddTranslationMapEntry(SGX_ERROR_NDEBUG_ENCLAVE,
                         "Cannot create debug enclave", GoogleError::INTERNAL);
  AddTranslationMapEntry(SGX_ERROR_OUT_OF_EPC, "Out of EPC",
                         GoogleError::RESOURCE_EXHAUSTED);
  AddTranslationMapEntry(SGX_ERROR_NO_DEVICE, "Cannot open SGX device",
                         GoogleError::INTERNAL);
  AddTranslationMapEntry(SGX_ERROR_MEMORY_MAP_CONFLICT, "Memory map conflict",
                         GoogleError::INTERNAL);
  AddTranslationMapEntry(SGX_ERROR_INVALID_METADATA, "Invalid metadata",
                         GoogleError::INVALID_ARGUMENT);
  AddTranslationMapEntry(SGX_ERROR_DEVICE_BUSY, "Device busy",
                         GoogleError::UNAVAILABLE);
  AddTranslationMapEntry(SGX_ERROR_INVALID_VERSION, "Invalid metadata version",
                         GoogleError::INVALID_ARGUMENT);
  AddTranslationMapEntry(SGX_ERROR_MODE_INCOMPATIBLE, "Mode incompatible",
                         GoogleError::INVALID_ARGUMENT);
  AddTranslationMapEntry(SGX_ERROR_ENCLAVE_FILE_ACCESS,
                         "Cannot open enclave file", GoogleError::INTERNAL);
  AddTranslationMapEntry(SGX_ERROR_INVALID_MISC,
                         "Invalid MiscSelect/MiscMask settings",
                         GoogleError::INVALID_ARGUMENT);
  AddTranslationMapEntry(SGX_ERROR_MAC_MISMATCH, "MAC verification failed",
                         GoogleError::INTERNAL);
  AddTranslationMapEntry(SGX_ERROR_INVALID_ATTRIBUTE, "Invalid attribute",
                         GoogleError::INVALID_ARGUMENT);
  AddTranslationMapEntry(SGX_ERROR_INVALID_CPUSVN, "Invalid CPUSVN",
                         GoogleError::PERMISSION_DENIED);
  AddTranslationMapEntry(SGX_ERROR_INVALID_ISVSVN, "Invalid ISVSVN",
                         GoogleError::PERMISSION_DENIED);
  AddTranslationMapEntry(SGX_ERROR_INVALID_KEYNAME, "Invalid keyname",
                         GoogleError::INVALID_ARGUMENT);
  AddTranslationMapEntry(SGX_ERROR_SERVICE_UNAVAILABLE,
                         "AESM service unavailable", GoogleError::UNAVAILABLE);
  AddTranslationMapEntry(SGX_ERROR_SERVICE_TIMEOUT, "AESM service timeout",
                         GoogleError::DEADLINE_EXCEEDED);
  AddTranslationMapEntry(SGX_ERROR_AE_INVALID_EPIDBLOB,
                         "Invalid EPID blob for architectural enclave",
                         GoogleError::INVALID_ARGUMENT);
  AddTranslationMapEntry(SGX_ERROR_SERVICE_INVALID_PRIVILEGE,
                         "Invalid privilege for launch token",
                         GoogleError::PERMISSION_DENIED);
  AddTranslationMapEntry(SGX_ERROR_EPID_MEMBER_REVOKED,
                         "EPID group membership revoked",
                         GoogleError::PERMISSION_DENIED);
  AddTranslationMapEntry(SGX_ERROR_UPDATE_NEEDED, "SGX update needed",
                         GoogleError::INTERNAL);
  AddTranslationMapEntry(SGX_ERROR_NETWORK_FAILURE, "Network failure",
                         GoogleError::INTERNAL);
  AddTranslationMapEntry(SGX_ERROR_AE_SESSION_INVALID,
                         "Session invalid for architectural enclave",
                         GoogleError::INTERNAL);
  AddTranslationMapEntry(SGX_ERROR_BUSY, "Service busy",
                         GoogleError::UNAVAILABLE);
  AddTranslationMapEntry(SGX_ERROR_MC_NOT_FOUND, "Monotonic counter not found",
                         GoogleError::NOT_FOUND);
  AddTranslationMapEntry(SGX_ERROR_MC_NO_ACCESS_RIGHT,
                         "Access denied to monotonic counter",
                         GoogleError::PERMISSION_DENIED);
  AddTranslationMapEntry(SGX_ERROR_MC_USED_UP, "Monotonic counter used up",
                         GoogleError::RESOURCE_EXHAUSTED);
  AddTranslationMapEntry(SGX_ERROR_MC_OVER_QUOTA,
                         "Monotonic counter over quota",
                         GoogleError::UNAVAILABLE);
  AddTranslationMapEntry(SGX_ERROR_KDF_MISMATCH,
                         "Key derivation function mismatch",
                         GoogleError::FAILED_PRECONDITION);
}

ErrorSpace const *GetErrorSpace(ErrorSpaceAdlTag<sgx_status_t> tag) {
  return SgxErrorSpace::GetInstance();
}

}  // namespace error
}  // namespace asylo
