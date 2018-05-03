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

#include "asylo/platform/arch/sgx/untrusted/sgx_error_space.h"

#include <sstream>
#include <string>
#include <unordered_map>

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

Status SGXStatusToStatus(sgx_status_t status) {
  // The following values are adapted from the constants defined by the SGX SDK
  // in sgx_error.h.
  static const auto *status_message = new std::unordered_map<int, std::string>{
      {SGX_SUCCESS, "Success."},
      {SGX_ERROR_UNEXPECTED, "Unexpected error"},
      {SGX_ERROR_INVALID_PARAMETER, "The parameter is incorrect"},
      {SGX_ERROR_OUT_OF_MEMORY,
       "Not enough memory is available to complete this operation."},
      {SGX_ERROR_ENCLAVE_LOST,
       "Enclave lost after power transition or used in child process "
       "created by linux:fork()."},
      {SGX_ERROR_INVALID_STATE,
       "SGX API is invoked in incorrect order or state."},
      {SGX_ERROR_INVALID_FUNCTION, "The ecall/ocall index is invalid."},
      {SGX_ERROR_OUT_OF_TCS, "The enclave is out of TCS."},
      {SGX_ERROR_ENCLAVE_CRASHED, "The enclave is crashed."},
      {SGX_ERROR_ECALL_NOT_ALLOWED,
       "The ECALL is not allowed at this time, e.g. ecall is blocked by "
       "the dynamic entry table, or nested ecall is not allowed during "
       "initialization."},
      {SGX_ERROR_OCALL_NOT_ALLOWED,
       "The OCALL is not allowed at this time, e.g. ocall is not "
       "allowed during exception handling."},
      {SGX_ERROR_STACK_OVERRUN, "The enclave is running out of stack."},
      {SGX_ERROR_UNDEFINED_SYMBOL, "The enclave image has undefined symbol."},
      {SGX_ERROR_INVALID_ENCLAVE, "The enclave image is not correct."},
      {SGX_ERROR_INVALID_ENCLAVE_ID, "The enclave id is invalid."},
      {SGX_ERROR_INVALID_SIGNATURE, "The signature is invalid."},
      {SGX_ERROR_NDEBUG_ENCLAVE,
       "The enclave is signed as product enclave, and can not be "
       "created as debuggable enclave."},
      {SGX_ERROR_OUT_OF_EPC,
       "Not enough EPC is available to load the enclave."},
      {SGX_ERROR_NO_DEVICE, "Can't open SGX device."},
      {SGX_ERROR_MEMORY_MAP_CONFLICT, "Page mapping failed in driver."},
      {SGX_ERROR_INVALID_METADATA, "The metadata is incorrect."},
      {SGX_ERROR_DEVICE_BUSY, "Device is busy, mostly EINIT failed."},
      {SGX_ERROR_INVALID_VERSION,
       "Metadata version is inconsistent between uRTS and sgx_sign or "
       "uRTS is incompatible with current platform."},
      {SGX_ERROR_MODE_INCOMPATIBLE,
       "The target enclave 32/64 bit mode or sim/hw mode is "
       "incompatible with the mode of current uRTS."},
      {SGX_ERROR_ENCLAVE_FILE_ACCESS, "Can't open enclave file."},
      {SGX_ERROR_INVALID_MISC,
       "The MiscSelct/MiscMask settings are not correct."},
      {SGX_ERROR_MAC_MISMATCH,
       "Indicates verification error for reports, sealed datas, etc."},
      {SGX_ERROR_INVALID_ATTRIBUTE, "The enclave is not authorized."},
      {SGX_ERROR_INVALID_CPUSVN,
       "The cpu svn is beyond platform's cpu svn value."},
      {SGX_ERROR_INVALID_ISVSVN,
       "The isv svn is greater than the enclave's isv svn."},
      {SGX_ERROR_INVALID_KEYNAME, "The key name is an unsupported value."},
      {SGX_ERROR_SERVICE_UNAVAILABLE,
       "Either aesm did not respond or the requested service is not "
       "supported."},
      {SGX_ERROR_SERVICE_TIMEOUT, "The request to aesm time out."},
      {SGX_ERROR_AE_INVALID_EPIDBLOB,
       "Indicates epid blob verification error."},
      {SGX_ERROR_SERVICE_INVALID_PRIVILEGE,
       "Enclave has no privilege to get launch token."},
      {SGX_ERROR_EPID_MEMBER_REVOKED, "The EPID group membership is revoked."},
      {SGX_ERROR_UPDATE_NEEDED, "SGX needs to be updated."},
      {SGX_ERROR_NETWORK_FAILURE,
       "Network connecting or proxy setting issue is encountered."},
      {SGX_ERROR_AE_SESSION_INVALID, "Session is invalid or ended by server."},
      {SGX_ERROR_BUSY, "The requested service is temporarily not availabe."},
      {SGX_ERROR_MC_NOT_FOUND,
       "The Monotonic Counter doesn't exist or has been invalided."},
      {SGX_ERROR_MC_NO_ACCESS_RIGHT,
       "Caller doesn't have the access right to specified VMC."},
      {SGX_ERROR_MC_USED_UP, "Monotonic counters are used out."},
      {SGX_ERROR_MC_OVER_QUOTA, "Monotonic counters exceeds quota limitation."},
      {SGX_ERROR_KDF_MISMATCH,
       "Key derivation function doesn't match during key exchange."}};

  const auto it = status_message->find(status);
  if (it != status_message->end()) {
    return {status, it->second};
  } else {
    std::stringstream message;
    message << "Unexpected value of sgx_status_t: " << status;
    return {status, message.str()};
  }
}

}  // namespace asylo
