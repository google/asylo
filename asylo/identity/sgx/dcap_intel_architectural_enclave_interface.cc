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

#include "asylo/identity/sgx/dcap_intel_architectural_enclave_interface.h"

#include <vector>

#include "include/sgx_key.h"
#include "include/sgx_report.h"
#include "QuoteGeneration/pce_wrapper/inc/sgx_pce.h"

namespace asylo {
namespace sgx {
namespace {

Status PceErrorToStatus(sgx_pce_error_t pce_error) {
  switch (pce_error) {
    case SGX_PCE_SUCCESS:
      return Status::OkStatus();
    case SGX_PCE_UNEXPECTED:
      return Status(error::GoogleError::INTERNAL, "Unexpected error");
    case SGX_PCE_OUT_OF_EPC:
      return Status(error::GoogleError::INTERNAL,
                    "Not enough EPC to load the PCE");
    case SGX_PCE_INTERFACE_UNAVAILABLE:
      return Status(error::GoogleError::INTERNAL, "Interface unavailable");
    case SGX_PCE_CRYPTO_ERROR:
      return Status(error::GoogleError::INTERNAL,
                    "Evaluation of REPORT.REPORTDATA failed");
    case SGX_PCE_INVALID_PARAMETER:
      return Status(error::GoogleError::INVALID_ARGUMENT, "Invalid parameter");
    case SGX_PCE_INVALID_REPORT:
      return Status(error::GoogleError::INVALID_ARGUMENT, "Invalid report");
    case SGX_PCE_INVALID_TCB:
      return Status(error::GoogleError::INVALID_ARGUMENT, "Invalid TCB");
    case SGX_PCE_INVALID_PRIVILEGE:
      return Status(error::GoogleError::PERMISSION_DENIED,
                    "Report must have the PROVISION_KEY attribute bit set");
    default:
      return Status(error::GoogleError::UNKNOWN, "Unknown error");
  }
}

}  // namespace

Status DcapIntelArchitecturalEnclaveInterface::GetPceTargetinfo(
    Targetinfo *targetinfo, uint16_t *pce_svn) {
  static_assert(
      sizeof(Targetinfo) == sizeof(sgx_target_info_t),
      "Targetinfo struct is not the same size as sgx_target_info_t struct");

  sgx_pce_error_t result = sgx_pce_get_target(
      reinterpret_cast<sgx_target_info_t *>(targetinfo), pce_svn);

  return PceErrorToStatus(result);
}

Status DcapIntelArchitecturalEnclaveInterface::GetPceInfo(
    const Report &report, absl::Span<const uint8_t> ppid_encryption_key,
    uint8_t crypto_suite, std::string *ppid_encrypted, uint16_t *pce_svn,
    uint16_t *pce_id, uint8_t *signature_scheme) {
  static_assert(sizeof(Report) == sizeof(sgx_report_t),
                "Report struct is not the same size as sgx_report_t struct");

  std::vector<uint8_t> ppid_encrypted_tmp(ppid_encrypted->size());
  uint32_t encrypted_ppid_out_size = 0;
  sgx_pce_error_t result = sgx_get_pce_info(
      reinterpret_cast<const sgx_report_t *>(&report),
      ppid_encryption_key.data(), ppid_encryption_key.size(), crypto_suite,
      ppid_encrypted_tmp.data(), ppid_encrypted_tmp.size(),
      &encrypted_ppid_out_size, pce_svn, pce_id, signature_scheme);
  if (result == SGX_PCE_SUCCESS) {
    ppid_encrypted_tmp.resize(encrypted_ppid_out_size);
    ppid_encrypted->insert(ppid_encrypted->begin(), ppid_encrypted_tmp.cbegin(),
                           ppid_encrypted_tmp.cend());
    ppid_encrypted->resize(encrypted_ppid_out_size);
  }

  return PceErrorToStatus(result);
}

Status DcapIntelArchitecturalEnclaveInterface::PceSignReport(
    const Report &report, uint16_t target_pce_svn,
    UnsafeBytes<kCpusvnSize> target_cpu_svn, std::string *signature) {
  static_assert(sizeof(target_cpu_svn) == sizeof(sgx_cpu_svn_t),
                "target_cpusvn is not the same size as sgx_cpu_svn_t struct");

  std::vector<uint8_t> signature_tmp(signature->size());
  uint32_t signature_out_size = 0;
  sgx_pce_error_t result = sgx_pce_sign_report(
      &target_pce_svn, reinterpret_cast<sgx_cpu_svn_t *>(&target_cpu_svn),
      reinterpret_cast<const sgx_report_t *>(&report), signature_tmp.data(),
      signature_tmp.size(), &signature_out_size);
  if (result == SGX_PCE_SUCCESS) {
    signature_tmp.resize(signature_out_size);
    signature->insert(signature->begin(), signature_tmp.cbegin(),
                      signature_tmp.cend());
    signature->resize(signature_out_size);
  }

  return PceErrorToStatus(result);
}

}  // namespace sgx
}  // namespace asylo
