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

#include "absl/strings/str_cat.h"
#include "asylo/crypto/algorithms.pb.h"
#include "asylo/identity/sgx/pce_util.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"
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
    AsymmetricEncryptionScheme ppid_encryption_scheme,
    std::string *ppid_encrypted, uint16_t *pce_svn, uint16_t *pce_id,
    SignatureScheme *signature_scheme) {
  static_assert(sizeof(Report) == sizeof(sgx_report_t),
                "Report struct is not the same size as sgx_report_t struct");

  absl::optional<uint8_t> crypto_suite =
      AsymmetricEncryptionSchemeToPceCryptoSuite(ppid_encryption_scheme);
  if (!crypto_suite.has_value()) {
    return Status(
        error::GoogleError::INVALID_ARGUMENT,
        absl::StrCat("Invalid ppid_encryption_scheme: ",
                     AsymmetricEncryptionScheme_Name(ppid_encryption_scheme)));
  }

  uint32_t max_ppid_out_size;
  ASYLO_ASSIGN_OR_RETURN(max_ppid_out_size,
                         GetEncryptedDataSize(ppid_encryption_scheme));

  std::vector<uint8_t> ppid_encrypted_tmp(max_ppid_out_size);
  uint32_t encrypted_ppid_out_size = 0;
  uint8_t pce_signature_scheme;
  sgx_pce_error_t result =
      sgx_get_pce_info(reinterpret_cast<const sgx_report_t *>(&report),
                       ppid_encryption_key.data(), ppid_encryption_key.size(),
                       crypto_suite.value(), ppid_encrypted_tmp.data(),
                       ppid_encrypted_tmp.size(), &encrypted_ppid_out_size,
                       pce_svn, pce_id, &pce_signature_scheme);
  if (result == SGX_PCE_SUCCESS) {
    ppid_encrypted->assign(
        ppid_encrypted_tmp.begin(),
        ppid_encrypted_tmp.begin() + encrypted_ppid_out_size);
    *signature_scheme =
        PceSignatureSchemeToSignatureScheme(pce_signature_scheme);
  }

  return PceErrorToStatus(result);
}

Status DcapIntelArchitecturalEnclaveInterface::PceSignReport(
    const Report &report, uint16_t target_pce_svn,
    UnsafeBytes<kCpusvnSize> target_cpu_svn, std::string *signature) {
  static_assert(sizeof(target_cpu_svn) == sizeof(sgx_cpu_svn_t),
                "target_cpusvn is not the same size as sgx_cpu_svn_t struct");

  std::vector<uint8_t> signature_tmp(kEcdsaP256SignatureSize);
  uint32_t signature_out_size = 0;
  sgx_pce_error_t result = sgx_pce_sign_report(
      &target_pce_svn, reinterpret_cast<sgx_cpu_svn_t *>(&target_cpu_svn),
      reinterpret_cast<const sgx_report_t *>(&report), signature_tmp.data(),
      signature_tmp.size(), &signature_out_size);
  if (result == SGX_PCE_SUCCESS) {
    signature->assign(signature_tmp.begin(),
                      signature_tmp.begin() + signature_out_size);
  }

  return PceErrorToStatus(result);
}

}  // namespace sgx
}  // namespace asylo
