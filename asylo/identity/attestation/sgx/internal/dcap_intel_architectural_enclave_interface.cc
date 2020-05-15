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

#include "asylo/identity/attestation/sgx/internal/dcap_intel_architectural_enclave_interface.h"

#include <memory>
#include <type_traits>
#include <vector>

#include "absl/strings/str_cat.h"
#include "asylo/crypto/algorithms.pb.h"
#include "asylo/identity/attestation/sgx/internal/dcap_library_interface.h"
#include "asylo/identity/attestation/sgx/internal/intel_architectural_enclave_interface.h"
#include "asylo/identity/attestation/sgx/internal/pce_util.h"
#include "asylo/util/proto_enum_util.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"
#include "include/sgx_report.h"
#include "QuoteGeneration/pce_wrapper/inc/sgx_pce_types.h"
#include "QuoteGeneration/quote_wrapper/common/inc/sgx_ql_lib_common.h"

namespace asylo {
namespace sgx {
namespace {

// Performs a reinterpret_cast from a pointer of type |InT| to |OutT|. Both
// |InT| and |OutT| must be pointer types. Both pointed-to types must be trivial
// and the same size. Precondition failures result in a compilation error.
template <typename OutT, typename InT>
OutT CheckedPointerCast(InT in) {
  static_assert(std::is_pointer<OutT>::value && std::is_pointer<InT>::value,
                "OutT and InT must both be pointer types");
  using OutObjT = typename std::remove_pointer<OutT>::type;
  using InObjT = typename std::remove_pointer<InT>::type;
  static_assert(sizeof(OutObjT) == sizeof(InObjT),
                "Object sizes must be the same to safely cast");
  static_assert(std::is_trivial<OutObjT>::value,
                "Output type must be trivial to safely cast");
  static_assert(std::is_trivial<InObjT>::value,
                "Input type must be trivial to safely cast");
  return reinterpret_cast<OutT>(in);
}

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

Status Quote3ErrorToStatus(quote3_error_t quote3_error) {
  switch (quote3_error) {
    case SGX_QL_SUCCESS:
      return Status::OkStatus();
    case SGX_QL_ERROR_UNEXPECTED:
      return Status(error::GoogleError::INTERNAL, "Unexpected error");
    case SGX_QL_ERROR_INVALID_PARAMETER:
      return Status(error::GoogleError::INVALID_ARGUMENT, "Invalid parameter");
    case SGX_QL_ERROR_OUT_OF_MEMORY:
      return Status(error::GoogleError::RESOURCE_EXHAUSTED, "Out of memory");
    case SGX_QL_ERROR_ECDSA_ID_MISMATCH:
      return Status(error::GoogleError::INTERNAL,
                    "Unexpected ID in the ECDSA key blob");
    case SGX_QL_PATHNAME_BUFFER_OVERFLOW_ERROR:
      return Status(error::GoogleError::OUT_OF_RANGE,
                    "Pathname buffer overflow");
    case SGX_QL_FILE_ACCESS_ERROR:
      return Status(error::GoogleError::INTERNAL, "File access error");
    case SGX_QL_ERROR_STORED_KEY:
      return Status(error::GoogleError::INTERNAL, "Invalid cached ECDSA key");
    case SGX_QL_ERROR_PUB_KEY_ID_MISMATCH:
      return Status(error::GoogleError::INTERNAL,
                    "Cached ECDSA key ID does not match request");
    case SGX_QL_ERROR_INVALID_PCE_SIG_SCHEME:
      return Status(error::GoogleError::INTERNAL,
                    "The signature scheme supported by the PCE is not "
                    "supported by the QE");
    case SGX_QL_ATT_KEY_BLOB_ERROR:
      return Status(error::GoogleError::INTERNAL, "Attestation key blob error");
    case SGX_QL_UNSUPPORTED_ATT_KEY_ID:
      return Status(error::GoogleError::INTERNAL, "Invalid attestation key ID");
    case SGX_QL_UNSUPPORTED_LOADING_POLICY:
      return Status(error::GoogleError::INTERNAL,
                    "Unsupported enclave loading policy");
    case SGX_QL_INTERFACE_UNAVAILABLE:
      return Status(error::GoogleError::INTERNAL,
                    "Unable to load the quoting enclave");
    case SGX_QL_PLATFORM_LIB_UNAVAILABLE:
      return Status(
          error::GoogleError::INTERNAL,
          "Unable to load the platform quote provider library (not fatal)");
    case SGX_QL_ATT_KEY_NOT_INITIALIZED:
      return Status(error::GoogleError::FAILED_PRECONDITION,
                    "Attestation key not initialized");
    case SGX_QL_ATT_KEY_CERT_DATA_INVALID:
      return Status(error::GoogleError::INTERNAL,
                    "Invalid attestation key certification retrieved from "
                    "platform quote provider library");
    case SGX_QL_NO_PLATFORM_CERT_DATA:
      return Status(error::GoogleError::INTERNAL,
                    "No certification for the platform could be found");
    case SGX_QL_OUT_OF_EPC:
      return Status(error::GoogleError::RESOURCE_EXHAUSTED,
                    "Insufficient EPC memory to load an enclave");
    case SGX_QL_ERROR_REPORT:
      return Status(error::GoogleError::INTERNAL,
                    "An error occurred validating the report");
    case SGX_QL_ENCLAVE_LOST:
      return Status(error::GoogleError::INTERNAL,
                    "The enclave was lost due to power transition or fork()");
    case SGX_QL_INVALID_REPORT:
      return Status(error::GoogleError::INVALID_ARGUMENT,
                    "The application enclave's report failed validation");
    case SGX_QL_ENCLAVE_LOAD_ERROR:
      return Status(error::GoogleError::INTERNAL, "Unable to load an enclave");
    case SGX_QL_UNABLE_TO_GENERATE_QE_REPORT:
      return Status(
          error::GoogleError::INTERNAL,
          "Unable to generate QE report targeting the application enclave");
    case SGX_QL_KEY_CERTIFCATION_ERROR:
      return Status(
          error::GoogleError::INTERNAL,
          "The platform quote provider library returned an invalid TCB");
    case SGX_QL_NETWORK_ERROR:
      return Status(error::GoogleError::INTERNAL,
                    "Network error getting PCK certificates");
    case SGX_QL_MESSAGE_ERROR:
      return Status(error::GoogleError::INTERNAL,
                    "Protocol error getting PCK certificates");
    case SGX_QL_ERROR_INVALID_PRIVILEGE:
      return Status(error::GoogleError::PERMISSION_DENIED,
                    "Invalid permission");
    default:
      return Status(error::GoogleError::UNKNOWN, "Unknown error");
  }
}

}  // namespace

DcapIntelArchitecturalEnclaveInterface::DcapIntelArchitecturalEnclaveInterface(
    std::unique_ptr<DcapLibraryInterface> dcap_library)
    : dcap_library_(std::move(dcap_library)) {}

Status DcapIntelArchitecturalEnclaveInterface::SetEnclaveDir(
    const std::string &path) {
  return Quote3ErrorToStatus(dcap_library_->QeSetEnclaveDirpath(path.c_str()));
}

Status DcapIntelArchitecturalEnclaveInterface::GetPceTargetinfo(
    Targetinfo *targetinfo, uint16_t *pce_svn) {
  sgx_pce_error_t result = dcap_library_->PceGetTarget(
      CheckedPointerCast<sgx_target_info_t *>(targetinfo), pce_svn);

  return PceErrorToStatus(result);
}

Status DcapIntelArchitecturalEnclaveInterface::GetPceInfo(
    const Report &report, absl::Span<const uint8_t> ppid_encryption_key,
    AsymmetricEncryptionScheme ppid_encryption_scheme,
    std::string *ppid_encrypted, uint16_t *pce_svn, uint16_t *pce_id,
    SignatureScheme *signature_scheme) {
  absl::optional<uint8_t> crypto_suite =
      AsymmetricEncryptionSchemeToPceCryptoSuite(ppid_encryption_scheme);
  if (!crypto_suite.has_value()) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  absl::StrCat("Invalid ppid_encryption_scheme: ",
                               ProtoEnumValueName(ppid_encryption_scheme)));
  }

  uint32_t max_ppid_out_size;
  ASYLO_ASSIGN_OR_RETURN(max_ppid_out_size,
                         GetEncryptedDataSize(ppid_encryption_scheme));

  std::vector<uint8_t> ppid_encrypted_tmp(max_ppid_out_size);
  uint32_t encrypted_ppid_out_size = 0;
  uint8_t pce_signature_scheme;
  sgx_pce_error_t result = dcap_library_->GetPceInfo(
      CheckedPointerCast<const sgx_report_t *>(&report),
      ppid_encryption_key.data(), ppid_encryption_key.size(),
      crypto_suite.value(), ppid_encrypted_tmp.data(),
      ppid_encrypted_tmp.size(), &encrypted_ppid_out_size, pce_svn, pce_id,
      &pce_signature_scheme);
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
  std::vector<uint8_t> signature_tmp(kEcdsaP256SignatureSize);
  uint32_t signature_out_size = 0;
  sgx_pce_error_t result = dcap_library_->PceSignReport(
      &target_pce_svn, CheckedPointerCast<sgx_cpu_svn_t *>(&target_cpu_svn),
      CheckedPointerCast<const sgx_report_t *>(&report), signature_tmp.data(),
      signature_tmp.size(), &signature_out_size);
  if (result == SGX_PCE_SUCCESS) {
    signature->assign(signature_tmp.begin(),
                      signature_tmp.begin() + signature_out_size);
  }

  return PceErrorToStatus(result);
}

StatusOr<Targetinfo> DcapIntelArchitecturalEnclaveInterface::GetQeTargetinfo() {
  Targetinfo target_info;
  quote3_error_t result = dcap_library_->QeGetTargetInfo(
      CheckedPointerCast<sgx_target_info_t *>(&target_info));
  if (result == SGX_QL_SUCCESS) {
    return target_info;
  }
  return Quote3ErrorToStatus(result);
}

StatusOr<std::vector<uint8_t>>
DcapIntelArchitecturalEnclaveInterface::GetQeQuote(const Report &report) {
  uint32_t quote_size;
  quote3_error_t result = dcap_library_->QeGetQuoteSize(&quote_size);
  if (result != SGX_QL_SUCCESS) {
    return Quote3ErrorToStatus(result);
  }

  std::vector<uint8_t> quote(quote_size);
  result = dcap_library_->QeGetQuote(
      CheckedPointerCast<const sgx_report_t *>(&report), quote_size,
      quote.data());
  if (result != SGX_QL_SUCCESS) {
    return Quote3ErrorToStatus(result);
  }

  return quote;
}

}  // namespace sgx
}  // namespace asylo
