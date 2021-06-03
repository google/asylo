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

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/certificate_util.h"
#include "asylo/crypto/x509_certificate.h"
#include "asylo/identity/attestation/sgx/internal/dcap_library_interface.h"
#include "asylo/identity/attestation/sgx/internal/intel_architectural_enclave_interface.h"
#include "asylo/identity/attestation/sgx/internal/pce_util.h"
#include "asylo/identity/provisioning/sgx/internal/pck_certificate_util.h"
#include "asylo/util/error_codes.h"
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
      return absl::OkStatus();
    case SGX_PCE_UNEXPECTED:
      return absl::InternalError("Unexpected error");
    case SGX_PCE_OUT_OF_EPC:
      return absl::InternalError("Not enough EPC to load the PCE");
    case SGX_PCE_INTERFACE_UNAVAILABLE:
      return absl::InternalError("Interface unavailable");
    case SGX_PCE_CRYPTO_ERROR:
      return absl::InternalError("Evaluation of REPORT.REPORTDATA failed");
    case SGX_PCE_INVALID_PARAMETER:
      return absl::InvalidArgumentError("Invalid parameter");
    case SGX_PCE_INVALID_REPORT:
      return absl::InvalidArgumentError("Invalid report");
    case SGX_PCE_INVALID_TCB:
      return absl::InvalidArgumentError("Invalid TCB");
    case SGX_PCE_INVALID_PRIVILEGE:
      return absl::PermissionDeniedError(
          "Report must have the PROVISION_KEY attribute bit set");
    default:
      return absl::UnknownError("Unknown error");
  }
}

Status Quote3ErrorToStatus(quote3_error_t quote3_error) {
  switch (quote3_error) {
    case SGX_QL_SUCCESS:
      return absl::OkStatus();
    case SGX_QL_ERROR_UNEXPECTED:
      return absl::InternalError("Unexpected error");
    case SGX_QL_ERROR_INVALID_PARAMETER:
      return absl::InvalidArgumentError("Invalid parameter");
    case SGX_QL_ERROR_OUT_OF_MEMORY:
      return absl::ResourceExhaustedError("Out of memory");
    case SGX_QL_ERROR_ECDSA_ID_MISMATCH:
      return absl::InternalError("Unexpected ID in the ECDSA key blob");
    case SGX_QL_PATHNAME_BUFFER_OVERFLOW_ERROR:
      return absl::OutOfRangeError("Pathname buffer overflow");
    case SGX_QL_FILE_ACCESS_ERROR:
      return absl::InternalError("File access error");
    case SGX_QL_ERROR_STORED_KEY:
      return absl::InternalError("Invalid cached ECDSA key");
    case SGX_QL_ERROR_PUB_KEY_ID_MISMATCH:
      return absl::InternalError("Cached ECDSA key ID does not match request");
    case SGX_QL_ERROR_INVALID_PCE_SIG_SCHEME:
      return absl::InternalError(
          "The signature scheme supported by the PCE is not "
          "supported by the QE");
    case SGX_QL_ATT_KEY_BLOB_ERROR:
      return absl::InternalError("Attestation key blob error");
    case SGX_QL_UNSUPPORTED_ATT_KEY_ID:
      return absl::InternalError("Invalid attestation key ID");
    case SGX_QL_UNSUPPORTED_LOADING_POLICY:
      return absl::InternalError("Unsupported enclave loading policy");
    case SGX_QL_INTERFACE_UNAVAILABLE:
      return absl::InternalError("Unable to load the quoting enclave");
    case SGX_QL_PLATFORM_LIB_UNAVAILABLE:
      return absl::InternalError(
          "Unable to load the platform quote provider library (not fatal)");
    case SGX_QL_ATT_KEY_NOT_INITIALIZED:
      return absl::FailedPreconditionError("Attestation key not initialized");
    case SGX_QL_ATT_KEY_CERT_DATA_INVALID:
      return absl::InternalError(
          "Invalid attestation key certification retrieved from "
          "platform quote provider library");
    case SGX_QL_NO_PLATFORM_CERT_DATA:
      return absl::InternalError(
          "No certification for the platform could be found");
    case SGX_QL_OUT_OF_EPC:
      return absl::ResourceExhaustedError(
          "Insufficient EPC memory to load an enclave");
    case SGX_QL_ERROR_REPORT:
      return absl::InternalError("An error occurred validating the report");
    case SGX_QL_ENCLAVE_LOST:
      return absl::InternalError(
          "The enclave was lost due to power transition or fork()");
    case SGX_QL_INVALID_REPORT:
      return absl::InvalidArgumentError(
          "The application enclave's report failed validation");
    case SGX_QL_ENCLAVE_LOAD_ERROR:
      return absl::InternalError("Unable to load an enclave");
    case SGX_QL_UNABLE_TO_GENERATE_QE_REPORT:
      return absl::InternalError(
          "Unable to generate QE report targeting the application enclave");
    case SGX_QL_KEY_CERTIFCATION_ERROR:
      return absl::InternalError(
          "The platform quote provider library returned an invalid TCB");
    case SGX_QL_NETWORK_ERROR:
      return absl::InternalError("Network error getting PCK certificates");
    case SGX_QL_MESSAGE_ERROR:
      return absl::InternalError("Protocol error getting PCK certificates");
    case SGX_QL_ERROR_INVALID_PRIVILEGE:
      return absl::PermissionDeniedError("Invalid permission");
    default:
      return absl::UnknownError("Unknown error");
  }
}

}  // namespace

DcapIntelArchitecturalEnclaveInterface::DcapIntelArchitecturalEnclaveInterface(
    std::unique_ptr<DcapLibraryInterface> dcap_library)
    : dcap_library_(std::move(dcap_library)) {}

Status DcapIntelArchitecturalEnclaveInterface::SetPckCertificateChain(
    const CertificateChain &chain) {
  if (chain.certificates().empty()) {
    return absl::InvalidArgumentError("Certificate chain is empty");
  }

  auto parsed_chain =
      CreateCertificateChain({{Certificate::X509_PEM, X509Certificate::Create},
                              {Certificate::X509_DER, X509Certificate::Create}},
                             chain);
  if (!parsed_chain.ok()) {
    // Wrap the cert parsing error so that we always return INVALID_ARGUMENT if
    // the input cert chain cannot be parsed. The cert chain parsing code will
    // return other errors, which are potentially misleading.
    return absl::InvalidArgumentError(parsed_chain.status().message());
  }

  SgxExtensions extensions;
  ASYLO_ASSIGN_OR_RETURN(extensions, ExtractSgxExtensionsFromPckCert(
                                         *parsed_chain.value().front()));

  sgx_ql_config_t config;
  config.version = SGX_QL_CONFIG_VERSION_1;
  if (extensions.cpu_svn.value().size() != sizeof(config.cert_cpu_svn)) {
    return absl::InvalidArgumentError(absl::StrCat(
        "CPUSVN in the cert is ", extensions.cpu_svn.value().size(),
        " bytes. Expected ", sizeof(config.cert_cpu_svn)));
  }
  memcpy(&config.cert_cpu_svn, extensions.cpu_svn.value().data(),
         extensions.cpu_svn.value().size());
  config.cert_pce_isv_svn = extensions.tcb.pce_svn().value();

  std::string cert_data;
  for (const auto &parsed_cert : parsed_chain.value()) {
    Certificate proto_cert;
    ASYLO_ASSIGN_OR_RETURN(
        proto_cert, parsed_cert->ToCertificateProto(Certificate::X509_PEM));
    absl::StrAppend(&cert_data, proto_cert.data());
    // The output is a PEM with multiple certs. Each cert must be separated from
    // the previous one with a newline.
    if (proto_cert.data().back() != '\n') {
      absl::StrAppend(&cert_data, "\n");
    }
  }

  config.cert_data_size = cert_data.size();
  config.p_cert_data =
      reinterpret_cast<uint8_t *>(const_cast<char *>(cert_data.data()));
  return Quote3ErrorToStatus(dcap_library_->SetQuoteConfig(config));
}

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
    return absl::InvalidArgumentError(
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
