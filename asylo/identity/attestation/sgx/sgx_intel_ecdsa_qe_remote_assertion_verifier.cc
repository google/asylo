/*
 *
 * Copyright 2020 Asylo authors
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

#include "asylo/identity/attestation/sgx/sgx_intel_ecdsa_qe_remote_assertion_verifier.h"

#include <math.h>

#include <algorithm>
#include <iterator>
#include <string>

#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/certificate.pb.h"
#include "asylo/crypto/certificate_interface.h"
#include "asylo/crypto/certificate_util.h"
#include "asylo/crypto/ecdsa_p256_sha256_signing_key.h"
#include "asylo/crypto/keys.pb.h"
#include "asylo/crypto/sha256_hash.h"
#include "asylo/crypto/sha256_hash.pb.h"
#include "asylo/crypto/util/byte_container_util.h"
#include "asylo/crypto/util/bytes.h"
#include "asylo/crypto/util/trivial_object_util.h"
#include "asylo/crypto/x509_certificate.h"
#include "asylo/identity/additional_authenticated_data_generator.h"
#include "asylo/identity/attestation/sgx/internal/intel_ecdsa_quote.h"
#include "asylo/identity/attestation/sgx/internal/pce_util.h"
#include "asylo/identity/attestation/sgx/sgx_intel_ecdsa_qe_remote_assertion_authority_config.pb.h"
#include "asylo/identity/descriptions.h"
#include "asylo/identity/enclave_assertion_authority.h"
#include "asylo/identity/enclave_assertion_authority_config_verifiers.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/identity/identity_acl.pb.h"
#include "asylo/identity/identity_acl_evaluator.h"
#include "asylo/identity/platform/sgx/code_identity.pb.h"
#include "asylo/identity/platform/sgx/internal/code_identity_constants.h"
#include "asylo/identity/platform/sgx/internal/identity_key_management_structs.h"
#include "asylo/identity/platform/sgx/internal/sgx_identity_util_internal.h"
#include "asylo/identity/platform/sgx/machine_configuration.pb.h"
#include "asylo/identity/platform/sgx/sgx_identity.pb.h"
#include "asylo/identity/platform/sgx/sgx_identity_expectation_matcher.h"
#include "asylo/identity/platform/sgx/sgx_identity_util.h"
#include "asylo/identity/provisioning/sgx/internal/pck_certificate_util.h"
#include "asylo/platform/common/static_map.h"
#include "asylo/util/error_codes.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"
#include "QuoteGeneration/quote_wrapper/common/inc/sgx_quote_3.h"
#include "QuoteVerification/Src/AttestationLibrary/include/QuoteVerification/QuoteConstants.h"

namespace asylo {
namespace {

StatusOr<std::unique_ptr<EcdsaP256Sha256VerifyingKey>>
ToEcdsaP256Sha256VerifyingKey(UnsafeBytes<64> big_endian_key_bytes) {
  EccP256CurvePoint public_key_point;
  static_assert(sizeof(big_endian_key_bytes) == sizeof(public_key_point),
                "Key size mismatch");
  memcpy(&public_key_point, &big_endian_key_bytes, sizeof(public_key_point));
  return EcdsaP256Sha256VerifyingKey::Create(public_key_point);
}

Status CheckDescription(const AssertionDescription &description) {
  if (description.identity_type() != CODE_IDENTITY ||
      description.authority_type() !=
          sgx::kSgxIntelEcdsaQeRemoteAssertionAuthority) {
    return absl::InvalidArgumentError("Assertion description does not match");
  }

  return absl::OkStatus();
}

StatusOr<CertificateChain> GetPckCertificateChainFromCertData(
    const std::vector<uint8_t> &cert_data) {
  return GetCertificateChainFromPem(absl::string_view(
      reinterpret_cast<const char *>(cert_data.data()), cert_data.size()));
}

Status VerifyQuoteHeader(const sgx::IntelQeQuote &quote) {
  if (quote.header.version != intel::sgx::qvl::constants::QUOTE_VERSION) {
    return absl::InvalidArgumentError(absl::StrFormat(
        "Invalid quote version '%d'. Expected '%d'", quote.header.version,
        intel::sgx::qvl::constants::QUOTE_VERSION));
  }

  if (quote.header.algorithm !=
      intel::sgx::qvl::constants::ECDSA_256_WITH_P256_CURVE) {
    return absl::InvalidArgumentError(absl::StrFormat(
        "Invalid quote algorithm '%d'. Expected '%d'", quote.header.algorithm,
        intel::sgx::qvl::constants::ECDSA_256_WITH_P256_CURVE));
  }

  if (!quote.header.qe_vendor_id.Equals(
          intel::sgx::qvl::constants::INTEL_QE_VENDOR_ID)) {
    return absl::InvalidArgumentError(absl::StrFormat(
        "Invalid vendor ID '%s'. Expected '%s'",
        ConvertTrivialObjectToHexString(quote.header.qe_vendor_id),
        ConvertTrivialObjectToHexString(
            intel::sgx::qvl::constants::INTEL_QE_VENDOR_ID)));
  }

  return absl::OkStatus();
}

Status VerifyQuoteBodySignature(
    const AdditionalAuthenticatedDataGenerator &aad_generator,
    const std::string &user_data, const sgx::IntelQeQuote &quote) {
  UnsafeBytes<kAdditionalAuthenticatedDataSize> expected_auth_data;
  ASYLO_ASSIGN_OR_RETURN(expected_auth_data, aad_generator.Generate(user_data));
  if (!expected_auth_data.Equals(quote.body.reportdata.data)) {
    return absl::InvalidArgumentError(
        "Authenticated quote data does not match expected user data");
  }

  std::unique_ptr<EcdsaP256Sha256VerifyingKey> verifying_key;
  ASYLO_ASSIGN_OR_RETURN(
      verifying_key, ToEcdsaP256Sha256VerifyingKey(quote.signature.public_key));

  Signature signature;
  ASYLO_ASSIGN_OR_RETURN(signature,
                         sgx::CreateSignatureFromPckEcdsaP256Sha256Signature(
                             quote.signature.body_signature));

  return verifying_key->Verify(
      {&quote, sizeof(quote.header) + sizeof(quote.body)}, signature);
}

Status VerifyQeReportDataMatchesQuoteSigningKey(
    const sgx::IntelQeQuote &quote) {
  // The provisioning certification enclave certifies the quoting enclave's
  // signing key by signing the QE's report data. The report data contains a
  // hash of the quote signing key, creating a chain from the quote up to the
  // Intel root.
  Sha256Hash sha256;
  sha256.Update(quote.signature.public_key);
  sha256.Update(quote.qe_authn_data);

  std::vector<uint8_t> report_data;
  ASYLO_RETURN_IF_ERROR(sha256.CumulativeHash(&report_data));

  // According to Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf, the report
  // has the hash at the front of the data, followed by 32 0x00's.
  constexpr uint8_t kDefaultValue = 0;
  report_data.resize(sgx::kReportdataSize, kDefaultValue);

  if (!quote.signature.qe_report.reportdata.data.Equals(report_data)) {
    return absl::InvalidArgumentError(
        "Quoting enclave report data does not match quote signing "
        "key and authenticated data");
  }

  return absl::OkStatus();
}

Status VerifyPckSignatureFromPckCertChain(
    const std::vector<uint8_t> &cert_data,
    const sgx::IntelEcdsaP256QuoteSignature &signature) {
  CertificateChain pck_cert_chain;
  ASYLO_ASSIGN_OR_RETURN(pck_cert_chain,
                         GetPckCertificateChainFromCertData(cert_data));

  std::unique_ptr<X509Certificate> pck_cert;
  ASYLO_ASSIGN_OR_RETURN(pck_cert, X509Certificate::Create(
                                       *pck_cert_chain.certificates().begin()));

  std::string pck_der;
  ASYLO_ASSIGN_OR_RETURN(pck_der, pck_cert->SubjectKeyDer());

  std::unique_ptr<EcdsaP256Sha256VerifyingKey> pck_pub;
  ASYLO_ASSIGN_OR_RETURN(pck_pub,
                         EcdsaP256Sha256VerifyingKey::CreateFromDer(pck_der));

  Signature qe_report_signature;
  ASYLO_ASSIGN_OR_RETURN(qe_report_signature,
                         sgx::CreateSignatureFromPckEcdsaP256Sha256Signature(
                             signature.qe_report_signature));
  return pck_pub->Verify(
      ConvertTrivialObjectToBinaryString(signature.qe_report),
      qe_report_signature);
}

Status VerifyPckSignatureOverQuotingEnclave(const sgx::IntelQeQuote &quote) {
  switch (quote.cert_data.qe_cert_data_type) {
    case PCK_CERT_CHAIN:
      return VerifyPckSignatureFromPckCertChain(quote.cert_data.qe_cert_data,
                                                quote.signature);
  }
  return absl::UnimplementedError(
      absl::StrFormat("Verification not supported for QE cert data type %d",
                      quote.cert_data.qe_cert_data_type));
}

Status VerifyPckCertificateChain(
    const sgx::IntelQeQuote &quote,
    const std::vector<std::unique_ptr<CertificateInterface>>
        &trusted_root_certificates) {
  CertificateChain pck_cert_chain;
  ASYLO_ASSIGN_OR_RETURN(pck_cert_chain, GetPckCertificateChainFromCertData(
                                             quote.cert_data.qe_cert_data));

  CertificateInterfaceVector certificate_chain;
  ASYLO_ASSIGN_OR_RETURN(
      certificate_chain,
      CreateCertificateChain({{Certificate::X509_PEM, X509Certificate::Create}},
                             pck_cert_chain));

  VerificationConfig verification_config(/*all_fields=*/true);
  ASYLO_RETURN_IF_ERROR(
      VerifyCertificateChain(certificate_chain, verification_config));

  const CertificateInterface &root_certificate = *certificate_chain.back();

  if (std::none_of(
          trusted_root_certificates.begin(), trusted_root_certificates.end(),
          [&root_certificate](
              const std::unique_ptr<CertificateInterface> &trusted_root) {
            return root_certificate == *trusted_root;
          })) {
    return absl::UnauthenticatedError(
        absl::StrCat("Unrecognized root certificate: ",
                     root_certificate.SubjectName().value_or("Unknown CA")));
  }

  return absl::OkStatus();
}

Status ParseAndAppendPeerMachineConfigurationFromPckCertChain(
    const sgx::IntelCertData &cert_data, SgxIdentity *identity) {
  CertificateChain pck_cert_chain;
  ASYLO_ASSIGN_OR_RETURN(pck_cert_chain, GetPckCertificateChainFromCertData(
                                             cert_data.qe_cert_data));

  std::unique_ptr<X509Certificate> pck_cert;
  ASYLO_ASSIGN_OR_RETURN(pck_cert, X509Certificate::Create(
                                       *pck_cert_chain.certificates().begin()));

  ASYLO_ASSIGN_OR_RETURN(
      *identity->mutable_machine_configuration(),
      sgx::ExtractMachineConfigurationFromPckCert(pck_cert.get()));

  return absl::OkStatus();
}

Status ParseEnclaveIdentityFromQuote(const sgx::ReportBody &report_body,
                                     const sgx::IntelCertData &cert_data,
                                     EnclaveIdentity *enclave_identity) {
  SgxIdentity identity = ParseSgxIdentityFromHardwareReport(report_body);

  switch (cert_data.qe_cert_data_type) {
    case PCK_CERT_CHAIN: {
      ASYLO_RETURN_IF_ERROR(
          ParseAndAppendPeerMachineConfigurationFromPckCertChain(cert_data,
                                                                 &identity));
      ASYLO_ASSIGN_OR_RETURN(*enclave_identity, SerializeSgxIdentity(identity));
      return absl::OkStatus();
    }
  }

  return absl::UnimplementedError(
      absl::StrFormat("Extracting peer machine identity not "
                      "supported for QE cert data type %d",
                      cert_data.qe_cert_data_type));
}

Status VerifyQeIdentityMatchesExpectation(
    const sgx::IntelQeQuote &quote,
    const IdentityAclPredicate &qe_expectation) {
  EnclaveIdentity qe_identity;
  ASYLO_RETURN_IF_ERROR(ParseEnclaveIdentityFromQuote(
      quote.signature.qe_report, quote.cert_data, &qe_identity));

  std::string explanation;
  SgxIdentityExpectationMatcher matcher;

  bool qe_match_result;
  ASYLO_ASSIGN_OR_RETURN(qe_match_result,
                         EvaluateIdentityAcl({qe_identity}, qe_expectation,
                                             matcher, &explanation));

  if (!qe_match_result) {
    return absl::UnauthenticatedError(
        absl::StrCat("QE identity did not match expectation: ", explanation));
  }

  return absl::OkStatus();
}

}  // namespace

SgxIntelEcdsaQeRemoteAssertionVerifier::SgxIntelEcdsaQeRemoteAssertionVerifier()
    : SgxIntelEcdsaQeRemoteAssertionVerifier(
          AdditionalAuthenticatedDataGenerator::CreateEkepAadGenerator()) {}

SgxIntelEcdsaQeRemoteAssertionVerifier::SgxIntelEcdsaQeRemoteAssertionVerifier(
    std::unique_ptr<AdditionalAuthenticatedDataGenerator> aad_generator)
    : members_(Members(std::move(aad_generator))) {}

Status SgxIntelEcdsaQeRemoteAssertionVerifier::Initialize(
    const std::string &serialized_config) {
  auto members_view = members_.Lock();
  if (members_view->is_initialized) {
    return absl::FailedPreconditionError("Already initialized");
  }

  SgxIntelEcdsaQeRemoteAssertionAuthorityConfig config;
  if (!config.ParseFromString(serialized_config)) {
    return absl::InvalidArgumentError(
        "Failed to deserialize assertion authority configuration");
  }

  ASYLO_RETURN_IF_ERROR(
      VerifySgxIntelEcdsaQeRemoteAssertionAuthorityConfig(config));

  // The configuration may not necessarily contain verifier info. In this case,
  // do not initialize the verifier at all, as the caller did not specify enough
  // information for the verifier to determine trust in remote assertions.
  if (!config.has_verifier_info()) {
    return absl::OkStatus();
  }

  std::vector<std::unique_ptr<CertificateInterface>> root_certificates;
  auto inserter = std::back_inserter(root_certificates);
  for (auto &cert : config.verifier_info().root_certificates()) {
    ASYLO_ASSIGN_OR_RETURN(inserter, X509Certificate::Create(cert));
  }

  members_view->qe_identity_expectation = std::move(
      *config.mutable_verifier_info()->mutable_qe_identity_expectation());
  members_view->root_certificates = std::move(root_certificates);
  members_view->is_initialized = true;

  return absl::OkStatus();
}

bool SgxIntelEcdsaQeRemoteAssertionVerifier::IsInitialized() const {
  return members_.ReaderLock()->is_initialized;
}

EnclaveIdentityType SgxIntelEcdsaQeRemoteAssertionVerifier::IdentityType()
    const {
  return CODE_IDENTITY;
}

std::string SgxIntelEcdsaQeRemoteAssertionVerifier::AuthorityType() const {
  return sgx::kSgxIntelEcdsaQeRemoteAssertionAuthority;
}

Status SgxIntelEcdsaQeRemoteAssertionVerifier::CreateAssertionRequest(
    AssertionRequest *request) const {
  ASYLO_RETURN_IF_ERROR(CheckInitialization(__func__));

  SetSgxIntelEcdsaQeRemoteAssertionDescription(request->mutable_description());
  return absl::OkStatus();
}

StatusOr<bool> SgxIntelEcdsaQeRemoteAssertionVerifier::CanVerify(
    const AssertionOffer &offer) const {
  ASYLO_RETURN_IF_ERROR(CheckInitialization(__func__));
  ASYLO_RETURN_IF_ERROR(CheckDescription(offer.description()));
  return true;
}

Status SgxIntelEcdsaQeRemoteAssertionVerifier::Verify(
    const std::string &user_data, const Assertion &assertion,
    EnclaveIdentity *peer_identity) const {
  ASYLO_RETURN_IF_ERROR(CheckInitialization(__func__));
  ASYLO_RETURN_IF_ERROR(CheckDescription(assertion.description()));

  sgx::IntelQeQuote quote;
  ASYLO_ASSIGN_OR_RETURN(
      quote, asylo::sgx::ParseDcapPackedQuote(assertion.assertion()));

  auto members_view = members_.ReaderLock();
  ASYLO_RETURN_IF_ERROR(VerifyQuoteHeader(quote));
  ASYLO_RETURN_IF_ERROR(
      VerifyQuoteBodySignature(*members_view->aad_generator, user_data, quote));
  ASYLO_RETURN_IF_ERROR(VerifyQeReportDataMatchesQuoteSigningKey(quote));
  ASYLO_RETURN_IF_ERROR(VerifyPckSignatureOverQuotingEnclave(quote));
  ASYLO_RETURN_IF_ERROR(
      VerifyPckCertificateChain(quote, members_view->root_certificates));
  ASYLO_RETURN_IF_ERROR(VerifyQeIdentityMatchesExpectation(
      quote, members_view->qe_identity_expectation));

  ASYLO_RETURN_IF_ERROR(ParseEnclaveIdentityFromQuote(
      quote.body, quote.cert_data, peer_identity));

  return absl::OkStatus();
}

Status SgxIntelEcdsaQeRemoteAssertionVerifier::CheckInitialization(
    absl::string_view caller) const {
  return IsInitialized() ? absl::OkStatus()
                         : absl::FailedPreconditionError(absl::StrCat(
                               "SgxIntelEcdsaQeRemoteAssertionVerifier "
                               "must be initialized before calling ",
                               caller));
}

SET_STATIC_MAP_VALUE_OF_DERIVED_TYPE(AssertionVerifierMap,
                                     SgxIntelEcdsaQeRemoteAssertionVerifier);

}  // namespace asylo
