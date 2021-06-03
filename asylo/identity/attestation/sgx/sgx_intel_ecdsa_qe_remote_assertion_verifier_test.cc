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

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/status/status.h"
#include "asylo/crypto/certificate.pb.h"
#include "asylo/crypto/ecdsa_p256_sha256_signing_key.h"
#include "asylo/crypto/keys.pb.h"
#include "asylo/crypto/sha256_hash.h"
#include "asylo/crypto/sha256_hash.pb.h"
#include "asylo/crypto/util/byte_container_util.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/crypto/util/bytes.h"
#include "asylo/crypto/util/trivial_object_util.h"
#include "asylo/identity/additional_authenticated_data_generator.h"
#include "asylo/identity/attestation/enclave_assertion_verifier.h"
#include "asylo/identity/attestation/sgx/internal/fake_pce.h"
#include "asylo/identity/attestation/sgx/internal/intel_ecdsa_quote.h"
#include "asylo/identity/attestation/sgx/sgx_intel_ecdsa_qe_remote_assertion_authority_config.pb.h"
#include "asylo/identity/enclave_assertion_authority.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/identity/platform/sgx/code_identity.pb.h"
#include "asylo/identity/platform/sgx/internal/code_identity_constants.h"
#include "asylo/identity/platform/sgx/internal/identity_key_management_structs.h"
#include "asylo/identity/platform/sgx/internal/secs_attributes.h"
#include "asylo/identity/platform/sgx/internal/sgx_identity_util_internal.h"
#include "asylo/identity/platform/sgx/machine_configuration.pb.h"
#include "asylo/identity/platform/sgx/sgx_identity_util.h"
#include "asylo/identity/provisioning/sgx/internal/fake_sgx_pki.h"
#include "asylo/platform/common/static_map.h"
#include "asylo/test/util/memory_matchers.h"
#include "asylo/test/util/proto_matchers.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/error_codes.h"
#include "asylo/util/proto_parse_util.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"
#include "QuoteVerification/Src/AttestationLibrary/include/QuoteVerification/QuoteConstants.h"

namespace asylo {
namespace {

using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::IsTrue;
using ::testing::Test;

// clang-format off
constexpr char kValidAssertionDescriptionProto[] = R"pb(
    description: {
      identity_type: CODE_IDENTITY
      authority_type: "SGX Intel ECDSA QE"
    })pb";
// clang-format on

class SgxIntelEcdsaQeRemoteAssertionVerifierTest : public Test {
 protected:
  void SetUp() override {
    qe_identity_ = TrivialRandomObject<sgx::ReportBody>();

    *valid_config_proto_.mutable_verifier_info()->add_root_certificates() =
        sgx::GetFakeSgxRootCertificate();

    SgxIdentityExpectation qe_expectation;
    ASYLO_ASSERT_OK_AND_ASSIGN(
        qe_expectation, CreateSgxIdentityExpectation(
                            ParseSgxIdentityFromHardwareReport(qe_identity_),
                            SgxIdentityMatchSpecOptions::DEFAULT));
    ASYLO_ASSERT_OK_AND_ASSIGN(*valid_config_proto_.mutable_verifier_info()
                                    ->mutable_qe_identity_expectation()
                                    ->mutable_expectation(),
                               SerializeSgxIdentityExpectation(qe_expectation));

    ASSERT_TRUE(valid_config_proto_.SerializeToString(&valid_config_));
  }

  sgx::IntelQeQuoteHeader GenerateValidQuoteHeader() const {
    // Pull the constants directly from the Intel spec instead of their
    // libraries so that we confirm compliance with the written spec.
    constexpr int kVersion = 3;
    constexpr int kEcdsaP256 = 2;
    constexpr char kVendorId[] =
        "\x93\x9A\x72\x33\xF7\x9C\x4C\xA9\x94\x0A\x0D\xB3\x95\x7F\x06\x07";

    auto header = TrivialRandomObject<sgx::IntelQeQuoteHeader>();
    header.version = kVersion;
    header.algorithm = kEcdsaP256;
    header.qe_vendor_id.assign(kVendorId, sizeof(kVendorId) - 1);
    return header;
  }

  sgx::ReportBody GenerateValidQuoteBody(ByteContainerView user_data) const {
    auto body = TrivialRandomObject<sgx::ReportBody>();
    auto aad_generator =
        AdditionalAuthenticatedDataGenerator::CreateEkepAadGenerator();
    body.reportdata.data = aad_generator->Generate(user_data).value();
    return body;
  }

  void SignQuoteHeaderAndReport(sgx::IntelQeQuote *quote,
                                const sgx::ReportBody &qe_identity) const {
    auto signing_key = EcdsaP256Sha256SigningKey::Create().value();
    ByteContainerView data_to_sign(quote,
                                   sizeof(quote->header) + sizeof(quote->body));
    Signature signature;
    ASYLO_ASSERT_OK(signing_key->Sign(data_to_sign, &signature));
    ASSERT_THAT(signature.ecdsa_signature().r().size(), Eq(32));
    quote->signature.body_signature.replace(0, signature.ecdsa_signature().r());

    ASSERT_THAT(signature.ecdsa_signature().s().size(), Eq(32));
    quote->signature.body_signature.replace(32,
                                            signature.ecdsa_signature().s());

    EccP256CurvePoint key_bytes = signing_key->GetPublicKeyPoint().value();
    static_assert(sizeof(quote->signature.public_key) == sizeof(key_bytes),
                  "Key size mismatch");
    quote->signature.public_key.assign(&key_bytes, sizeof(key_bytes));

    quote->signature.qe_report = qe_identity;
  }

  std::vector<uint8_t> CreateCertData(
      const std::vector<absl::string_view> &pem_certificates) const {
    std::vector<uint8_t> cert_data;
    for (auto pem_cert : pem_certificates) {
      cert_data.insert(cert_data.end(), pem_cert.begin(), pem_cert.end());
    }
    return cert_data;
  }

  void SignQuotingEnclaveReport(sgx::IntelQeQuote *quote) const {
    Sha256Hash sha256;
    sha256.Update(quote->signature.public_key);
    sha256.Update(quote->qe_authn_data);

    std::vector<uint8_t> report_data;
    ASYLO_ASSERT_OK(sha256.CumulativeHash(&report_data));
    report_data.resize(sgx::kReportdataSize);
    quote->signature.qe_report.reportdata.data.assign(report_data);

    quote->cert_data.qe_cert_data_type =
        ::intel::sgx::qvl::constants::PCK_ID_PCK_CERT_CHAIN;
    quote->cert_data.qe_cert_data = CreateCertData({
        sgx::kFakeSgxPck.certificate_pem,
        sgx::kFakeSgxProcessorCa.certificate_pem,
        sgx::kFakeSgxRootCa.certificate_pem,
    });

    std::unique_ptr<sgx::FakePce> pce;
    ASYLO_ASSERT_OK_AND_ASSIGN(pce, sgx::FakePce::CreateFromFakePki());

    sgx::Report qe_report_to_sign;
    qe_report_to_sign.body = quote->signature.qe_report;

    std::string qe_report_signature;
    ASYLO_ASSERT_OK(pce->PceSignReport(qe_report_to_sign, sgx::FakePce::kPceSvn,
                                       quote->signature.qe_report.cpusvn,
                                       &qe_report_signature));
    std::copy(qe_report_signature.begin(), qe_report_signature.end(),
              quote->signature.qe_report_signature.begin());
  }

  sgx::IntelQeQuote GenerateValidQuote(
      ByteContainerView user_data, const sgx::ReportBody &qe_identity) const {
    sgx::IntelQeQuote quote;
    quote.header = GenerateValidQuoteHeader();
    quote.body = GenerateValidQuoteBody(user_data);
    SignQuoteHeaderAndReport(&quote, qe_identity);
    AppendTrivialObject(TrivialRandomObject<UnsafeBytes<123>>(),
                        &quote.qe_authn_data);
    SignQuotingEnclaveReport(&quote);
    return quote;
  }

  // Generates a valid quote issued by |qe_identity_|.
  sgx::IntelQeQuote GenerateValidQuote(ByteContainerView user_data) const {
    return GenerateValidQuote(user_data, qe_identity_);
  }

  // Creates an assertion object that wraps the given quote, with the correct
  // description targeting the SGX Intel ECDSA QE assertion authority.
  Assertion CreateAssertion(sgx::IntelQeQuote quote) {
    Assertion assertion = ParseTextProtoOrDie(kValidAssertionDescriptionProto);

    std::vector<uint8_t> packed_quote = sgx::PackDcapQuote(quote);
    assertion.set_assertion(packed_quote.data(), packed_quote.size());
    return assertion;
  }

  sgx::ReportBody qe_identity_;
  std::string valid_config_;
  SgxIntelEcdsaQeRemoteAssertionAuthorityConfig valid_config_proto_;
};

TEST_F(SgxIntelEcdsaQeRemoteAssertionVerifierTest, VerifierFoundInStaticMap) {
  std::string authority_id;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      authority_id,
      EnclaveAssertionAuthority::GenerateAuthorityId(
          CODE_IDENTITY, sgx::kSgxIntelEcdsaQeRemoteAssertionAuthority));

  ASSERT_NE(AssertionVerifierMap::GetValue(authority_id),
            AssertionVerifierMap::value_end());
}

TEST_F(SgxIntelEcdsaQeRemoteAssertionVerifierTest, IdentityType) {
  SgxIntelEcdsaQeRemoteAssertionVerifier verifier;
  EXPECT_EQ(verifier.IdentityType(), CODE_IDENTITY);
}

TEST_F(SgxIntelEcdsaQeRemoteAssertionVerifierTest, AuthorityType) {
  SgxIntelEcdsaQeRemoteAssertionVerifier verifier;
  EXPECT_EQ(verifier.AuthorityType(),
            sgx::kSgxIntelEcdsaQeRemoteAssertionAuthority);
}

TEST_F(SgxIntelEcdsaQeRemoteAssertionVerifierTest, InitializeSucceedsOnce) {
  SgxIntelEcdsaQeRemoteAssertionVerifier verifier;
  ASYLO_EXPECT_OK(verifier.Initialize(valid_config_));
  EXPECT_THAT(verifier.Initialize(valid_config_),
              StatusIs(absl::StatusCode::kFailedPrecondition));
}

TEST_F(SgxIntelEcdsaQeRemoteAssertionVerifierTest,
       IsInitializedReturnsFalsePriorToInitialize) {
  SgxIntelEcdsaQeRemoteAssertionVerifier verifier;
  EXPECT_FALSE(verifier.IsInitialized());
}

TEST_F(SgxIntelEcdsaQeRemoteAssertionVerifierTest,
       IsInitializedReturnsTrueAfterInitialize) {
  SgxIntelEcdsaQeRemoteAssertionVerifier verifier;
  ASYLO_EXPECT_OK(verifier.Initialize(valid_config_));
  EXPECT_TRUE(verifier.IsInitialized());
}

TEST_F(SgxIntelEcdsaQeRemoteAssertionVerifierTest,
       IsInitializedReturnsFalseWithoutVerifierInfo) {
  std::string serialized_config;
  SgxIntelEcdsaQeRemoteAssertionAuthorityConfig config;
  *config.mutable_generator_info()
       ->mutable_pck_certificate_chain()
       ->add_certificates() = sgx::GetFakeSgxRootCertificate();
  ASSERT_TRUE(config.SerializeToString(&serialized_config));

  SgxIntelEcdsaQeRemoteAssertionVerifier verifier;
  ASYLO_EXPECT_OK(verifier.Initialize(serialized_config));
  EXPECT_FALSE(verifier.IsInitialized());
}

TEST_F(SgxIntelEcdsaQeRemoteAssertionVerifierTest,
       InitializeFailsWithUnparsableConfig) {
  SgxIntelEcdsaQeRemoteAssertionVerifier verifier;
  EXPECT_THAT(verifier.Initialize("!@#!@"),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(SgxIntelEcdsaQeRemoteAssertionVerifierTest,
       InitializeFailsWithInvalidConfig) {
  // There are separate tests for config validation, so there is no need to test
  // lots of permutations of bad configuration here.
  SgxIntelEcdsaQeRemoteAssertionAuthorityConfig config;
  std::string serialized_config;
  ASSERT_TRUE(config.SerializeToString(&serialized_config));

  SgxIntelEcdsaQeRemoteAssertionVerifier verifier;
  EXPECT_THAT(verifier.Initialize(serialized_config),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(SgxIntelEcdsaQeRemoteAssertionVerifierTest,
       CreateAssertionRequestFailsIfNotInitialized) {
  SgxIntelEcdsaQeRemoteAssertionVerifier verifier;

  AssertionRequest request;
  EXPECT_THAT(verifier.CreateAssertionRequest(&request),
              StatusIs(absl::StatusCode::kFailedPrecondition,
                       HasSubstr("CreateAssertionRequest")));
}

TEST_F(SgxIntelEcdsaQeRemoteAssertionVerifierTest,
       CreateAssertionRequestSuccess) {
  SgxIntelEcdsaQeRemoteAssertionVerifier verifier;
  ASYLO_ASSERT_OK(verifier.Initialize(valid_config_));

  AssertionRequest request;
  ASYLO_ASSERT_OK(verifier.CreateAssertionRequest(&request));

  const AssertionDescription &description = request.description();
  EXPECT_EQ(description.identity_type(), CODE_IDENTITY);
  EXPECT_EQ(description.authority_type(),
            sgx::kSgxIntelEcdsaQeRemoteAssertionAuthority);
}

TEST_F(SgxIntelEcdsaQeRemoteAssertionVerifierTest,
       CanVerifyFailsIfNotInitialized) {
  SgxIntelEcdsaQeRemoteAssertionVerifier verifier;

  AssertionOffer offer = ParseTextProtoOrDie(kValidAssertionDescriptionProto);
  EXPECT_THAT(
      verifier.CanVerify(offer),
      StatusIs(absl::StatusCode::kFailedPrecondition, HasSubstr("CanVerify")));
}

TEST_F(SgxIntelEcdsaQeRemoteAssertionVerifierTest,
       CanVerifyFailsIfIncompatibleAssertionIdentityType) {
  SgxIntelEcdsaQeRemoteAssertionVerifier verifier;
  ASYLO_ASSERT_OK(verifier.Initialize(valid_config_));

  AssertionOffer offer = ParseTextProtoOrDie(R"pb(
    description: {
      identity_type: CODE_IDENTITY
      authority_type: "bad authority"
    })pb");
  EXPECT_THAT(verifier.CanVerify(offer),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Assertion description does not match")));
}

TEST_F(SgxIntelEcdsaQeRemoteAssertionVerifierTest,
       CanVerifyFailsIfIncompatibleAssertionAuthorityType) {
  SgxIntelEcdsaQeRemoteAssertionVerifier verifier;
  ASYLO_ASSERT_OK(verifier.Initialize(valid_config_));

  AssertionOffer offer = ParseTextProtoOrDie(R"pb(
    description: {
      identity_type: CERT_IDENTITY
      authority_type: "SGX Intel ECDSA QE"
    })pb");
  EXPECT_THAT(verifier.CanVerify(offer),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Assertion description does not match")));
}

TEST_F(SgxIntelEcdsaQeRemoteAssertionVerifierTest, CanVerifySuccess) {
  SgxIntelEcdsaQeRemoteAssertionVerifier verifier;
  ASYLO_ASSERT_OK(verifier.Initialize(valid_config_));
  AssertionOffer offer = ParseTextProtoOrDie(kValidAssertionDescriptionProto);
  EXPECT_THAT(verifier.CanVerify(offer), IsOkAndHolds(IsTrue()));
}

TEST_F(SgxIntelEcdsaQeRemoteAssertionVerifierTest,
       VerifyFailsIfNotInitialized) {
  SgxIntelEcdsaQeRemoteAssertionVerifier verifier;

  Assertion assertion = ParseTextProtoOrDie(kValidAssertionDescriptionProto);
  EnclaveIdentity identity;
  EXPECT_THAT(
      verifier.Verify("user data", assertion, &identity),
      StatusIs(absl::StatusCode::kFailedPrecondition, HasSubstr("Verify")));
}

TEST_F(SgxIntelEcdsaQeRemoteAssertionVerifierTest,
       VerifyFailsIfIncompatibleAssertionDescription) {
  SgxIntelEcdsaQeRemoteAssertionVerifier verifier;
  ASYLO_ASSERT_OK(verifier.Initialize(valid_config_));

  Assertion assertion = ParseTextProtoOrDie(R"pb(
    description: {
      identity_type: CERT_IDENTITY
      authority_type: "SGX Intel ECDSA QE"
    })pb");
  EnclaveIdentity identity;
  EXPECT_THAT(verifier.Verify("user data", assertion, &identity),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Assertion description does not match")));
}

TEST_F(SgxIntelEcdsaQeRemoteAssertionVerifierTest,
       VerifyFailsIfUnparseableAssertion) {
  SgxIntelEcdsaQeRemoteAssertionVerifier verifier;
  ASYLO_ASSERT_OK(verifier.Initialize(valid_config_));

  Assertion assertion = ParseTextProtoOrDie(kValidAssertionDescriptionProto);
  assertion.set_assertion("can't parse this");
  EnclaveIdentity identity;
  EXPECT_THAT(verifier.Verify("user data", assertion, &identity),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(SgxIntelEcdsaQeRemoteAssertionVerifierTest,
       VerifyFailsIfAssertionIsNotBoundToUserData) {
  SgxIntelEcdsaQeRemoteAssertionVerifier verifier;
  ASYLO_ASSERT_OK(verifier.Initialize(valid_config_));

  Assertion assertion = CreateAssertion(GenerateValidQuote("user data"));
  EnclaveIdentity identity;
  EXPECT_THAT(verifier.Verify("not the user data", assertion, &identity),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("quote data does not match")));
}

TEST_F(SgxIntelEcdsaQeRemoteAssertionVerifierTest,
       VerifyFailsWithIncorrectAadGenerator) {
  auto wrong_generator =
      AdditionalAuthenticatedDataGenerator::CreateGetPceInfoAadGenerator();
  SgxIntelEcdsaQeRemoteAssertionVerifier verifier(std::move(wrong_generator));
  ASYLO_ASSERT_OK(verifier.Initialize(valid_config_));

  Assertion assertion =
      CreateAssertion(GenerateValidQuote("data to be quoted"));
  EnclaveIdentity identity;
  EXPECT_THAT(verifier.Verify("data to be quoted", assertion, &identity),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("quote data does not match")));
}

TEST_F(SgxIntelEcdsaQeRemoteAssertionVerifierTest,
       VerifyFailsWithIncorrectQuoteVersion) {
  SgxIntelEcdsaQeRemoteAssertionVerifier verifier;
  ASYLO_ASSERT_OK(verifier.Initialize(valid_config_));

  sgx::IntelQeQuote quote = GenerateValidQuote("user data");
  quote.header.version ^= 1;

  Assertion assertion = CreateAssertion(quote);
  EnclaveIdentity identity;
  EXPECT_THAT(
      verifier.Verify("user data", assertion, &identity),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("version")));
}

TEST_F(SgxIntelEcdsaQeRemoteAssertionVerifierTest,
       VerifyFailsWithIncorrectQuoteAlgorithm) {
  SgxIntelEcdsaQeRemoteAssertionVerifier verifier;
  ASYLO_ASSERT_OK(verifier.Initialize(valid_config_));

  sgx::IntelQeQuote quote = GenerateValidQuote("user data");
  quote.header.algorithm ^= 1;

  Assertion assertion = CreateAssertion(quote);
  EnclaveIdentity identity;
  EXPECT_THAT(
      verifier.Verify("user data", assertion, &identity),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("algorithm")));
}

TEST_F(SgxIntelEcdsaQeRemoteAssertionVerifierTest,
       VerifyFailsWithIncorrectVendorId) {
  SgxIntelEcdsaQeRemoteAssertionVerifier verifier;
  ASYLO_ASSERT_OK(verifier.Initialize(valid_config_));

  sgx::IntelQeQuote quote = GenerateValidQuote("user data");
  quote.header.qe_vendor_id[0] ^= 1;

  Assertion assertion = CreateAssertion(quote);
  EnclaveIdentity identity;
  EXPECT_THAT(
      verifier.Verify("user data", assertion, &identity),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("vendor ID")));
}

TEST_F(SgxIntelEcdsaQeRemoteAssertionVerifierTest,
       VerifyFailsWithBadKeyQuoteSigningKey) {
  SgxIntelEcdsaQeRemoteAssertionVerifier verifier;
  ASYLO_ASSERT_OK(verifier.Initialize(valid_config_));

  sgx::IntelQeQuote quote = GenerateValidQuote("user data");
  quote.signature.public_key =
      "\xff\xff\xff\xff\xff\xff\xff\xff"
      "\xff\xff\xff\xff\xff\xff\xff\xff"
      "\xff\xff\xff\xff\xff\xff\xff\xff"
      "\xff\xff\xff\xff\xff\xff\xff\xff";

  Assertion assertion = CreateAssertion(quote);
  EnclaveIdentity identity;
  EXPECT_THAT(verifier.Verify("user data", assertion, &identity),
              StatusIs(absl::StatusCode::kInternal,
                       HasSubstr("elliptic curve routines")));
}

TEST_F(SgxIntelEcdsaQeRemoteAssertionVerifierTest,
       VerifyFailsWithQuoteSignatureMismatch) {
  SgxIntelEcdsaQeRemoteAssertionVerifier verifier;
  ASYLO_ASSERT_OK(verifier.Initialize(valid_config_));

  sgx::IntelQeQuote quote = GenerateValidQuote("user data");
  quote.signature.body_signature[0] ^= 0xff;

  Assertion assertion = CreateAssertion(quote);
  EnclaveIdentity identity;
  EXPECT_THAT(
      verifier.Verify("user data", assertion, &identity),
      StatusIs(absl::StatusCode::kInternal, HasSubstr("BAD_SIGNATURE")));
}

TEST_F(SgxIntelEcdsaQeRemoteAssertionVerifierTest,
       VerifyFailsWithQeReportSignatureMismatch) {
  SgxIntelEcdsaQeRemoteAssertionVerifier verifier;
  ASYLO_ASSERT_OK(verifier.Initialize(valid_config_));

  sgx::IntelQeQuote quote = GenerateValidQuote("user data");
  quote.signature.qe_report_signature[0] ^= 0xff;

  Assertion assertion = CreateAssertion(quote);
  EnclaveIdentity identity;
  EXPECT_THAT(
      verifier.Verify("user data", assertion, &identity),
      StatusIs(absl::StatusCode::kInternal, HasSubstr("BAD_SIGNATURE")));
}

TEST_F(SgxIntelEcdsaQeRemoteAssertionVerifierTest,
       VerifyFailsWithInvalidPckCertChain) {
  SgxIntelEcdsaQeRemoteAssertionVerifier verifier;
  ASYLO_ASSERT_OK(verifier.Initialize(valid_config_));

  sgx::IntelQeQuote quote = GenerateValidQuote("user data");
  // Remove the root certificate to invalidate the cert chain.
  quote.cert_data.qe_cert_data = CreateCertData({
      sgx::kFakeSgxPck.certificate_pem,
      sgx::kFakeSgxProcessorCa.certificate_pem,
  });

  Assertion assertion = CreateAssertion(quote);
  EnclaveIdentity identity;
  EXPECT_THAT(
      verifier.Verify("user data", assertion, &identity),
      StatusIs(absl::StatusCode::kInternal, HasSubstr("BAD_SIGNATURE")));
}

TEST_F(SgxIntelEcdsaQeRemoteAssertionVerifierTest,
       VerifyFailsWithUnrecognizedRootCertificate) {
  SgxIntelEcdsaQeRemoteAssertionVerifier verifier;

  // Use a config that specifies a different trusted root certificate.
  valid_config_proto_.mutable_verifier_info()
      ->mutable_root_certificates()
      ->Clear();
  Certificate *cert =
      valid_config_proto_.mutable_verifier_info()->add_root_certificates();
  cert->set_format(Certificate::X509_PEM);
  cert->set_data({sgx::kFakeSgxPlatformCa.certificate_pem.begin(),
                  sgx::kFakeSgxPlatformCa.certificate_pem.end()});

  std::string config;
  ASSERT_TRUE(valid_config_proto_.SerializeToString(&config));
  ASYLO_ASSERT_OK(verifier.Initialize(config));

  sgx::IntelQeQuote quote = GenerateValidQuote("user data");

  Assertion assertion = CreateAssertion(quote);
  EnclaveIdentity identity;
  EXPECT_THAT(verifier.Verify("user data", assertion, &identity),
              StatusIs(absl::StatusCode::kUnauthenticated,
                       HasSubstr("Unrecognized root certificate")));
}

TEST_F(SgxIntelEcdsaQeRemoteAssertionVerifierTest,
       VerifyFailsWithQeIdentityExpectationMismatch) {
  SgxIntelEcdsaQeRemoteAssertionVerifier verifier;
  ASYLO_ASSERT_OK(verifier.Initialize(valid_config_));

  // Create a quote using a random QE identity, which should not match the
  // default QE identity expectation in the authority config.
  sgx::ReportBody qe_identity = TrivialRandomObject<sgx::ReportBody>();
  sgx::IntelQeQuote quote = GenerateValidQuote("user data", qe_identity);
  Assertion assertion = CreateAssertion(quote);
  EnclaveIdentity identity;
  EXPECT_THAT(verifier.Verify("user data", assertion, &identity),
              StatusIs(absl::StatusCode::kUnauthenticated));
}

TEST_F(SgxIntelEcdsaQeRemoteAssertionVerifierTest, VerifySuccess) {
  SgxIntelEcdsaQeRemoteAssertionVerifier verifier;
  ASYLO_ASSERT_OK(verifier.Initialize(valid_config_));

  sgx::IntelQeQuote quote = GenerateValidQuote("important data");

  Assertion assertion = CreateAssertion(quote);
  EnclaveIdentity identity;
  ASYLO_ASSERT_OK(verifier.Verify("important data", assertion, &identity));

  SgxIdentity peer_identity;
  ASYLO_ASSERT_OK_AND_ASSIGN(peer_identity, ParseSgxIdentity(identity));

  sgx::MachineConfiguration fake_pck_machine_config =
      ParseTextProtoOrDie(sgx::kFakePckMachineConfigurationTextProto);
  EXPECT_THAT(peer_identity.machine_configuration(),
              EqualsProto(fake_pck_machine_config));

  sgx::SecsAttributeSet peer_attributes(
      peer_identity.code_identity().attributes());
  EXPECT_EQ(peer_attributes, quote.body.attributes);
  EXPECT_EQ(peer_identity.code_identity().miscselect(), quote.body.miscselect);

  EXPECT_EQ(quote.body.mrenclave.size(),
            peer_identity.code_identity().mrenclave().hash().size());
  EXPECT_THAT(peer_identity.code_identity().mrenclave().hash().data(),
              MemEq(quote.body.mrenclave.data(), quote.body.mrenclave.size()));

  EXPECT_EQ(quote.body.mrsigner.size(), peer_identity.code_identity()
                                            .signer_assigned_identity()
                                            .mrsigner()
                                            .hash()
                                            .size());
  EXPECT_THAT(peer_identity.code_identity()
                  .signer_assigned_identity()
                  .mrsigner()
                  .hash()
                  .data(),
              MemEq(quote.body.mrsigner.data(), quote.body.mrsigner.size()));

  EXPECT_EQ(
      peer_identity.code_identity().signer_assigned_identity().isvprodid(),
      quote.body.isvprodid);
  EXPECT_EQ(peer_identity.code_identity().signer_assigned_identity().isvsvn(),
            quote.body.isvsvn);
}

}  // namespace
}  // namespace asylo
