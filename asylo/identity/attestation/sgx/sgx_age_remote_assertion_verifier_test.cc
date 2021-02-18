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
#include "asylo/identity/attestation/sgx/sgx_age_remote_assertion_verifier.h"

#include <memory>
#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "asylo/crypto/certificate.pb.h"
#include "asylo/crypto/ecdsa_p256_sha256_signing_key.h"
#include "asylo/identity/attestation/sgx/internal/intel_certs/intel_sgx_root_ca_cert.h"
#include "asylo/identity/attestation/sgx/internal/remote_assertion.pb.h"
#include "asylo/identity/attestation/sgx/internal/remote_assertion_util.h"
#include "asylo/identity/attestation/sgx/sgx_age_remote_assertion_authority_config.pb.h"
#include "asylo/identity/descriptions.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/identity/platform/sgx/internal/code_identity_constants.h"
#include "asylo/identity/platform/sgx/machine_configuration.pb.h"
#include "asylo/identity/platform/sgx/sgx_identity.pb.h"
#include "asylo/identity/platform/sgx/sgx_identity_util.h"
#include "asylo/identity/provisioning/sgx/internal/fake_sgx_pki.h"
#include "asylo/test/util/proto_matchers.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/proto_parse_util.h"
#include "asylo/util/status_macros.h"

namespace asylo {
namespace {

constexpr char kUserData[] = "User data";

constexpr char kAttestationKeyCertificateDerHex[] =
    "0ab3030ab0034820f3376ae6b2f2034d3b7a4b48a778000000000000000000000000000000"
    "00000000000000000000000000000000000700000000000000e70000000000000049c80749"
    "3583e5fb0d8d7c80f21e7c89ccbbf2820e75f94b7ef0cd37623d46a4000000000000000000"
    "000000000000000000000000000000000000000000000083d719e77deaca1470f6baf62a4d"
    "774303c899db69020f9c70ee1dfc08c7ce9e00000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000be7a8807a1ba8e"
    "785f17997bd29611637f7e8f12d4aec6c5696476f1c9ba52b8000000000000000000000000"
    "000000004153594c4f205349474e5245504f5254ff00ff00ff00ff00ff00ff00ff00ff0000"
    "000000000000000000000000000000cd49f8f05e1c228bf1d68d579549600e12dd010ac401"
    "0a63080210011802225b3059301306072a8648ce3d020106082a8648ce3d03010703420004"
    "bdb8ab220c1cb0089519cdf2818a91c6ccd957fcb0d528216139bf62e6a9272170e5b7a2e2"
    "faba7a8debad920c7c0a099e18ba4781cd389dec2489be981b20f11230417373657274696f"
    "6e2047656e657261746f7220456e636c617665204174746573746174696f6e204b65792076"
    "302e311a2b417373657274696f6e2047656e657261746f7220456e636c6176652041747465"
    "73746174696f6e204b65791214504345205369676e205265706f72742076302e311a480801"
    "12440a204f316d3250975af904ea23e1a8d86d4c4a034e69401650fc7e0324837036e00812"
    "20801b34199dc0a14397a0c830667677bd63f1ac0c3da73216ed4c4fe94df354ce";

constexpr char kAttestationKeyCertificateIdentity[] = R"pb(
  code_identity {
    mrenclave {
      hash: "I\310\007I5\203\345\373\r\215|\200\362\036|\211\314\273\362\202\016u\371K~\360\3157b=F\244"
    }
    signer_assigned_identity {
      mrsigner {
        hash: "\203\327\031\347}\352\312\024p\366\272\366*MwC\003\310\231\333i\002\017\234p\356\035\374\010\307\316\236"
      }
      isvprodid: 0
      isvsvn: 0
    }
    miscselect: 0
    attributes { flags: 7 xfrm: 231 }
  }
  machine_configuration {
    cpu_svn { value: "A fake TCB level" }
    sgx_type: STANDARD
  }
)pb";

constexpr char kAdditionalRootCertPem[] = R"pem(
-----BEGIN CERTIFICATE-----
MIICCzCCAbGgAwIBAgIUF/94/Naw8+Gb8bjA+ya6Zg9YHKswCgYIKoZIzj0EAwIw
cjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCldhc2hpbmd0b24xETAPBgNVBAcMCEtp
cmtsYW5kMQ8wDQYDVQQKDAZHb29nbGUxDjAMBgNVBAsMBUFzeWxvMRowGAYDVQQD
DBFUZXN0IFJlYWwgUm9vdCBDQTAgFw0xOTA3MzAyMjU4MTFaGA8yMjkzMDUxNDIy
NTgxMVowcjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCldhc2hpbmd0b24xETAPBgNV
BAcMCEtpcmtsYW5kMQ8wDQYDVQQKDAZHb29nbGUxDjAMBgNVBAsMBUFzeWxvMRow
GAYDVQQDDBFUZXN0IFJlYWwgUm9vdCBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEH
A0IABOrtpRA+iRlPQ7/g2ETz558ACVf8PJI3x+qN3NZ+Isdc11EZ6pqgL3bOysu/
Gy/mHGn8nuraH+KaVn1s60aOFr2jIzAhMBIGA1UdEwEB/wQIMAYBAf8CAQEwCwYD
VR0PBAQDAgIEMAoGCCqGSM49BAMCA0gAMEUCIA/rSJ6o/oIRuTk1MV0XjlZGF7+N
HQAOOAfPvg/KSecOAiEAx1o+05huNjGLOMl37Ee0Sy1elzyo12WgcVQVbTY47z4=
-----END CERTIFICATE-----
)pem";

// The key asserted by |kAttestationKeyCertificateDerHex|.
constexpr char kAttestationSigningKeyPem[] = R"pem(
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIAFhNjtm+5QpSgIaAym1XzkMD6SzfJJRiYz2DNQI84G4oAoGCCqGSM49
AwEHoUQDQgAEvbirIgwcsAiVGc3ygYqRxszZV/yw1SghYTm/YuapJyFw5bei4vq6
eo3rrZIMfAoJnhi6R4HNOJ3sJIm+mBsg8Q==
-----END EC PRIVATE KEY-----
)pem";

// The expected peer identity.
constexpr char kPeerIdentity[] = R"pb(
  code_identity {
    mrenclave {
      hash: "\x9e\x34\x6c\x23\x51\x63\x79\x20\x9c\x7d\x5f\x00\x05\xbd\xa5\xb1\x95\x28\xda\xba\x7a\x6e\x84\x5e\x18\xf4\xf4\xc8\xc7\xb1\x88\x54"
    }
    signer_assigned_identity {
      mrsigner {
        hash: "\xed\x9a\xfc\x4f\xc9\xa4\x75\x50\x4a\x47\x43\x9f\xbe\x6c\x63\x0a\xba\x24\x1a\xa0\xef\xb5\x6c\xf6\xce\x68\x36\xf7\x6b\x24\x18\x94"
      }
      isvprodid: 55832
      isvsvn: 35707
    }
    miscselect: 1
    attributes { flags: 21 xfrm: 647 }
  }
  machine_configuration {
    cpu_svn { value: "A fake TCB level" }
    sgx_type: STANDARD
  }
)pb";

Certificate GetFakeIntelRoot() {
  Certificate fake_intel_root;
  fake_intel_root.set_format(Certificate::X509_PEM);
  fake_intel_root.set_data(sgx::kFakeSgxRootCa.certificate_pem.data(),
                           sgx::kFakeSgxRootCa.certificate_pem.size());
  return fake_intel_root;
}

Certificate GetAdditionalRoot() {
  Certificate additional_root;
  additional_root.set_format(Certificate::X509_PEM);
  additional_root.set_data(kAdditionalRootCertPem);
  return additional_root;
}

StatusOr<SgxAgeRemoteAssertionAuthorityConfig> CreateValidConfig(
    bool include_additional_root = true) {
  SgxAgeRemoteAssertionAuthorityConfig config;

  *config.mutable_intel_root_certificate() = GetFakeIntelRoot();

  SgxIdentity age_identity =
      ParseTextProtoOrDie(kAttestationKeyCertificateIdentity);

  SgxIdentityExpectation age_sgx_expectation;
  ASYLO_ASSIGN_OR_RETURN(
      age_sgx_expectation,
      CreateSgxIdentityExpectation(age_identity,
                                   SgxIdentityMatchSpecOptions::DEFAULT));

  ASYLO_ASSIGN_OR_RETURN(
      *config.mutable_age_identity_expectation()->mutable_expectation(),
      SerializeSgxIdentityExpectation(age_sgx_expectation));

  if (include_additional_root) {
    *config.add_root_ca_certificates() = GetAdditionalRoot();
  }

  return config;
}

AssertionOffer CreateValidOffer() {
  sgx::RemoteAssertionOfferAdditionalInfo additional_info;
  *additional_info.add_root_ca_certificates() = GetFakeIntelRoot();
  *additional_info.add_root_ca_certificates() = GetAdditionalRoot();
  AssertionOffer offer;
  SetSgxAgeRemoteAssertionDescription(offer.mutable_description());
  offer.set_additional_information(additional_info.SerializeAsString());
  return offer;
}

StatusOr<Assertion> CreateValidAssertion() {
  sgx::RemoteAssertion remote_assertion;

  SgxIdentity peer_identity = ParseTextProtoOrDie(kPeerIdentity);

  std::unique_ptr<SigningKey> attestation_key;
  ASYLO_ASSIGN_OR_RETURN(
      attestation_key,
      EcdsaP256Sha256SigningKey::CreateFromPem(kAttestationSigningKeyPem));

  CertificateChain sgx_certificate_chain;
  Certificate *ak_cert = sgx_certificate_chain.add_certificates();
  ak_cert->set_format(Certificate::SGX_ATTESTATION_KEY_CERTIFICATE);
  ak_cert->set_data(absl::HexStringToBytes(kAttestationKeyCertificateDerHex));
  sgx::AppendFakePckCertificateChain(&sgx_certificate_chain);

  ASYLO_RETURN_IF_ERROR(
      sgx::MakeRemoteAssertion(kUserData, peer_identity, *attestation_key,
                               {sgx_certificate_chain}, &remote_assertion));

  Assertion assertion;
  SetSgxAgeRemoteAssertionDescription(assertion.mutable_description());
  if (!remote_assertion.SerializeToString(assertion.mutable_assertion())) {
    return Status(absl::StatusCode::kInternal,
                  "Could not serialize remote assertion to string");
  }
  return assertion;
}

TEST(SgxAgeRemoteAssertionVerifierTest, VerifierFoundInStaticMap) {
  std::string authority_id;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      authority_id, EnclaveAssertionAuthority::GenerateAuthorityId(
                        CODE_IDENTITY, sgx::kSgxAgeRemoteAssertionAuthority));

  EXPECT_NE(AssertionVerifierMap::GetValue(authority_id),
            AssertionVerifierMap::value_end());
}

TEST(SgxAgeRemoteAssertionVerifierTest, InitializeFailsWithBadConfig) {
  SgxAgeRemoteAssertionVerifier verifier;
  EXPECT_THAT(verifier.Initialize("Google makes good falafels"),
              StatusIs(absl::StatusCode::kInternal));
}

TEST(SgxAgeRemoteAssertionVerifierTest, InitializeFailsWithBadCerts) {
  SgxAgeRemoteAssertionAuthorityConfig config;
  ASYLO_ASSERT_OK_AND_ASSIGN(config, CreateValidConfig());
  SgxAgeRemoteAssertionVerifier verifier;

  // Test with bad Intel cert.
  config.mutable_intel_root_certificate()->set_data("Beet yogurt is nice");
  EXPECT_THAT(verifier.Initialize(config.SerializeAsString()),
              StatusIs(absl::StatusCode::kInternal));

  // Test with bad additional cert.
  *config.mutable_intel_root_certificate() = GetFakeIntelRoot();
  config.mutable_root_ca_certificates(0)->set_data("Lemon yogurt too");
  EXPECT_THAT(verifier.Initialize(config.SerializeAsString()),
              StatusIs(absl::StatusCode::kInternal));
}

TEST(SgxAgeRemoteAssertionVerifierTest, InitializeFailsWithoutIntelCert) {
  SgxAgeRemoteAssertionAuthorityConfig config;
  ASYLO_ASSERT_OK_AND_ASSIGN(config, CreateValidConfig());
  config.clear_intel_root_certificate();

  SgxAgeRemoteAssertionVerifier verifier;
  EXPECT_THAT(verifier.Initialize(config.SerializeAsString()),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(SgxAgeRemoteAssertionVerifierTest,
     InitializeFailsWithoutAgeIdentityExpectation) {
  SgxAgeRemoteAssertionAuthorityConfig config;
  ASYLO_ASSERT_OK_AND_ASSIGN(config, CreateValidConfig());
  config.clear_age_identity_expectation();

  SgxAgeRemoteAssertionVerifier verifier;
  EXPECT_THAT(verifier.Initialize(config.SerializeAsString()),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(SgxAgeRemoteAssertionVerifierTest, InitializesSucceedsAtMostOnce) {
  SgxAgeRemoteAssertionAuthorityConfig config;
  ASYLO_ASSERT_OK_AND_ASSIGN(config, CreateValidConfig());
  SgxAgeRemoteAssertionVerifier verifier;
  ASYLO_ASSERT_OK(verifier.Initialize(config.SerializeAsString()));

  EXPECT_THAT(verifier.Initialize(config.SerializeAsString()),
              StatusIs(absl::StatusCode::kFailedPrecondition));
}

TEST(SgxAgeRemoteAssertionVerifierTest, InitializeSuccess) {
  SgxAgeRemoteAssertionAuthorityConfig config;
  ASYLO_ASSERT_OK_AND_ASSIGN(config, CreateValidConfig());
  SgxAgeRemoteAssertionVerifier verifier;
  ASYLO_EXPECT_OK(verifier.Initialize(config.SerializeAsString()));
}

TEST(SgxAgeRemoteAssertionVerifierTest, IdentityType) {
  SgxAgeRemoteAssertionVerifier verifier;
  EXPECT_EQ(verifier.IdentityType(), CODE_IDENTITY);
}

TEST(SgxAgeRemoteAssertionVerifierTest, AuthorityType) {
  SgxAgeRemoteAssertionVerifier verifier;
  EXPECT_EQ(verifier.AuthorityType(), sgx::kSgxAgeRemoteAssertionAuthority);
}

TEST(SgxAgeRemoteAssertionVerifierTest, CreateAssertionRequestUninitialized) {
  SgxAgeRemoteAssertionVerifier verifier;
  AssertionRequest request;
  EXPECT_THAT(verifier.CreateAssertionRequest(&request),
              StatusIs(absl::StatusCode::kFailedPrecondition));
}

TEST(SgxAgeRemoteAssertionVerifierTest, CreateAssertionRequestSuccess) {
  SgxAgeRemoteAssertionAuthorityConfig config;
  ASYLO_ASSERT_OK_AND_ASSIGN(config, CreateValidConfig());
  SgxAgeRemoteAssertionVerifier verifier;
  ASYLO_ASSERT_OK(verifier.Initialize(config.SerializeAsString()));

  AssertionDescription sgx_age_remote_description;
  SetSgxAgeRemoteAssertionDescription(&sgx_age_remote_description);

  AssertionRequest request;
  ASYLO_ASSERT_OK(verifier.CreateAssertionRequest(&request));
  EXPECT_THAT(request.description(), EqualsProto(sgx_age_remote_description));

  sgx::RemoteAssertionRequestAdditionalInfo additional_request_info;
  ASSERT_TRUE(additional_request_info.ParseFromString(
      request.additional_information()));
  EXPECT_THAT(additional_request_info.root_ca_certificates(),
              testing::UnorderedElementsAre(EqualsProto(GetFakeIntelRoot()),
                                            EqualsProto(GetAdditionalRoot())));
}

TEST(SgxAgeRemoteAssertionVerifierTest, CanVerifyUninitialized) {
  SgxAgeRemoteAssertionVerifier verifier;
  AssertionOffer offer = CreateValidOffer();
  EXPECT_THAT(verifier.CanVerify(offer),
              StatusIs(absl::StatusCode::kFailedPrecondition));
}

TEST(SgxAgeRemoteAssertionVerifierTest, CanVerifyIncompatibleRootCaSets) {
  SgxAgeRemoteAssertionVerifier verifier;
  SgxAgeRemoteAssertionAuthorityConfig config;
  ASYLO_ASSERT_OK_AND_ASSIGN(config, CreateValidConfig());

  // Modify the config to include a root certificate not provided by the
  // generator.
  Certificate *unsupported_cert = config.add_root_ca_certificates();
  unsupported_cert->set_format(Certificate::X509_PEM);
  unsupported_cert->set_data(kIntelSgxRootCaCertificate);

  ASYLO_ASSERT_OK(verifier.Initialize(config.SerializeAsString()));

  AssertionOffer offer = CreateValidOffer();
  EXPECT_THAT(verifier.CanVerify(offer), IsOkAndHolds(false));
}

TEST(SgxAgeRemoteAssertionVerifierTest,
     CanVerifyIncompatibleAssertionDescription) {
  SgxAgeRemoteAssertionVerifier verifier;
  SgxAgeRemoteAssertionAuthorityConfig config;
  ASYLO_ASSERT_OK_AND_ASSIGN(config, CreateValidConfig());
  ASYLO_ASSERT_OK(verifier.Initialize(config.SerializeAsString()));

  AssertionOffer offer = CreateValidOffer();
  SetSgxLocalAssertionDescription(offer.mutable_description());
  EXPECT_THAT(verifier.CanVerify(offer),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(SgxAgeRemoteAssertionVerifierTest, CanVerifySuccess) {
  SgxAgeRemoteAssertionVerifier verifier;
  SgxAgeRemoteAssertionAuthorityConfig config;
  ASYLO_ASSERT_OK_AND_ASSIGN(config, CreateValidConfig());
  ASYLO_ASSERT_OK(verifier.Initialize(config.SerializeAsString()));

  AssertionOffer offer = CreateValidOffer();
  ASYLO_EXPECT_OK(verifier.CanVerify(offer));
}

TEST(SgxAgeRemoteAssertionVerifierTest, VerifyUninitialized) {
  SgxAgeRemoteAssertionVerifier verifier;
  Assertion assertion;
  ASYLO_ASSERT_OK_AND_ASSIGN(assertion, CreateValidAssertion());
  EnclaveIdentity peer_identity;
  EXPECT_THAT(verifier.Verify(kUserData, assertion, &peer_identity),
              StatusIs(absl::StatusCode::kFailedPrecondition));
}

TEST(SgxAgeRemoteAssertionVerifierTest,
     VerifyIncompatibleAssertionDescription) {
  SgxAgeRemoteAssertionVerifier verifier;
  SgxAgeRemoteAssertionAuthorityConfig config;
  ASYLO_ASSERT_OK_AND_ASSIGN(config, CreateValidConfig());
  ASYLO_ASSERT_OK(verifier.Initialize(config.SerializeAsString()));

  Assertion assertion;
  ASYLO_ASSERT_OK_AND_ASSIGN(assertion, CreateValidAssertion());
  SetSgxLocalAssertionDescription(assertion.mutable_description());
  EnclaveIdentity peer_identity;
  EXPECT_THAT(verifier.Verify(kUserData, assertion, &peer_identity),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(SgxAgeRemoteAssertionVerifierTest, VerifyInvalidAssertion) {
  SgxAgeRemoteAssertionVerifier verifier;
  SgxAgeRemoteAssertionAuthorityConfig config;
  ASYLO_ASSERT_OK_AND_ASSIGN(config, CreateValidConfig());
  ASYLO_ASSERT_OK(verifier.Initialize(config.SerializeAsString()));

  Assertion assertion;
  ASYLO_ASSERT_OK_AND_ASSIGN(assertion, CreateValidAssertion());
  EnclaveIdentity peer_identity;
  EXPECT_THAT(verifier.Verify("Not the user data", assertion, &peer_identity),
              Not(IsOk()));
}

TEST(SgxAgeRemoteAssertionVerifierTest, VerifySuccess) {
  SgxAgeRemoteAssertionVerifier verifier;
  SgxAgeRemoteAssertionAuthorityConfig config;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      config, CreateValidConfig(/*include_additional_root=*/false));
  ASYLO_ASSERT_OK(verifier.Initialize(config.SerializeAsString()));

  SgxIdentity expected_peer_sgx_identity = ParseTextProtoOrDie(kPeerIdentity);
  EnclaveIdentity expected_peer_identity;
  ASYLO_ASSERT_OK_AND_ASSIGN(expected_peer_identity,
                             SerializeSgxIdentity(expected_peer_sgx_identity));

  Assertion assertion;
  ASYLO_ASSERT_OK_AND_ASSIGN(assertion, CreateValidAssertion());
  EnclaveIdentity peer_identity;
  ASYLO_ASSERT_OK(verifier.Verify(kUserData, assertion, &peer_identity));
  EXPECT_THAT(peer_identity, EqualsProto(expected_peer_identity));
}

}  // namespace
}  // namespace asylo
