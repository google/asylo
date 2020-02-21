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
#include "absl/strings/escaping.h"
#include "asylo/crypto/certificate.pb.h"
#include "asylo/crypto/ecdsa_p256_sha256_signing_key.h"
#include "asylo/identity/attestation/sgx/internal/remote_assertion.pb.h"
#include "asylo/identity/attestation/sgx/internal/remote_assertion_generator_enclave_test_util.h"
#include "asylo/identity/attestation/sgx/internal/remote_assertion_util.h"
#include "asylo/identity/attestation/sgx/sgx_age_remote_assertion_authority_config.pb.h"
#include "asylo/identity/descriptions.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/identity/platform/sgx/sgx_identity.pb.h"
#include "asylo/identity/provisioning/sgx/internal/fake_sgx_pki.h"
#include "asylo/identity/sgx/code_identity_constants.h"
#include "asylo/identity/sgx/intel_certs/intel_sgx_root_ca_cert.h"
#include "asylo/identity/sgx/sgx_identity_util.h"
#include "asylo/test/util/proto_matchers.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/proto_parse_util.h"
#include "asylo/util/status_macros.h"

namespace asylo {
namespace {

constexpr char kUserData[] = "User data";

constexpr char kAttestationKeyCertificateDerHex[] =
    "0ab3030ab00300000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000003300000000000000a300000000000000fc472767"
    "9b21934dcae43b77ec9fcaeb2523be349af57890e85aa68eae058574000000000000000000"
    "0000000000000000000000000000000000000000000000fead2be7f1a24f725ee7e596873b"
    "260f435ebbf14df5bbe8d99c0fa5bc3abeaf00000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000074efd1e4000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000f1bace90cd72b0"
    "a8f874ea4264500b109142a284479e826ff74a6ae1659d159b000000000000000000000000"
    "000000004153594c4f205349474e5245504f52540000000000000000000000000000000000"
    "000000000000000000000000000000f5ee16c9593502a362aeba59a1d9ae1e12b6020a9d02"
    "0abb0108021001180122b2012d2d2d2d2d424547494e205055424c4943204b45592d2d2d2d"
    "2d0a4d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a304441516344516741"
    "453669416d6646584954635934426d583166396a5561733469343144450a643461754a486c"
    "645337564c41676973354941753438724377776c5565474842644d746747444d53435a5051"
    "677446384b5a4957392f317133773d3d0a2d2d2d2d2d454e44205055424c4943204b45592d"
    "2d2d2d2d0a1230417373657274696f6e2047656e657261746f7220456e636c617665204174"
    "746573746174696f6e204b65792076302e311a2b417373657274696f6e2047656e65726174"
    "6f7220456e636c617665204174746573746174696f6e204b65791214504345205369676e20"
    "5265706f72742076302e311a48080112440a203856d715177f8527a2f37b3ba42c98f1e69d"
    "9e6630a39b0406d81b63f8faa5db12203e81f00dc10d5480437c3f78ea21ea8f9c13168be6"
    "db18d5c248b0350eb473e1";

// The identity for |kAttestationKeyCertificateDerHex|.
constexpr char kAttestationKeyCertificateIdentity[] = R"pb(
  code_identity {
    mrenclave {
      hash: "\xfc\x47\x27\x67\x9b\x21\x93\x4d\xca\xe4\x3b\x77\xec\x9f\xca\xeb\x25\x23\xbe\x34\x9a\xf5\x78\x90\xe8\x5a\xa6\x8e\xae\x05\x85\x74"
    }
    signer_assigned_identity {
      mrsigner {
        hash: "\xfe\xad\x2b\xe7\xf1\xa2\x4f\x72\x5e\xe7\xe5\x96\x87\x3b\x26\x0f\x43\x5e\xbb\xf1\x4d\xf5\xbb\xe8\xd9\x9c\x0f\xa5\xbc\x3a\xbe\xaf"
      }
      isvprodid: 61300
      isvsvn: 58577
    }
    miscselect: 0
    attributes { flags: 51 xfrm: 163 }
  }
  machine_configuration {
    cpu_svn {
      value: "\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000"
    }
  }
)pb";

constexpr char kAdditionalRootCertPem[] = R"(
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
)";

constexpr char kAdditionalUserCertPem[] = R"(
-----BEGIN CERTIFICATE-----
MIIBsTCCAVgCFEqP7cn0EO/6JfCCduo57IyKPwDPMAoGCCqGSM49BAMCMHIxCzAJ
BgNVBAYTAlVTMRMwEQYDVQQIDApXYXNoaW5ndG9uMREwDwYDVQQHDAhLaXJrbGFu
ZDEPMA0GA1UECgwGR29vZ2xlMQ4wDAYDVQQLDAVBc3lsbzEaMBgGA1UEAwwRVGVz
dCBSZWFsIFJvb3QgQ0EwHhcNMjAwMjA2MjA1NjAzWhcNMjAwMzA3MjA1NjAzWjBF
MQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGluZ3RvbjERMA8GA1UEBwwIS2ly
a2xhbmQxDjAMBgNVBAoMBUFzeWxvMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
6iAmfFXITcY4BmX1f9jUas4i41DEd4auJHldS7VLAgis5IAu48rCwwlUeGHBdMtg
GDMSCZPQgtF8KZIW9/1q3zAKBggqhkjOPQQDAgNHADBEAiABLsDucezCfoAUceC9
bJvA715j/gAv0EnjX1xuSaIlAwIgcaJtKBHsHG2p8rFcB/olOAI3CV/luRGHOTkI
3DwEqSU=
-----END CERTIFICATE-----
)";

// The key asserted by |kAttestationKeyCertificateDerHex|.
constexpr char kAttestationSigningKeyDerHex[] =
    "30770201010420a2e1e43f82f267f006806f2ae9b2a662c98f20d7c75ebcc14df2f6cbf60b"
    "e7b4a00a06082a8648ce3d030107a14403420004ea20267c55c84dc6380665f57fd8d46ace"
    "22e350c47786ae24795d4bb54b0208ace4802ee3cac2c309547861c174cb601833120993d0"
    "82d17c299216f7fd6adf";

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

StatusOr<SgxAgeRemoteAssertionAuthorityConfig> CreateValidConfig() {
  SgxAgeRemoteAssertionAuthorityConfig config;

  *config.mutable_intel_root_certificate() = GetFakeIntelRoot();

  SgxIdentity age_identity =
      ParseTextProtoOrDie(kAttestationKeyCertificateIdentity);

  SgxIdentityExpectation age_sgx_expectation;
  ASYLO_ASSIGN_OR_RETURN(
      age_sgx_expectation,
      CreateSgxIdentityExpectation(age_identity,
                                   SgxIdentityMatchSpecOptions::STRICT_LOCAL));

  ASYLO_ASSIGN_OR_RETURN(
      *config.mutable_age_identity_expectation()->mutable_expectation(),
      SerializeSgxIdentityExpectation(age_sgx_expectation));

  *config.add_root_ca_certificates() = GetAdditionalRoot();

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
      EcdsaP256Sha256SigningKey::CreateFromDer(
          absl::HexStringToBytes(kAttestationSigningKeyDerHex)));

  CertificateChain sgx_certificate_chain;
  Certificate *ak_cert = sgx_certificate_chain.add_certificates();
  ak_cert->set_format(Certificate::SGX_ATTESTATION_KEY_CERTIFICATE);
  ak_cert->set_data(absl::HexStringToBytes(kAttestationKeyCertificateDerHex));
  sgx::AppendFakePckCertificateChain(&sgx_certificate_chain);

  CertificateChain additional_certificate_chain;
  Certificate *additional_user_cert =
      additional_certificate_chain.add_certificates();
  additional_user_cert->set_format(Certificate::X509_PEM);
  additional_user_cert->set_data(kAdditionalUserCertPem);
  *additional_certificate_chain.add_certificates() = GetAdditionalRoot();

  ASYLO_RETURN_IF_ERROR(sgx::MakeRemoteAssertion(
      kUserData, peer_identity, *attestation_key,
      {sgx_certificate_chain, additional_certificate_chain},
      &remote_assertion));

  Assertion assertion;
  SetSgxAgeRemoteAssertionDescription(assertion.mutable_description());
  if (!remote_assertion.SerializeToString(assertion.mutable_assertion())) {
    return Status(error::GoogleError::INTERNAL,
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
              StatusIs(error::GoogleError::INTERNAL));
}

TEST(SgxAgeRemoteAssertionVerifierTest, InitializeFailsWithBadCerts) {
  SgxAgeRemoteAssertionAuthorityConfig config;
  ASYLO_ASSERT_OK_AND_ASSIGN(config, CreateValidConfig());
  SgxAgeRemoteAssertionVerifier verifier;

  // Test with bad Intel cert.
  config.mutable_intel_root_certificate()->set_data("Beet yogurt is nice");
  EXPECT_THAT(verifier.Initialize(config.SerializeAsString()),
              StatusIs(error::GoogleError::INTERNAL));

  // Test with bad additional cert.
  *config.mutable_intel_root_certificate() = GetFakeIntelRoot();
  config.mutable_root_ca_certificates(0)->set_data("Lemon yogurt too");
  EXPECT_THAT(verifier.Initialize(config.SerializeAsString()),
              StatusIs(error::GoogleError::INTERNAL));
}

TEST(SgxAgeRemoteAssertionVerifierTest, InitializeFailsWithoutIntelCert) {
  SgxAgeRemoteAssertionAuthorityConfig config;
  ASYLO_ASSERT_OK_AND_ASSIGN(config, CreateValidConfig());
  config.clear_intel_root_certificate();

  SgxAgeRemoteAssertionVerifier verifier;
  EXPECT_THAT(verifier.Initialize(config.SerializeAsString()),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(SgxAgeRemoteAssertionVerifierTest,
     InitializeFailsWithoutAgeIdentityExpectation) {
  SgxAgeRemoteAssertionAuthorityConfig config;
  ASYLO_ASSERT_OK_AND_ASSIGN(config, CreateValidConfig());
  config.clear_age_identity_expectation();

  SgxAgeRemoteAssertionVerifier verifier;
  EXPECT_THAT(verifier.Initialize(config.SerializeAsString()),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(SgxAgeRemoteAssertionVerifierTest, InitializesSucceedsAtMostOnce) {
  SgxAgeRemoteAssertionAuthorityConfig config;
  ASYLO_ASSERT_OK_AND_ASSIGN(config, CreateValidConfig());
  SgxAgeRemoteAssertionVerifier verifier;
  ASYLO_ASSERT_OK(verifier.Initialize(config.SerializeAsString()));

  EXPECT_THAT(verifier.Initialize(config.SerializeAsString()),
              StatusIs(error::GoogleError::FAILED_PRECONDITION));
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
              StatusIs(error::GoogleError::FAILED_PRECONDITION));
}

TEST(SgxAgeRemoteAssertionVerifierTest, CreateAssertionRequestSuccess) {
  SgxAgeRemoteAssertionAuthorityConfig config;
  ASYLO_ASSERT_OK_AND_ASSIGN(config, CreateValidConfig());
  SgxAgeRemoteAssertionVerifier verifier;
  ASYLO_ASSERT_OK(verifier.Initialize(config.SerializeAsString()));

  AssertionRequest expected_request;
  SetSgxAgeRemoteAssertionDescription(expected_request.mutable_description());
  sgx::RemoteAssertionRequestAdditionalInfo additional_info;
  *additional_info.mutable_root_ca_certificates() =
      config.root_ca_certificates();
  ASSERT_TRUE(additional_info.SerializeToString(
      expected_request.mutable_additional_information()));

  AssertionRequest request;
  ASYLO_ASSERT_OK(verifier.CreateAssertionRequest(&request));
  EXPECT_THAT(request, EqualsProto(expected_request));
}

TEST(SgxAgeRemoteAssertionVerifierTest, CanVerifyUninitialized) {
  SgxAgeRemoteAssertionVerifier verifier;
  AssertionOffer offer = CreateValidOffer();
  EXPECT_THAT(verifier.CanVerify(offer),
              StatusIs(error::GoogleError::FAILED_PRECONDITION));
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
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
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
              StatusIs(error::GoogleError::FAILED_PRECONDITION));
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
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
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
  ASYLO_ASSERT_OK_AND_ASSIGN(config, CreateValidConfig());
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
