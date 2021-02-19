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

#include "asylo/identity/enclave_assertion_authority_config_verifiers.h"

#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/status/status.h"
#include "asylo/identity/attestation/sgx/sgx_age_remote_assertion_authority_config.pb.h"
#include "asylo/identity/attestation/sgx/sgx_intel_ecdsa_qe_remote_assertion_authority_config.pb.h"
#include "asylo/identity/attestation/sgx/sgx_local_assertion_authority_config.pb.h"
#include "asylo/identity/provisioning/sgx/internal/fake_sgx_pki.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/error_codes.h"
#include "asylo/util/proto_enum_util.h"
#include "asylo/util/proto_parse_util.h"
#include "asylo/util/status.h"

namespace asylo {
namespace {

using ::testing::HasSubstr;
using ::testing::Test;

TEST(EnclaveAssertionAuthorityConfigVerifiersTest,
     VerifySgxLocalAssertionAuthorityConfigEmpty) {
  SgxLocalAssertionAuthorityConfig config;
  EXPECT_THAT(VerifySgxLocalAssertionAuthorityConfig(config),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EnclaveAssertionAuthorityConfigVerifiersTest,
     VerifySgxLocalAssertionAuthorityConfigInvalidAttestationDomain) {
  SgxLocalAssertionAuthorityConfig config;
  config.set_attestation_domain("this is a bit too long");
  EXPECT_THAT(VerifySgxLocalAssertionAuthorityConfig(config),
              StatusIs(absl::StatusCode::kInvalidArgument));

  config.set_attestation_domain("too short");
  EXPECT_THAT(VerifySgxLocalAssertionAuthorityConfig(config),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EnclaveAssertionAuthorityConfigVerifiersTest,
     VerifySgxAgeRemoteAssertionAuthorityConfigEmpty) {
  SgxAgeRemoteAssertionAuthorityConfig config;
  EXPECT_THAT(VerifySgxAgeRemoteAssertionAuthorityConfig(config),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EnclaveAssertionAuthorityConfigVerifiersTest,
     VerifySgxAgeRemoteAssertionAuthorityConfigNoCertificates) {
  SgxAgeRemoteAssertionAuthorityConfig config;
  config.set_server_address("the address");
  EXPECT_THAT(VerifySgxAgeRemoteAssertionAuthorityConfig(config),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EnclaveAssertionAuthorityConfigVerifiersTest,
     VerifySgxIntelEcdsaQeRemoteAssertionAuthorityConfigEmpty) {
  SgxIntelEcdsaQeRemoteAssertionAuthorityConfig config;
  EXPECT_THAT(VerifySgxIntelEcdsaQeRemoteAssertionAuthorityConfig(config),
              StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("empty")));
}

TEST(EnclaveAssertionAuthorityConfigVerifiersTest,
     VerifySgxIntelEcdsaQeRemoteAssertionVerifierConfigInvalidCertFormat) {
  SgxIntelEcdsaQeRemoteAssertionAuthorityConfig config =
      ParseTextProtoOrDie(R"pb(
        verifier_info: {
          qe_identity_expectation: {}
          root_certificates:
          [ { format: UNKNOWN data: "" }]
        })pb");
  EXPECT_THAT(VerifySgxIntelEcdsaQeRemoteAssertionAuthorityConfig(config),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("unknown format")));
}

TEST(EnclaveAssertionAuthorityConfigVerifiersTest,
     VerifySgxIntelEcdsaQeRemoteAssertionVerifierConfigInvalidRootCertData) {
  SgxIntelEcdsaQeRemoteAssertionAuthorityConfig config =
      ParseTextProtoOrDie(R"pb(
        verifier_info: {
          qe_identity_expectation: {}
          root_certificates:
          [ { format: X509_PEM data: "junk data" }]
        })pb");
  EXPECT_THAT(VerifySgxIntelEcdsaQeRemoteAssertionAuthorityConfig(config),
              StatusIs(absl::StatusCode::kInternal,
                       HasSubstr("OPENSSL_internal:NO_START_LINE")));
}

TEST(EnclaveAssertionAuthorityConfigVerifiersTest,
     VerifySgxIntelEcdsaQeRemoteAssertionVerifierConfigNoRootCerts) {
  SgxIntelEcdsaQeRemoteAssertionAuthorityConfig config =
      ParseTextProtoOrDie(R"pb(
        verifier_info: { qe_identity_expectation: {} })pb");
  EXPECT_THAT(VerifySgxIntelEcdsaQeRemoteAssertionAuthorityConfig(config),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("root certificate")));
}

TEST(EnclaveAssertionAuthorityConfigVerifiersTest,
     VerifySgxIntelEcdsaQeRemoteAssertionVerifierConfigNoQeExpectation) {
  SgxIntelEcdsaQeRemoteAssertionAuthorityConfig config =
      ParseTextProtoOrDie(R"pb(
        verifier_info: {
          root_certificates:
          [ { format: X509_PEM data: "" }]
        })pb");
  config.mutable_verifier_info()->mutable_root_certificates(0)->set_data(
      {sgx::kFakeSgxRootCa.certificate_pem.begin(),
       sgx::kFakeSgxRootCa.certificate_pem.end()});
  EXPECT_THAT(VerifySgxIntelEcdsaQeRemoteAssertionAuthorityConfig(config),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("QE identity expectation")));
}

TEST(EnclaveAssertionAuthorityConfigVerifiersTest,
     VerifySgxIntelEcdsaQeRemoteAssertionVerifierConfigInvalidQeExpectation) {
  SgxIntelEcdsaQeRemoteAssertionAuthorityConfig config =
      ParseTextProtoOrDie(R"pb(
        verifier_info: {
          qe_identity_expectation: {
            expectation: {
              reference_identity: {
                description: {
                  identity_type: CODE_IDENTITY
                  authority_type: "SGX"
                }
                identity: "baz"
              }
              match_spec: "foobar"
            }
          }
          root_certificates:
          [ { format: X509_PEM data: "" }]
        })pb");
  config.mutable_verifier_info()->mutable_root_certificates(0)->set_data(
      {sgx::kFakeSgxRootCa.certificate_pem.begin(),
       sgx::kFakeSgxRootCa.certificate_pem.end()});
  EXPECT_THAT(VerifySgxIntelEcdsaQeRemoteAssertionAuthorityConfig(config),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("QE identity expectation")));
}

TEST(EnclaveAssertionAuthorityConfigVerifiersTest,
     VerifySgxIntelEcdsaQeRemoteAssertionGeneratorConfigInvalidCertFormat) {
  SgxIntelEcdsaQeRemoteAssertionAuthorityConfig config =
      ParseTextProtoOrDie(R"pb(
        generator_info: {
          pck_certificate_chain: {
            certificates:
            [ { format: UNKNOWN data: "" }]
          }
        })pb");
  EXPECT_THAT(VerifySgxIntelEcdsaQeRemoteAssertionAuthorityConfig(config),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("unknown format")));
}

TEST(EnclaveAssertionAuthorityConfigVerifiersTest,
     VerifySgxIntelEcdsaQeRemoteAssertionGeneratorConfigInvalidPckCertData) {
  SgxIntelEcdsaQeRemoteAssertionAuthorityConfig config =
      ParseTextProtoOrDie(R"pb(
        generator_info: {
          pck_certificate_chain: {
            certificates:
            [ { format: X509_DER data: "not DER data" }]
          }
        })pb");
  EXPECT_THAT(
      VerifySgxIntelEcdsaQeRemoteAssertionAuthorityConfig(config),
      StatusIs(absl::StatusCode::kInternal, HasSubstr("OPENSSL_internal")));
}

}  // namespace
}  // namespace asylo
