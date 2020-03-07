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

#include "asylo/identity/enclave_assertion_authority_configs.h"

#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/container/flat_hash_set.h"
#include "asylo/crypto/certificate.pb.h"
#include "asylo/daemon/identity/attestation_domain.h"
#include "asylo/identity/attestation/sgx/sgx_age_remote_assertion_authority_config.pb.h"
#include "asylo/identity/attestation/sgx/sgx_intel_ecdsa_qe_remote_assertion_authority_config.pb.h"
#include "asylo/identity/descriptions.h"
#include "asylo/identity/enclave_assertion_authority_config.pb.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/identity/sgx/intel_certs/intel_sgx_root_ca_cert.h"
#include "asylo/identity/sgx/sgx_local_assertion_authority_config.pb.h"
#include "asylo/test/util/proto_matchers.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/error_codes.h"
#include "asylo/util/proto_enum_util.h"
#include "asylo/util/proto_parse_util.h"

namespace asylo {
namespace {

using ::testing::ElementsAre;
using ::testing::SizeIs;
using ::testing::StrEq;
using ::testing::Test;

TEST(EnclaveAssertionAuthorityConfigsTest,
     CreateNullAssertionAuthorityConfigSuccess) {
  AssertionDescription description;
  SetNullAssertionDescription(&description);

  EnclaveAssertionAuthorityConfig config = CreateNullAssertionAuthorityConfig();
  EXPECT_THAT(config.description(), EqualsProto(description));
}

TEST(EnclaveAssertionAuthorityConfigsTest,
     CreateSgxLocalAssertionAuthorityConfigWithAttestationDomainSuccess) {
  constexpr char kAttestationDomain[] = "A 16-byte string";

  AssertionDescription description;
  SetSgxLocalAssertionDescription(&description);

  EnclaveAssertionAuthorityConfig config;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      config, CreateSgxLocalAssertionAuthorityConfig(kAttestationDomain));

  EXPECT_THAT(config.description(), EqualsProto(description));

  SgxLocalAssertionAuthorityConfig sgx_config;
  ASSERT_TRUE(sgx_config.ParseFromString(config.config()));
  EXPECT_THAT(sgx_config.attestation_domain(), StrEq(kAttestationDomain));
}

TEST(EnclaveAssertionAuthorityConfigsTest,
     CreateSgxLocalAssertionAuthorityConfigSuccess) {
  AssertionDescription description;
  SetSgxLocalAssertionDescription(&description);

  EnclaveAssertionAuthorityConfig config;
  ASYLO_ASSERT_OK_AND_ASSIGN(config, CreateSgxLocalAssertionAuthorityConfig());

  EXPECT_THAT(config.description(), EqualsProto(description));

  SgxLocalAssertionAuthorityConfig sgx_config;
  ASSERT_TRUE(sgx_config.ParseFromString(config.config()));
  EXPECT_THAT(sgx_config.attestation_domain(),
              SizeIs(kAttestationDomainNameSize));
}

TEST(EnclaveAssertionAuthorityConfigsTest,
     CreateSgxLocalAssertionAuthorityConfigInvalidAttestationDomain) {
  EXPECT_THAT(CreateSgxLocalAssertionAuthorityConfig("this is a bit too long"),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));

  EXPECT_THAT(CreateSgxLocalAssertionAuthorityConfig("too short"),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(EnclaveAssertionAuthorityConfigsTest,
     CreateSgxIntelEcdsaQeRemoteAssertionAuthorityConfigWithEmptyChain) {
  EXPECT_THAT(
      experimental::CreateSgxIntelEcdsaQeRemoteAssertionAuthorityConfig({}),
      StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(EnclaveAssertionAuthorityConfigsTest,
     CreateSgxIntelEcdsaQeRemoteAssertionAuthorityConfig) {
  EnclaveAssertionAuthorityConfig expected_config = ParseTextProtoOrDie(R"pb(
    description: {
      identity_type: CODE_IDENTITY
      authority_type: "SGX Intel ECDSA QE"
    })pb");

  // clang-format off
  SgxIntelEcdsaQeRemoteAssertionAuthorityConfig sgx_config =
      ParseTextProtoOrDie(R"pb(
        generator_info: {
          pck_certificate_chain: {
            certificates: [{
              format: X509_PEM
              data: "first cert"
            }, {
              format: X509_DER
              data: "second cert"
            }]
          }
        })pb");
  // clang-format on

  Certificate *cert =
      sgx_config.mutable_verifier_info()->add_root_certificates();
  cert->set_format(Certificate::X509_PEM);
  cert->set_data(kIntelSgxRootCaCertificate);
  ASSERT_TRUE(sgx_config.SerializeToString(expected_config.mutable_config()));

  std::vector<Certificate> certs = {
      ParseTextProtoOrDie("format: X509_PEM\ndata: 'first cert'"),
      ParseTextProtoOrDie("format: X509_DER\ndata: 'second cert'")};
  EXPECT_THAT(
      experimental::CreateSgxIntelEcdsaQeRemoteAssertionAuthorityConfig(certs),
      IsOkAndHolds(EqualsProto(expected_config)));
}

TEST(EnclaveAssertionAuthorityConfigsTest,
     CreateSgxIntelEcdsaQeRemoteAssertionAuthorityConfigWithDefaults) {
  EnclaveAssertionAuthorityConfig expected_config = ParseTextProtoOrDie(R"pb(
    description: {
      identity_type: CODE_IDENTITY
      authority_type: "SGX Intel ECDSA QE"
    })pb");

  // clang-format off
  SgxIntelEcdsaQeRemoteAssertionAuthorityConfig sgx_config =
      ParseTextProtoOrDie(R"pb(
        generator_info: {
          use_dcap_default: {}
        })pb");
  // clang-format on

  Certificate *cert =
      sgx_config.mutable_verifier_info()->add_root_certificates();
  cert->set_format(Certificate::X509_PEM);
  cert->set_data(kIntelSgxRootCaCertificate);
  EXPECT_TRUE(sgx_config.SerializeToString(expected_config.mutable_config()));

  EXPECT_THAT(
      experimental::CreateSgxIntelEcdsaQeRemoteAssertionAuthorityConfig(),
      IsOkAndHolds(EqualsProto(expected_config)));
}

}  // namespace
}  // namespace asylo
