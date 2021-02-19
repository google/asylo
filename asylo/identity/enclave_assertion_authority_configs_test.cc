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
#include "absl/status/status.h"
#include "asylo/crypto/certificate.pb.h"
#include "asylo/daemon/identity/attestation_domain.h"
#include "asylo/identity/attestation/sgx/internal/intel_certs/intel_sgx_root_ca_cert.h"
#include "asylo/identity/attestation/sgx/internal/intel_certs/qe_identity.h"
#include "asylo/identity/attestation/sgx/sgx_age_remote_assertion_authority_config.pb.h"
#include "asylo/identity/attestation/sgx/sgx_intel_ecdsa_qe_remote_assertion_authority_config.pb.h"
#include "asylo/identity/attestation/sgx/sgx_local_assertion_authority_config.pb.h"
#include "asylo/identity/descriptions.h"
#include "asylo/identity/enclave_assertion_authority_config.pb.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/identity/identity_acl.pb.h"
#include "asylo/identity/platform/sgx/sgx_identity.pb.h"
#include "asylo/identity/platform/sgx/sgx_identity_util.h"
#include "asylo/test/util/proto_matchers.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/error_codes.h"
#include "asylo/util/proto_enum_util.h"
#include "asylo/util/proto_parse_util.h"
#include "asylo/util/status_macros.h"

namespace asylo {
namespace {

using ::testing::ElementsAre;
using ::testing::IsEmpty;
using ::testing::SizeIs;
using ::testing::StrEq;
using ::testing::Test;

// Valid cert, formatted for insertion into a protubuf message.
#define TEST_PEM_CERT                                                   \
  "-----BEGIN CERTIFICATE-----\\n"                                      \
  "MIIBdTCCAR+gAwIBAgIUYct7MCZjztm0hr1mQH6jE8Z/3wUwDQYJKoZIhvcNAQEF\\n" \
  "BQAwDzENMAsGA1UEAwwEdGVzdDAeFw0yMDAyMTQyMjQzMzZaFw00NzA3MDEyMjQz\\n" \
  "MzZaMA8xDTALBgNVBAMMBHRlc3QwXDANBgkqhkiG9w0BAQEFAANLADBIAkEAvtwO\\n" \
  "oP6GtTtlsw5qrbO6O1EiE4+6mLdJjuxOrsHWvx4SHnZ1qgD3UVQyeo0corgJK57g\\n" \
  "bGGvfPR0X30cn3lWTQIDAQABo1MwUTAdBgNVHQ4EFgQUadIc6sRpRLex0C/WVTHf\\n" \
  "KhIfAhowHwYDVR0jBBgwFoAUadIc6sRpRLex0C/WVTHfKhIfAhowDwYDVR0TAQH/\\n" \
  "BAUwAwEB/zANBgkqhkiG9w0BAQUFAANBAA34lGWyozDj6vl0xGqkR7PzU4DyE27K\\n" \
  "MR+48EpgZn4qUY9anOCUFGkqyBpZ7HX3z/LQW2UU1QhyJr3UYKYul3Q=\\n"         \
  "-----END CERTIFICATE-----"

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
              StatusIs(absl::StatusCode::kInvalidArgument));

  EXPECT_THAT(CreateSgxLocalAssertionAuthorityConfig("too short"),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EnclaveAssertionAuthorityConfigsTest,
     CreateSgxAgeRemoteAssertionAuthorityConfigSuccess) {
  constexpr char kServerAddress[] = "the address";

  AssertionDescription description;
  SetSgxAgeRemoteAssertionDescription(&description);

  Certificate additional_root_certificate;
  additional_root_certificate.set_data("Cert Data");
  additional_root_certificate.set_format(Certificate::X509_DER);

  Certificate intel_root_cert =
      ParseTextProtoOrDie("format: X509_PEM\ndata: '" TEST_PEM_CERT "'");

  SgxIdentityExpectation sgx_age_expectation;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      sgx_age_expectation,
      CreateSgxIdentityExpectation(GetSelfSgxIdentity(),
                                   SgxIdentityMatchSpecOptions::DEFAULT));
  IdentityAclPredicate age_identity_expectation;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      *age_identity_expectation.mutable_expectation(),
      SerializeSgxIdentityExpectation(sgx_age_expectation));

  EnclaveAssertionAuthorityConfig config;
  ASYLO_ASSERT_OK_AND_ASSIGN(config,
                             CreateSgxAgeRemoteAssertionAuthorityConfig(
                                 intel_root_cert, {additional_root_certificate},
                                 kServerAddress, age_identity_expectation));

  EXPECT_THAT(config.description(), EqualsProto(description));

  SgxAgeRemoteAssertionAuthorityConfig sgx_config;
  ASSERT_TRUE(sgx_config.ParseFromString(config.config()));
  EXPECT_THAT(sgx_config.root_ca_certificates(),
              ElementsAre(EqualsProto(additional_root_certificate)));
  EXPECT_THAT(sgx_config.server_address(), StrEq(kServerAddress));
  EXPECT_THAT(sgx_config.intel_root_certificate(),
              EqualsProto(intel_root_cert));
  EXPECT_THAT(sgx_config.age_identity_expectation(),
              EqualsProto(age_identity_expectation));
}

TEST(EnclaveAssertionAuthorityConfigsTest,
     CreateSgxAgeRemoteAssertionAuthorityConfigWithDefaultsSuccess) {
  constexpr char kServerAddress[] = "Home";

  SgxIdentity age_identity = GetSelfSgxIdentity();

  EnclaveAssertionAuthorityConfig config;
  ASYLO_ASSERT_OK_AND_ASSIGN(config, CreateSgxAgeRemoteAssertionAuthorityConfig(
                                         kServerAddress, age_identity));

  AssertionDescription expected_description;
  SetSgxAgeRemoteAssertionDescription(&expected_description);
  EXPECT_THAT(config.description(), EqualsProto(expected_description));

  IdentityAclPredicate expected_age_expectation;

  SgxIdentityExpectation expected_age_sgx_expectation;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      expected_age_sgx_expectation,
      CreateSgxIdentityExpectation(age_identity,
                                   SgxIdentityMatchSpecOptions::DEFAULT));
  ASYLO_ASSERT_OK_AND_ASSIGN(
      *expected_age_expectation.mutable_expectation(),
      SerializeSgxIdentityExpectation(expected_age_sgx_expectation));

  SgxAgeRemoteAssertionAuthorityConfig sgx_config;
  ASSERT_TRUE(sgx_config.ParseFromString(config.config()));
  EXPECT_THAT(sgx_config.intel_root_certificate(),
              EqualsProto(MakeIntelSgxRootCaCertificateProto()));
  EXPECT_THAT(sgx_config.root_ca_certificates(), IsEmpty());
  EXPECT_THAT(sgx_config.server_address(), StrEq(kServerAddress));
  EXPECT_THAT(sgx_config.age_identity_expectation(),
              EqualsProto(expected_age_expectation));
}

TEST(EnclaveAssertionAuthorityConfigsTest,
     CreateSgxIntelEcdsaQeRemoteAssertionAuthorityConfigWithEmptyChain) {
  EXPECT_THAT(experimental::CreateSgxIntelEcdsaQeRemoteAssertionAuthorityConfig(
                  {}, GetSelfSgxIdentity()),
              StatusIs(absl::StatusCode::kInvalidArgument));
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
              data: ")pb" TEST_PEM_CERT R"pb("
            }, {
              format: X509_PEM
              data: ")pb" TEST_PEM_CERT R"pb("
            }]
          }
        })pb");
  // clang-format on

  Certificate *cert =
      sgx_config.mutable_verifier_info()->add_root_certificates();
  cert->set_format(Certificate::X509_PEM);
  cert->set_data(kIntelSgxRootCaCertificate);

  SgxIdentityExpectation expectation;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      expectation,
      CreateSgxIdentityExpectation(GetSelfSgxIdentity(),
                                   SgxIdentityMatchSpecOptions::DEFAULT));
  ASYLO_ASSERT_OK_AND_ASSIGN(*sgx_config.mutable_verifier_info()
                                  ->mutable_qe_identity_expectation()
                                  ->mutable_expectation(),
                             SerializeSgxIdentityExpectation(expectation));

  ASSERT_TRUE(sgx_config.SerializeToString(expected_config.mutable_config()));

  Certificate pem_cert =
      ParseTextProtoOrDie("format: X509_PEM\ndata: '" TEST_PEM_CERT "'");
  CertificateChain certs;
  *certs.add_certificates() = pem_cert;
  *certs.add_certificates() = pem_cert;
  EXPECT_THAT(experimental::CreateSgxIntelEcdsaQeRemoteAssertionAuthorityConfig(
                  certs, GetSelfSgxIdentity()),
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

  SgxIdentityExpectation expectation;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      expectation, CreateSgxIdentityExpectation(
                       ParseTextProtoOrDie(sgx::kIntelEcdsaQeIdentityTextproto),
                       SgxIdentityMatchSpecOptions::DEFAULT));
  ASYLO_ASSERT_OK_AND_ASSIGN(*sgx_config.mutable_verifier_info()
                                  ->mutable_qe_identity_expectation()
                                  ->mutable_expectation(),
                             SerializeSgxIdentityExpectation(expectation));

  EXPECT_TRUE(sgx_config.SerializeToString(expected_config.mutable_config()));

  EXPECT_THAT(
      experimental::CreateSgxIntelEcdsaQeRemoteAssertionAuthorityConfig(),
      IsOkAndHolds(EqualsProto(expected_config)));
}

}  // namespace
}  // namespace asylo
