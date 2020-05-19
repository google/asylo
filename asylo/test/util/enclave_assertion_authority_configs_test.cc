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

#include "asylo/test/util/enclave_assertion_authority_configs.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/identity/attestation/sgx/sgx_age_remote_assertion_authority_config.pb.h"
#include "asylo/identity/descriptions.h"
#include "asylo/identity/enclave_assertion_authority_config.pb.h"
#include "asylo/identity/identity_acl.pb.h"
#include "asylo/identity/platform/sgx/sgx_identity.pb.h"
#include "asylo/identity/platform/sgx/sgx_identity_expectation_matcher.h"
#include "asylo/identity/platform/sgx/sgx_identity_util.h"
#include "asylo/identity/provisioning/sgx/internal/fake_sgx_pki.h"
#include "asylo/test/util/proto_matchers.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/proto_parse_util.h"

using ::testing::IsEmpty;
using ::testing::StrEq;

namespace asylo {
namespace {

constexpr char kSampleDebugEnclaveSgxIdentity[] = R"proto(
  code_identity {
    mrenclave {
      hash: "\346\311\'u\205r\026\323\331\236\270\274J\345\267\037\022\364\264,\254\2303\034\231\226Pgf\350\325\205"
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
    cpu_svn { value: "H \3637j\346\262\362\003M;zKH\247x" }
  }
)proto";

TEST(EnclaveAssertionAuthorityConfigsTest,
     GetSgxAgeRemoteAssertionAuthorityTestConfigSuccess) {
  constexpr char kServerAddress[] = "[::1]";
  SgxIdentity age_identity = GetSelfSgxIdentity();
  EnclaveAssertionAuthorityConfig authority_config =
      GetSgxAgeRemoteAssertionAuthorityTestConfig(kServerAddress, age_identity);

  AssertionDescription expected_description;
  SetSgxAgeRemoteAssertionDescription(&expected_description);
  EXPECT_THAT(authority_config.description(),
              EqualsProto(expected_description));

  SgxAgeRemoteAssertionAuthorityConfig sgx_authority_config;
  ASSERT_TRUE(sgx_authority_config.ParseFromString(authority_config.config()));
  EXPECT_THAT(sgx_authority_config.root_ca_certificates(), IsEmpty());
  EXPECT_THAT(sgx_authority_config.server_address(), StrEq(kServerAddress));
  EXPECT_THAT(sgx_authority_config.intel_root_certificate(),
              EqualsProto(sgx::GetFakeSgxRootCertificate()));

  SgxIdentityExpectation sgx_identity_expectation;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      sgx_identity_expectation,
      CreateSgxIdentityExpectation(age_identity,
                                   SgxIdentityMatchSpecOptions::DEFAULT));
  EnclaveIdentityExpectation age_identity_expectation;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      age_identity_expectation,
      SerializeSgxIdentityExpectation(sgx_identity_expectation));
  EXPECT_THAT(sgx_authority_config.age_identity_expectation().expectation(),
              EqualsProto(age_identity_expectation));
}

TEST(EnclaveAssertionAuthorityConfigsTest,
     GetSgxAgeRemoteAssertionAuthorityTestConfigDefaultIdentitySuccess) {
  constexpr char kServerAddress[] = "[::1]";
  EnclaveAssertionAuthorityConfig authority_config =
      GetSgxAgeRemoteAssertionAuthorityTestConfig(kServerAddress);

  AssertionDescription expected_description;
  SetSgxAgeRemoteAssertionDescription(&expected_description);
  EXPECT_THAT(authority_config.description(),
              EqualsProto(expected_description));

  SgxAgeRemoteAssertionAuthorityConfig sgx_authority_config;
  ASSERT_TRUE(sgx_authority_config.ParseFromString(authority_config.config()));
  EXPECT_THAT(sgx_authority_config.root_ca_certificates(), IsEmpty());
  EXPECT_THAT(sgx_authority_config.server_address(), StrEq(kServerAddress));
  EXPECT_THAT(sgx_authority_config.intel_root_certificate(),
              EqualsProto(sgx::GetFakeSgxRootCertificate()));

  SgxIdentityExpectationMatcher matcher;
  SgxIdentity random_sgx_identity =
      ParseTextProtoOrDie(kSampleDebugEnclaveSgxIdentity);
  EnclaveIdentity random_enclave_identity;
  ASYLO_ASSERT_OK_AND_ASSIGN(random_enclave_identity,
                             SerializeSgxIdentity(random_sgx_identity));
  EXPECT_THAT(
      matcher.MatchAndExplain(
          random_enclave_identity,
          sgx_authority_config.age_identity_expectation().expectation(),
          /*explanation=*/nullptr),
      IsOkAndHolds(true));
}

}  // namespace
}  // namespace asylo
