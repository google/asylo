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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/daemon/identity/attestation_domain.h"
#include "asylo/identity/attestation/sgx/sgx_age_remote_assertion_authority_config.pb.h"
#include "asylo/identity/descriptions.h"
#include "asylo/identity/enclave_assertion_authority_config.pb.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/identity/sgx/sgx_local_assertion_authority_config.pb.h"
#include "asylo/test/util/proto_matchers.h"
#include "asylo/test/util/status_matchers.h"

namespace asylo {
namespace {

using ::testing::ElementsAre;
using ::testing::SizeIs;
using ::testing::StrEq;

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

}  // namespace
}  // namespace asylo
