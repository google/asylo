/*
 *
 * Copyright 2018 Asylo authors
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

#include "asylo/identity/init.h"

#include <vector>

#include <google/protobuf/text_format.h>
#include <gtest/gtest.h>
#include "asylo/identity/enclave_assertion_authority_config.pb.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/proto_parse_util.h"

namespace asylo {
namespace {

using ::testing::Not;

constexpr char kTestConfig[] = R"proto(
  description: { identity_type: NULL_IDENTITY authority_type: "Any" }
  config: "The office was underappreciated. Let me back"
)proto";

constexpr char kTestInvalidConfig[] = R"proto(
  description: { identity_type: CODE_IDENTITY authority_type: "foobar" }
  config: "I miss my desk chair"
)proto";

// Verify that InitializeEnclaveAssertionAuthorities succeeds with a set of
// empty configs.
TEST(InitTest, InitializeSucceedsWithEmptyConfigs) {
  std::vector<EnclaveAssertionAuthorityConfig> configs;

  EXPECT_THAT(
      InitializeEnclaveAssertionAuthorities(configs.begin(), configs.end()),
      IsOk());
}


// Verify that InitializeEnclaveAssertionAuthorities succeeds when provided with
// valid configs.
TEST(InitTest, InitializeSucceedsWithConfigs) {
  std::vector<EnclaveAssertionAuthorityConfig> configs(1);

  ASSERT_TRUE(
      google::protobuf::TextFormat::ParseFromString(kTestConfig, &configs.front()));

  EXPECT_THAT(
      InitializeEnclaveAssertionAuthorities(configs.begin(), configs.end()),
      IsOk());
}

// Verify that InitializeEnclaveAssertionAuthorities continues to succeed after
// the first successful call.
TEST(InitTest, InitializeSucceedsRepeatedlyAfterFirstSuccess) {
  std::vector<EnclaveAssertionAuthorityConfig> configs;

  EXPECT_THAT(
      InitializeEnclaveAssertionAuthorities(configs.begin(), configs.end()),
      IsOk());
  EXPECT_THAT(
      InitializeEnclaveAssertionAuthorities(configs.begin(), configs.end()),
      IsOk());
  EXPECT_THAT(
      InitializeEnclaveAssertionAuthorities(configs.begin(), configs.end()),
      IsOk());
}

// Verify that InitializeEnclaveAssertionAuthorities fails when provided with
// configs that don't match any available assertion authorities.
TEST(InitTest, InitializeFailsWithNonMatchingConfigs) {
  std::vector<EnclaveAssertionAuthorityConfig> configs(1);

  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(kTestInvalidConfig,
                                                  &configs.front()));

  EXPECT_THAT(
      InitializeEnclaveAssertionAuthorities(configs.begin(), configs.end()),
      Not(IsOk()));
}

TEST(InitTest, InitializeEnclaveAssertionVerifierSuccess) {
  EnclaveAssertionAuthorityConfig config = ParseTextProtoOrDie(kTestConfig);
  ASYLO_EXPECT_OK(InitializeEnclaveAssertionVerifier(config));
}

TEST(InitTest, InitializeEnclaveAssertionVerifierFailsWithInvalidConfig) {
  EnclaveAssertionAuthorityConfig config =
      ParseTextProtoOrDie(kTestInvalidConfig);
  EXPECT_THAT(InitializeEnclaveAssertionVerifier(config), Not(IsOk()));
}

TEST(InitTest, InitializeEnclaveAssertionGeneratorSuccess) {
  EnclaveAssertionAuthorityConfig config = ParseTextProtoOrDie(kTestConfig);
  ASYLO_EXPECT_OK(InitializeEnclaveAssertionGenerator(config));
}

TEST(InitTest, InitializeEnclaveAssertionGeneratorFailsWithInvalidConfig) {
  EnclaveAssertionAuthorityConfig config =
      ParseTextProtoOrDie(kTestInvalidConfig);
  EXPECT_THAT(InitializeEnclaveAssertionGenerator(config), Not(IsOk()));
}

}  // namespace
}  // namespace asylo
