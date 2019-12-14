/*
 *
 * Copyright 2017 Asylo authors
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

#include "asylo/grpc/auth/core/ekep_handshaker_util.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/grpc/auth/core/ekep_handshaker.h"
#include "asylo/identity/attestation/null/null_identity_util.h"
#include "asylo/identity/descriptions.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/test/util/status_matchers.h"

namespace asylo {
namespace {

using ::testing::Not;

const char kBadAuthorityType[] = "unknown authority";

class EkepHandshakerUtilTest : public ::testing::Test {
 protected:
  void SetUp() override {
    SetNullAssertionDescription(&null_assertion_description_);

    default_options_.self_assertions = {null_assertion_description_};
    default_options_.accepted_peer_assertions = {null_assertion_description_};
  }

  AssertionDescription null_assertion_description_;
  EkepHandshakerOptions default_options_;
};

// Verify that GetEnclaveAssertionGenerator can retrieve a pointer to an
// instance of the NullAssertionGenerator.
TEST_F(EkepHandshakerUtilTest, GetNullEnclaveAssertionGenerator) {
  EXPECT_NE(GetEnclaveAssertionGenerator(null_assertion_description_), nullptr);
}

// Verify that GetEnclaveAssertionGenerator cannot retrieve a pointer to an
// instance of non-existent EnclaveAssertionGenerator.
TEST_F(EkepHandshakerUtilTest, GetInvalidEnclaveAssertionGenerator) {
  AssertionDescription bad_assertion_description;
  bad_assertion_description.set_identity_type(CODE_IDENTITY);
  bad_assertion_description.set_authority_type(kBadAuthorityType);
  EXPECT_EQ(GetEnclaveAssertionGenerator(bad_assertion_description), nullptr);
}

// Verify that GetEnclaveAssertionVerifier can retrieve a pointer to an instance
// of the NullAssertionVerifier.
TEST_F(EkepHandshakerUtilTest, GetNullEnclaveAssertionVerifier) {
  EXPECT_NE(GetEnclaveAssertionVerifier(null_assertion_description_), nullptr);
}

// Verify that GetEnclaveAssertionVerifier cannot retrieve a pointer to an
// instance of a non-existent EnclaveAssertionVerifier.
TEST_F(EkepHandshakerUtilTest, GetInvalidEnclaveAssertionVerifier) {
  AssertionDescription bad_assertion_description;
  bad_assertion_description.set_identity_type(CODE_IDENTITY);
  bad_assertion_description.set_authority_type(kBadAuthorityType);
  EXPECT_EQ(GetEnclaveAssertionVerifier(bad_assertion_description), nullptr);
}

TEST_F(EkepHandshakerUtilTest, ValidateSuccess) {
  EXPECT_THAT(default_options_.Validate(), IsOk());
}

// Verify that Validate fails on a set of options with an invalid maximum frame
// size.
TEST_F(EkepHandshakerUtilTest, ValidateBadFrameSize) {
  EkepHandshakerOptions options = default_options_;

  // Max frame size exceeds the limit on maximum frame size.
  options.max_frame_size = EkepHandshaker::kFrameSizeLimit + 1;
  EXPECT_THAT(options.Validate(), Not(IsOk()));

  // Negative max frame size.
  options.max_frame_size = -1;
  EXPECT_THAT(options.Validate(), Not(IsOk()));
}

// Verify that Validate fails on a set of options with additional authenticated
// data that is larger than half the maximum frame size.
TEST_F(EkepHandshakerUtilTest, ValidateBadAadSize) {
  EkepHandshakerOptions options = default_options_;
  options.max_frame_size = 10;
  options.additional_authenticated_data.resize(options.max_frame_size + 1);

  EXPECT_THAT(options.Validate(), Not(IsOk()));
}

// Verify that Validate fails on a set of options with an empty list of self
// assertions.
TEST_F(EkepHandshakerUtilTest, ValidateMissingSelfIdentities) {
  EkepHandshakerOptions options = default_options_;
  options.self_assertions.clear();

  EXPECT_THAT(options.Validate(), Not(IsOk()));
}

// Verify that Validate fails on a set of options with an empty list of accepted
// peer assertions.
TEST_F(EkepHandshakerUtilTest, ValidateMissingAcceptedPeerIdentities) {
  EkepHandshakerOptions options = default_options_;
  options.accepted_peer_assertions.clear();

  EXPECT_THAT(options.Validate(), Not(IsOk()));
}

// Verify that Validate fails when passed options with a self assertion that has
// no associated EnclaveAssertionGenerator library.
TEST_F(EkepHandshakerUtilTest, ValidateInvalidSelfAssertions) {
  EkepHandshakerOptions options = default_options_;

  AssertionDescription description;
  description.set_identity_type(CODE_IDENTITY);
  description.set_authority_type(kBadAuthorityType);
  options.self_assertions.push_back(description);

  EXPECT_THAT(options.Validate(), Not(IsOk()));
}

// Verify that Validate fails on a set of options with an accepted peer
// assertion that has no associated EnclaveAssertionVerifier library.
TEST_F(EkepHandshakerUtilTest, ValidateInvalidAcceptedPeerAssertions) {
  EkepHandshakerOptions options = default_options_;

  AssertionDescription description;
  description.set_identity_type(CODE_IDENTITY);
  description.set_authority_type(kBadAuthorityType);
  options.accepted_peer_assertions.push_back(description);

  EXPECT_THAT(options.Validate(), Not(IsOk()));
}

}  // namespace
}  // namespace asylo
