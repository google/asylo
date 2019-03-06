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
#include "asylo/grpc/auth/peer_identity_util.h"

#include <memory>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/grpc/auth/test/mock_enclave_auth_context.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/identity/sgx/code_identity.pb.h"
#include "asylo/identity/sgx/code_identity_util.h"
#include "asylo/identity/test/mock_identity_expectation_matcher.h"
#include "asylo/test/util/proto_matchers.h"
#include "asylo/test/util/status_matchers.h"

namespace asylo {
namespace {

using ::testing::Return;
using ::testing::StrictMock;
using ::testing::Test;

class PeerIdentityUtilTest : public Test {
 protected:
  void SetUp() override {
    // Sets up the objects to return from the mocks.
    sgx::CodeIdentityExpectation code_identity_expectation;
    sgx::SetDefaultSelfCodeIdentityExpectation(&code_identity_expectation);
    ASYLO_ASSERT_OK(sgx::SerializeSgxExpectation(
        code_identity_expectation, &enclave_identity_expectation_));

    sgx::CodeIdentity code_identity;
    sgx::SetSelfCodeIdentity(&code_identity);
    ASYLO_ASSERT_OK(
        sgx::SerializeSgxIdentity(code_identity, &enclave_identity_));
  }

 protected:
  StrictMock<MockEnclaveAuthContext> mock_enclave_auth_context_;
  EnclaveIdentity enclave_identity_;
  EnclaveIdentityExpectation enclave_identity_expectation_;
  MockIdentityExpectationMatcher mock_identity_expectation_matcher_;
};

TEST_F(PeerIdentityUtilTest, ExtractAndMatchEnclaveIdentitySucceedsAndMatches) {
  // The enclave auth context contains an identity that matches the enclave
  // identity expectation.
  EXPECT_CALL(
      mock_enclave_auth_context_,
      FindEnclaveIdentity(EqualsProto(
          enclave_identity_expectation_.reference_identity().description())))
      .WillOnce(Return(&enclave_identity_));
  EXPECT_CALL(mock_identity_expectation_matcher_,
              Match(EqualsProto(enclave_identity_),
                    EqualsProto(enclave_identity_expectation_)))
      .WillOnce(Return(true));

  EXPECT_THAT(ExtractAndMatchEnclaveIdentity(
                  mock_enclave_auth_context_, enclave_identity_expectation_,
                  mock_identity_expectation_matcher_),
              IsOkAndHolds(true));
}

TEST_F(PeerIdentityUtilTest,
       ExtractAndMatchEnclaveIdentitySucceedsAndDoesNotMatch) {
  // The enclave auth context contains an identity with the same description as
  // the enclave identity expectation, but the identity does not match the
  // expectation.
  EXPECT_CALL(
      mock_enclave_auth_context_,
      FindEnclaveIdentity(EqualsProto(
          enclave_identity_expectation_.reference_identity().description())))
      .WillOnce(Return(&enclave_identity_));
  EXPECT_CALL(mock_identity_expectation_matcher_,
              Match(EqualsProto(enclave_identity_),
                    EqualsProto(enclave_identity_expectation_)))
      .WillOnce(Return(false));

  EXPECT_THAT(ExtractAndMatchEnclaveIdentity(
                  mock_enclave_auth_context_, enclave_identity_expectation_,
                  mock_identity_expectation_matcher_),
              IsOkAndHolds(false));
}

TEST_F(PeerIdentityUtilTest, ExtractAndMatchEnclaveIdentityFindIdentityFails) {
  // The enclave auth context does not contain an identity with the same
  // description as the enclave identity expectation.
  EXPECT_CALL(
      mock_enclave_auth_context_,
      FindEnclaveIdentity(EqualsProto(
          enclave_identity_expectation_.reference_identity().description())))
      .WillOnce(Return(Status(error::GoogleError::NOT_FOUND, "")));

  EXPECT_THAT(ExtractAndMatchEnclaveIdentity(mock_enclave_auth_context_,
                                             enclave_identity_expectation_,
                                             mock_identity_expectation_matcher_)
                  .status(),
              StatusIs(error::GoogleError::PERMISSION_DENIED));
}

TEST_F(PeerIdentityUtilTest, ExtractAndMatchEnclaveIdentityMatcherFails) {
  // The identity matcher fails to compare the identity and expectation.
  EXPECT_CALL(
      mock_enclave_auth_context_,
      FindEnclaveIdentity(EqualsProto(
          enclave_identity_expectation_.reference_identity().description())))
      .WillOnce(Return(&enclave_identity_));
  EXPECT_CALL(mock_identity_expectation_matcher_,
              Match(EqualsProto(enclave_identity_),
                    EqualsProto(enclave_identity_expectation_)))
      .WillOnce(Return(Status(error::GoogleError::INVALID_ARGUMENT, "")));

  EXPECT_THAT(ExtractAndMatchEnclaveIdentity(mock_enclave_auth_context_,
                                             enclave_identity_expectation_,
                                             mock_identity_expectation_matcher_)
                  .status(),
              StatusIs(error::GoogleError::INTERNAL));
}

}  // namespace
}  // namespace asylo
