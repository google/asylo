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

#include "asylo/grpc/auth/enclave_credentials_options.h"
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/grpc/auth/null_credentials_options.h"
#include "asylo/grpc/auth/sgx_local_credentials_options.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/identity/null_identity/null_identity_util.h"
#include "asylo/identity/sgx/code_identity_util.h"
#include "asylo/test/util/proto_matchers.h"

namespace asylo {
namespace {

using ::testing::Test;
using ::testing::UnorderedElementsAre;

/// A test fixture is used to set up global constants to test against.
class EnclaveCredentialsOptionsTest : public Test {
 protected:
  EnclaveCredentialsOptionsTest() {
    sgx::SetSgxLocalAssertionDescription(&sgx_local_assertion_description_);
    SetNullAssertionDescription(&null_assertion_description_);
  }
  AssertionDescription sgx_local_assertion_description_;
  AssertionDescription null_assertion_description_;
};

TEST_F(EnclaveCredentialsOptionsTest, SelfNullPeerSgxLocal) {
  EnclaveCredentialsOptions self_null_peer_sgx_local =
      PeerSgxLocalCredentialsOptions().Add(SelfNullCredentialsOptions());
  EXPECT_THAT(self_null_peer_sgx_local.self_assertions,
              UnorderedElementsAre(EqualsProto(null_assertion_description_)));
  EXPECT_THAT(
      self_null_peer_sgx_local.accepted_peer_assertions,
      UnorderedElementsAre(EqualsProto(sgx_local_assertion_description_)));
}

/// Verifies de-duplication if the same credentials option is added
/// more than once.
TEST_F(EnclaveCredentialsOptionsTest, SelfSgxLocalPeerSgxLocalSgxLocal) {
  EnclaveCredentialsOptions self_sgx_local_peer_sgx_local_sgx_local =
      BidirectionalSgxLocalCredentialsOptions().Add(
          PeerSgxLocalCredentialsOptions());
  EXPECT_THAT(
      self_sgx_local_peer_sgx_local_sgx_local.self_assertions,
      UnorderedElementsAre(EqualsProto(sgx_local_assertion_description_)));
  EXPECT_THAT(
      self_sgx_local_peer_sgx_local_sgx_local.accepted_peer_assertions,
      UnorderedElementsAre(EqualsProto(sgx_local_assertion_description_)));
}

TEST_F(EnclaveCredentialsOptionsTest, BidirectionalNull) {
  EnclaveCredentialsOptions bidirectional_null =
      BidirectionalNullCredentialsOptions();
  EXPECT_THAT(bidirectional_null.self_assertions,
              UnorderedElementsAre(EqualsProto(null_assertion_description_)));
  EXPECT_THAT(bidirectional_null.accepted_peer_assertions,
              UnorderedElementsAre(EqualsProto(null_assertion_description_)));
}

TEST_F(EnclaveCredentialsOptionsTest, BidirectionalSgxLocal) {
  EnclaveCredentialsOptions bidirectional_sgx_local =
      BidirectionalSgxLocalCredentialsOptions();
  EXPECT_THAT(
      bidirectional_sgx_local.self_assertions,
      UnorderedElementsAre(EqualsProto(sgx_local_assertion_description_)));
  EXPECT_THAT(
      bidirectional_sgx_local.accepted_peer_assertions,
      UnorderedElementsAre(EqualsProto(sgx_local_assertion_description_)));
}

TEST_F(EnclaveCredentialsOptionsTest, BidirectionalSgxLocalNull) {
  EnclaveCredentialsOptions bidirectional_null_sgx_local =
      BidirectionalNullCredentialsOptions().Add(
          BidirectionalSgxLocalCredentialsOptions());
  EXPECT_THAT(
      bidirectional_null_sgx_local.self_assertions,
      UnorderedElementsAre(EqualsProto(null_assertion_description_),
                           EqualsProto(sgx_local_assertion_description_)));
  EXPECT_THAT(
      bidirectional_null_sgx_local.accepted_peer_assertions,
      UnorderedElementsAre(EqualsProto(null_assertion_description_),
                           EqualsProto(sgx_local_assertion_description_)));
}

}  // namespace
}  // namespace asylo
