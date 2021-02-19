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

#include "asylo/identity/platform/sgx/sgx_identity_util.h"

#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/status/status.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/identity/platform/sgx/internal/fake_enclave.h"
#include "asylo/identity/platform/sgx/internal/proto_format.h"
#include "asylo/identity/platform/sgx/internal/sgx_identity_test_util.h"
#include "asylo/identity/platform/sgx/sgx_identity.pb.h"
#include "asylo/test/util/proto_matchers.h"
#include "asylo/test/util/status_matchers.h"

namespace asylo {

TEST(SgxIdentityUtilTest, GetSelfSgxIdentity) {
  sgx::FakeEnclave enclave;
  enclave.SetRandomIdentity();

  // Ensure we are not already inside of an enclave, which could happen if
  // this is not the first test in the suite to be executed.
  if (sgx::FakeEnclave::GetCurrentEnclave() != nullptr) {
    sgx::FakeEnclave::ExitEnclave();
  }

  sgx::FakeEnclave::EnterEnclave(enclave);
  EXPECT_THAT(GetSelfSgxIdentity(), EqualsProto(enclave.GetIdentity()));
  sgx::FakeEnclave::ExitEnclave();
}

TEST(SgxIdentityUtilTest, CreateSgxIdentityMatchSpecs) {
  const auto all_options = {SgxIdentityMatchSpecOptions::DEFAULT,
                            SgxIdentityMatchSpecOptions::STRICT_LOCAL,
                            SgxIdentityMatchSpecOptions::STRICT_REMOTE};

  // Check that all SgxIdentityMatchSpecOptions create valid
  // SgxIdentityMatchSpec objects, and that all are unique (ie. there are no
  // redundant enum values).
  for (auto options_1 : all_options) {
    SgxIdentityMatchSpec match_spec_1;
    ASYLO_ASSERT_OK_AND_ASSIGN(match_spec_1,
                               CreateSgxIdentityMatchSpec(options_1));
    EXPECT_TRUE(IsValidSgxIdentityMatchSpec(match_spec_1));
    for (auto options_2 : all_options) {
      SgxIdentityMatchSpec match_spec_2;
      ASYLO_ASSERT_OK_AND_ASSIGN(match_spec_2,
                                 CreateSgxIdentityMatchSpec(options_2));
      if (options_1 == options_2) {
        EXPECT_THAT(match_spec_1, EqualsProto(match_spec_2));
      } else {
        EXPECT_THAT(match_spec_1, Not(EqualsProto(match_spec_2)));
      }
    }
  }
}

TEST(SgxIdentityUtilTest, CreateSgxIdentityExpectationSuccess) {
  // The self identity should be compatible with the default match spec.
  SgxIdentityMatchSpec match_spec;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      match_spec,
      CreateSgxIdentityMatchSpec(SgxIdentityMatchSpecOptions::DEFAULT));
  ASYLO_EXPECT_OK(CreateSgxIdentityExpectation(GetSelfSgxIdentity(),
                                               std::move(match_spec)));
}

TEST(SgxIdentityUtilTest, CreateSgxIdentityExpectationFailure) {
  // The empty identity should be incompatible with any strict match spec.
  SgxIdentity identity;
  SgxIdentityMatchSpec match_spec;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      match_spec,
      CreateSgxIdentityMatchSpec(SgxIdentityMatchSpecOptions::STRICT_LOCAL));
  EXPECT_THAT(CreateSgxIdentityExpectation(identity, match_spec),
              StatusIs(absl::StatusCode::kInvalidArgument));

  ASYLO_ASSERT_OK_AND_ASSIGN(
      match_spec,
      CreateSgxIdentityMatchSpec(SgxIdentityMatchSpecOptions::STRICT_REMOTE));
  EXPECT_THAT(CreateSgxIdentityExpectation(identity, match_spec),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(SgxIdentityUtilTest, CreateSgxIdentityExpectationFromOptions) {
  SgxIdentity identity = GetSelfSgxIdentity();

  SgxIdentityExpectation expectation_1;
  SgxIdentityMatchSpec match_spec;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      match_spec,
      CreateSgxIdentityMatchSpec(SgxIdentityMatchSpecOptions::DEFAULT));
  ASYLO_ASSERT_OK_AND_ASSIGN(
      expectation_1,
      CreateSgxIdentityExpectation(identity, std::move(match_spec)));

  SgxIdentityExpectation expectation_2;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      expectation_2, CreateSgxIdentityExpectation(
                         identity, SgxIdentityMatchSpecOptions::DEFAULT));

  EXPECT_THAT(expectation_1, EqualsProto(expectation_2))
      << sgx::FormatProto(expectation_1) << "\n"
      << sgx::FormatProto(expectation_2);
}

TEST(SgxIdentityUtilTest, ParseInvalidIdentityFailure) {
  EnclaveIdentity generic_identity;
  SgxIdentity identity;
  ASYLO_ASSERT_OK(
      sgx::SetRandomValidGenericIdentity(&generic_identity, &identity));

  generic_identity.set_identity("bad identity");
  EXPECT_THAT(ParseSgxIdentity(generic_identity),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(SgxIdentityUtilTest, ParseInvalidMatchSpecFailure) {
  EXPECT_THAT(ParseSgxIdentityMatchSpec("bad match spec"),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(SgxIdentityUtilTest, ParseInvalidExpectationFailure) {
  EnclaveIdentityExpectation generic_expectation;
  SgxIdentityExpectation expectation;
  ASYLO_ASSERT_OK(sgx::SetRandomValidGenericExpectation(&generic_expectation,
                                                        &expectation));

  generic_expectation.set_match_spec("bad match spec");
  EXPECT_THAT(ParseSgxIdentityExpectation(generic_expectation),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(SgxIdentityUtilTest, SerializeInvalidIdentityFailure) {
  SgxIdentity identity;
  EXPECT_THAT(SerializeSgxIdentity(identity),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(SgxIdentityUtilTest, SerializeInvalidMatchSpecFailure) {
  SgxIdentityMatchSpec match_spec;
  EXPECT_THAT(SerializeSgxIdentityMatchSpec(match_spec),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(SgxIdentityUtilTest, SerializeInvalidExpectationFailure) {
  SgxIdentityExpectation expectation;
  EXPECT_THAT(SerializeSgxIdentityExpectation(expectation),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(SgxIdentityUtilTest, SerializeAndParseIdentityEndToEnd) {
  SgxIdentity identity = sgx::GetRandomValidSgxIdentity();

  EnclaveIdentity serialized_identity;
  ASYLO_ASSERT_OK_AND_ASSIGN(serialized_identity,
                             SerializeSgxIdentity(identity));

  SgxIdentity parsed_identity;
  ASYLO_ASSERT_OK_AND_ASSIGN(parsed_identity,
                             ParseSgxIdentity(serialized_identity));

  EXPECT_TRUE(IsValidSgxIdentity(parsed_identity));
  EXPECT_THAT(parsed_identity, EqualsProto(identity))
      << sgx::FormatProto(parsed_identity) << "\n"
      << sgx::FormatProto(identity);
}

TEST(SgxIdentityUtilTest, SerializeAndParseMatchSpecEndToEnd) {
  SgxIdentityMatchSpec match_spec = sgx::GetRandomValidSgxMatchSpec();

  std::string serialized_match_spec;
  ASYLO_ASSERT_OK_AND_ASSIGN(serialized_match_spec,
                             SerializeSgxIdentityMatchSpec(match_spec));

  SgxIdentityMatchSpec parsed_match_spec;
  ASYLO_ASSERT_OK_AND_ASSIGN(parsed_match_spec,
                             ParseSgxIdentityMatchSpec(serialized_match_spec));

  EXPECT_TRUE(IsValidSgxIdentityMatchSpec(parsed_match_spec));
  EXPECT_THAT(parsed_match_spec, EqualsProto(match_spec))
      << sgx::FormatProto(parsed_match_spec) << "\n"
      << sgx::FormatProto(match_spec);
}

TEST(SgxIdentityUtilTest, SerializeAndParseExpectationEndToEnd) {
  SgxIdentityExpectation expectation = sgx::GetRandomValidSgxExpectation();

  EnclaveIdentityExpectation serialized_expectation;
  ASYLO_ASSERT_OK_AND_ASSIGN(serialized_expectation,
                             SerializeSgxIdentityExpectation(expectation));

  SgxIdentityExpectation parsed_expectation;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      parsed_expectation, ParseSgxIdentityExpectation(serialized_expectation));

  EXPECT_TRUE(IsValidSgxIdentityExpectation(parsed_expectation));
  EXPECT_THAT(parsed_expectation, EqualsProto(expectation))
      << sgx::FormatProto(parsed_expectation) << "\n"
      << sgx::FormatProto(expectation);
}

}  // namespace asylo
