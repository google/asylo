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

#include "asylo/identity/attestation/null/null_identity_expectation_matcher.h"

#include <string>

#include <gtest/gtest.h>
#include "asylo/identity/attestation/null/internal/null_identity_constants.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/identity/named_identity_expectation_matcher.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

namespace asylo {

namespace {

using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::Not;

// A test fixture is used to initialize state consistently.
class NullIdentityExpectationMatcherTest : public ::testing::Test {
 protected:
  NullIdentityExpectationMatcherTest() {
    null_identity_.mutable_description()->set_identity_type(NULL_IDENTITY);
    null_identity_.mutable_description()->set_authority_type(
        kNullAuthorizationAuthority);
    null_identity_.set_identity(kNullIdentity);
    *null_expectation_.mutable_reference_identity() = null_identity_;

    non_null_identity_.mutable_description()->set_identity_type(CODE_IDENTITY);
    *non_null_expectation_.mutable_reference_identity() = non_null_identity_;
  }

  EnclaveIdentity null_identity_;
  EnclaveIdentity non_null_identity_;
  EnclaveIdentityExpectation null_expectation_;
  EnclaveIdentityExpectation non_null_expectation_;
};

// Tests that the NullIdentityExpectationMatcher exists in the
// IdentityExpectationMatchers' map.
TEST_F(NullIdentityExpectationMatcherTest, MatcherExistsInStaticMap) {
  auto matcher_it = IdentityExpectationMatcherMap::GetValue(
      NamedIdentityExpectationMatcher::GetMatcherName(
          null_identity_.description())
          .value());
  ASSERT_NE(matcher_it, IdentityExpectationMatcherMap::value_end());
}

// Tests that the NullIdentityExpectationMatcher has the correct description.
TEST_F(NullIdentityExpectationMatcherTest, DescriptionCorrectness) {
  NullIdentityExpectationMatcher matcher;
  EXPECT_EQ(matcher.Description().identity_type(), NULL_IDENTITY);
  EXPECT_EQ(matcher.Description().authority_type(),
            kNullAuthorizationAuthority);
}

// Tests that null_identity_ matches null_expectation_.
TEST_F(NullIdentityExpectationMatcherTest, MatchNullIdentityToNullExpectation) {
  NullIdentityExpectationMatcher matcher;
  std::string explanation;
  EXPECT_THAT(
      matcher.MatchAndExplain(null_identity_, null_expectation_, &explanation),
      IsOkAndHolds(true));
  EXPECT_THAT(explanation, Eq(""));
}

// Tests that an identity with the null identity description, but an incorrect
// identity string, fails to match against a null identity expectation.
TEST_F(NullIdentityExpectationMatcherTest,
       MatchAndExplainMismatchedIdentityFails) {
  EnclaveIdentity bad_null_identity = null_identity_;
  bad_null_identity.set_identity("foobar");

  std::string explanation;
  NullIdentityExpectationMatcher matcher;
  ASSERT_THAT(matcher.MatchAndExplain(bad_null_identity, null_expectation_,
                                      &explanation),
              IsOkAndHolds(false));
  EXPECT_THAT(explanation, HasSubstr("foobar does not match"));
}

// Tests that attempt to match non_null_expectation_ using
// NullIdentityExpectationMatcher results in a failure.
TEST_F(NullIdentityExpectationMatcherTest,
       MatchNullIdentityToNonNullExpectation) {
  NullIdentityExpectationMatcher matcher;
  std::string explanation;
  ASSERT_THAT(matcher.MatchAndExplain(null_identity_, non_null_expectation_,
                                      &explanation),
              Not(IsOk()));
  EXPECT_THAT(explanation, Eq(""));
}

// Tests that an attempt to match non_null_identity_ using
// NullIdentityExpectationMatcher results in a failure.
TEST_F(NullIdentityExpectationMatcherTest,
       MatchNonNullIdentityNullExpectation) {
  NullIdentityExpectationMatcher matcher;
  std::string explanation;
  ASSERT_THAT(matcher.MatchAndExplain(null_identity_, non_null_expectation_,
                                      &explanation),
              Not(IsOk()));
  EXPECT_THAT(explanation, Eq(""));
}

}  // namespace
}  // namespace asylo
