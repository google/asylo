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

#include "asylo/identity/sgx/code_identity_expectation_matcher.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/identity/identity.pb.h"
#include "asylo/identity/named_identity_expectation_matcher.h"
#include "asylo/identity/sgx/code_identity.pb.h"
#include "asylo/identity/sgx/code_identity_constants.h"
#include "asylo/identity/sgx/code_identity_test_util.h"
#include "asylo/test/util/status_matchers.h"

namespace asylo {
namespace sgx {
namespace {

using ::testing::Not;

// Tests that the CodeIdentityExpectationMatcher exists in the
// IdentityExpectationMatcher map.
TEST(CodeIdentityExpectationMatcherTest, MatcherExistsInStaticMap) {
  EnclaveIdentityDescription description;
  description.set_identity_type(CODE_IDENTITY);
  description.set_authority_type(kSgxAuthorizationAuthority);

  auto matcher_it = IdentityExpectationMatcherMap::GetValue(
      NamedIdentityExpectationMatcher::GetMatcherName(description)
          .ValueOrDie());
  ASSERT_NE(matcher_it, IdentityExpectationMatcherMap::value_end());
}

// Tests that the CodeIdentityExpectationMatcher has correct description.
TEST(CodeIdentityExpectationMatcherTest, MatcherCheckDescription) {
  CodeIdentityExpectationMatcher matcher;
  EXPECT_EQ(matcher.Description().identity_type(), CODE_IDENTITY);
  EXPECT_EQ(matcher.Description().authority_type(), kSgxAuthorizationAuthority);
}

// Tests that CodeIdentityExpectationMatcher correctly matches reference
// identity inside a valid code-identity expectation with that expectation.
TEST(CodeIdentityExpectationMatcherTest, MatcherPositive) {
  EnclaveIdentityExpectation expectation;
  CodeIdentityExpectation code_identity_expectation;
  ASSERT_THAT(SetRandomValidGenericExpectation(&expectation,
                                               &code_identity_expectation),
              IsOk());

  CodeIdentityExpectationMatcher matcher;
  StatusOr<bool> matcher_result =
      matcher.Match(expectation.reference_identity(), expectation);
  ASSERT_THAT(matcher_result, IsOk())
      << code_identity_expectation.ShortDebugString();
  EXPECT_TRUE(matcher_result.ValueOrDie())
      << code_identity_expectation.ShortDebugString();
}

// Tests that CodeIdentityExpectationMatcher returns a non-ok status when
// invoked with invalid code identity.
TEST(CodeIdentityExpectationMatcherTest, MatcherInvalidIdentity) {
  EnclaveIdentity identity;
  SetRandomInvalidGenericIdentity(&identity);

  EnclaveIdentityExpectation expectation;
  CodeIdentityExpectation code_identity_expectation;
  SetRandomValidGenericExpectation(&expectation, &code_identity_expectation);

  CodeIdentityExpectationMatcher matcher;
  EXPECT_THAT(matcher.Match(identity, expectation), Not(IsOk()))
      << identity.ShortDebugString()
      << code_identity_expectation.ShortDebugString();
}

// Tests that CodeIdentityExpectationMatcher returns a non-ok status when
// invoked with an invalid code-identity expectation.
TEST(CodeIdentityExpectationMatcherTest, MatcherInvalidExpectation) {
  EnclaveIdentity identity;
  CodeIdentity code_identity;
  SetRandomValidGenericIdentity(&identity, &code_identity);

  EnclaveIdentityExpectation expectation;
  ASSERT_THAT(SetRandomInvalidGenericExpectation(&expectation), IsOk());

  CodeIdentityExpectationMatcher matcher;
  ASSERT_THAT(matcher.Match(identity, expectation), Not(IsOk()))
      << code_identity.ShortDebugString() << expectation.ShortDebugString();
}

// Tests that CodeIdentityExpectationMatcher returns a non-ok status when
// invoked with invalid code identity and invalid code-identity expectation.
TEST(CodeIdentityExpectationMatcherTest, MatcherInvalidIdentityExpectation) {
  EnclaveIdentity identity;
  SetRandomInvalidGenericIdentity(&identity);

  EnclaveIdentityExpectation expectation;
  ASSERT_THAT(SetRandomInvalidGenericExpectation(&expectation), IsOk());

  CodeIdentityExpectationMatcher matcher;
  EXPECT_THAT(matcher.Match(identity, expectation), Not(IsOk()))
      << identity.ShortDebugString() << expectation.ShortDebugString();
}

}  // namespace
}  // namespace sgx
}  // namespace asylo
