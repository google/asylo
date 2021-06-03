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

#include "asylo/identity/platform/sgx/sgx_identity_expectation_matcher.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/identity/descriptions.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/identity/named_identity_expectation_matcher.h"
#include "asylo/identity/platform/sgx/code_identity.pb.h"
#include "asylo/identity/platform/sgx/internal/code_identity_constants.h"
#include "asylo/identity/platform/sgx/internal/proto_format.h"
#include "asylo/identity/platform/sgx/internal/sgx_identity_test_util.h"
#include "asylo/identity/platform/sgx/internal/sgx_identity_util_internal.h"
#include "asylo/identity/platform/sgx/machine_configuration.pb.h"
#include "asylo/identity/platform/sgx/sgx_identity.pb.h"
#include "asylo/test/util/status_matchers.h"

namespace asylo {
namespace {

using ::testing::Eq;
using ::testing::IsEmpty;
using ::testing::Not;

// Tests that the SgxIdentityExpectationMatcher exists in the
// IdentityExpectationMatcher map.
TEST(SgxIdentityExpectationMatcherTest, MatcherExistsInStaticMap) {
  EnclaveIdentityDescription description;
  SetSgxIdentityDescription(&description);

  auto matcher_it = IdentityExpectationMatcherMap::GetValue(
      NamedIdentityExpectationMatcher::GetMatcherName(description).value());
  ASSERT_NE(matcher_it, IdentityExpectationMatcherMap::value_end());
}

// Tests that the SgxIdentityExpectationMatcher has correct description.
TEST(SgxIdentityExpectationMatcherTest, MatcherCheckDescription) {
  SgxIdentityExpectationMatcher matcher;
  EXPECT_EQ(matcher.Description().identity_type(), CODE_IDENTITY);
  EXPECT_EQ(matcher.Description().authority_type(),
            sgx::kSgxAuthorizationAuthority);
}

// Tests that SgxIdentityExpectationMatcher correctly matches reference
// identity inside a valid SGX identity expectation with that expectation.
TEST(SgxIdentityExpectationMatcherTest, MatcherPositive) {
  EnclaveIdentityExpectation expectation;
  SgxIdentityExpectation sgx_identity_expectation;
  ASSERT_THAT(sgx::SetRandomValidGenericExpectation(&expectation,
                                                    &sgx_identity_expectation),
              IsOk());

  SgxIdentityExpectationMatcher matcher;
  std::string explanation;
  StatusOr<bool> matcher_result = matcher.MatchAndExplain(
      expectation.reference_identity(), expectation, &explanation);
  ASSERT_THAT(matcher_result, IsOk())
      << sgx::FormatProto(sgx_identity_expectation);
  EXPECT_TRUE(matcher_result.value())
      << sgx::FormatProto(sgx_identity_expectation);
  EXPECT_THAT(explanation, Eq(""));
}

// Tests that when an SgxIdentityExpectationMatcher returns false it populates
// the explanation, and does not populate the explanation when it returns true.
TEST(SgxIdentityExpectationMatcherTest, MatchAndExplain) {
  EnclaveIdentityExpectation expectation;
  SgxIdentityExpectation sgx_identity_expectation;
  ASYLO_ASSERT_OK(sgx::SetRandomValidGenericExpectation(
      &expectation, &sgx_identity_expectation));

  SgxIdentity sgx_identity = sgx::GetRandomValidSgxIdentityWithConstraints(
      /*mrenclave_constraint=*/{true}, /*mrsigner_constraint=*/{true},
      /*cpu_svn_constraint=*/{true}, /*sgx_type_constraint=*/{true});

  EnclaveIdentity identity;
  ASYLO_ASSERT_OK(sgx::SerializeSgxIdentity(sgx_identity, &identity));

  SgxIdentityExpectationMatcher matcher;
  std::string explanation;

  auto result = matcher.MatchAndExplain(identity, expectation, &explanation);
  ASYLO_ASSERT_OK(result.status());

  if (result.value()) {
    EXPECT_THAT(explanation, IsEmpty());
  } else {
    EXPECT_THAT(explanation, Not(IsEmpty()));
  }
}

// Tests that SgxIdentityExpectationMatcher returns a non-OK status when
// invoked with invalid SGX identity.
TEST(SgxIdentityExpectationMatcherTest, MatchInvalidIdentity) {
  EnclaveIdentity identity;
  sgx::SetRandomInvalidGenericIdentity(&identity);

  EnclaveIdentityExpectation expectation;
  SgxIdentityExpectation sgx_identity_expectation;
  sgx::SetRandomValidGenericExpectation(&expectation,
                                        &sgx_identity_expectation);

  SgxIdentityExpectationMatcher matcher;
  EXPECT_THAT(
      matcher.MatchAndExplain(identity, expectation, /*explanation=*/nullptr),
      Not(IsOk()))
      << sgx::FormatProto(identity)
      << sgx::FormatProto(sgx_identity_expectation);
}

// Tests that SgxIdentityExpectationMatcher returns a non-OK status when
// invoked with an invalid SGX identity expectation.
TEST(SgxIdentityExpectationMatcherTest, MatchInvalidExpectation) {
  EnclaveIdentity identity;
  SgxIdentity sgx_identity;
  sgx::SetRandomValidGenericIdentity(&identity, &sgx_identity);

  EnclaveIdentityExpectation expectation;
  ASSERT_THAT(sgx::SetRandomInvalidGenericExpectation(&expectation), IsOk());

  SgxIdentityExpectationMatcher matcher;
  ASSERT_THAT(
      matcher.MatchAndExplain(identity, expectation, /*explanation=*/nullptr),
      Not(IsOk()))
      << sgx::FormatProto(sgx_identity) << sgx::FormatProto(expectation);
}

// Tests that SgxIdentityExpectationMatcher returns a non-OK status when
// invoked with invalid code identity and invalid SGX identity expectation.
TEST(SgxIdentityExpectationMatcherTest, MatchInvalidIdentityExpectation) {
  EnclaveIdentity identity;
  sgx::SetRandomInvalidGenericIdentity(&identity);

  EnclaveIdentityExpectation expectation;
  ASYLO_ASSERT_OK(sgx::SetRandomInvalidGenericExpectation(&expectation));

  SgxIdentityExpectationMatcher matcher;
  EXPECT_THAT(
      matcher.MatchAndExplain(identity, expectation, /*explanation=*/nullptr),
      Not(IsOk()))
      << sgx::FormatProto(identity) << sgx::FormatProto(expectation);
}

}  // namespace
}  // namespace asylo
