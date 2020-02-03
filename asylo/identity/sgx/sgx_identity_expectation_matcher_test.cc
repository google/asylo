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

#include "asylo/identity/sgx/sgx_identity_expectation_matcher.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/identity/descriptions.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/identity/named_identity_expectation_matcher.h"
#include "asylo/identity/platform/sgx/code_identity.pb.h"
#include "asylo/identity/platform/sgx/machine_configuration.pb.h"
#include "asylo/identity/platform/sgx/sgx_identity.pb.h"
#include "asylo/identity/sgx/code_identity_constants.h"
#include "asylo/identity/sgx/proto_format.h"
#include "asylo/identity/sgx/sgx_identity_test_util.h"
#include "asylo/identity/sgx/sgx_identity_util_internal.h"
#include "asylo/test/util/status_matchers.h"

namespace asylo {
namespace {

using ::testing::IsEmpty;
using ::testing::Not;

// Tests that the SgxIdentityExpectationMatcher exists in the
// IdentityExpectationMatcher map.
TEST(SgxIdentityExpectationMatcherTest, MatcherExistsInStaticMap) {
  EnclaveIdentityDescription description;
  SetSgxIdentityDescription(&description);

  auto matcher_it = IdentityExpectationMatcherMap::GetValue(
      NamedIdentityExpectationMatcher::GetMatcherName(description)
          .ValueOrDie());
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
  StatusOr<bool> matcher_result =
      matcher.Match(expectation.reference_identity(), expectation);
  ASSERT_THAT(matcher_result, IsOk())
      << sgx::FormatProto(sgx_identity_expectation);
  EXPECT_TRUE(matcher_result.ValueOrDie())
      << sgx::FormatProto(sgx_identity_expectation);
}

TEST(SgxIdentityExpectationMatcherTest, MatcherLegacyExpectationPositive) {
  EnclaveIdentityExpectation expectation;
  SgxIdentityExpectation sgx_identity_expectation;
  ASYLO_ASSERT_OK(sgx::SetRandomValidLegacyGenericExpectation(
      &expectation, &sgx_identity_expectation));

  SgxIdentityExpectationMatcher matcher;
  StatusOr<bool> matcher_result =
      matcher.Match(expectation.reference_identity(), expectation);
  ASSERT_THAT(matcher_result, IsOkAndHolds(true))
      << sgx::FormatProto(sgx_identity_expectation);
}

// Tests that SgxIdentityExpectationMatcher correctly matches a legacy identity
// when the expectation itself is not a legacy expectation, given that the
// expectation does not expect anything with respect to non-legacy fields.
TEST(SgxIdentityExpectationMatcherTest,
     MatchLegacyIdentityNonLegacyExpectationSuccess) {
  EnclaveIdentityExpectation expectation;
  SgxIdentityExpectation sgx_identity_expectation;
  ASSERT_THAT(sgx::SetRandomValidGenericExpectation(&expectation,
                                                    &sgx_identity_expectation),
              IsOk());

  // Backfill the expectation with a legacy identity.
  EnclaveIdentity identity;
  ASYLO_ASSERT_OK(sgx::SerializeSgxIdentity(
      sgx_identity_expectation.reference_identity().code_identity(),
      &identity));
  ASSERT_FALSE(identity.has_version());

  // Clear the MachineConfiguration fields of the expectation's match spec,
  // since the legacy identity will never match the expectation identity for
  // these fields.
  SgxIdentityMatchSpec *match_spec =
      sgx_identity_expectation.mutable_match_spec();
  sgx::MachineConfigurationMatchSpec *machine_config_match_spec =
      match_spec->mutable_machine_configuration_match_spec();
  machine_config_match_spec->set_is_cpu_svn_match_required(false);
  machine_config_match_spec->set_is_sgx_type_match_required(false);

  ASYLO_ASSERT_OK(sgx::SerializeSgxMatchSpec(*match_spec,
                                             expectation.mutable_match_spec()));

  SgxIdentity parsed_identity;
  ASYLO_ASSERT_OK(sgx::ParseSgxIdentity(identity, &parsed_identity));

  SgxIdentityExpectationMatcher matcher;
  StatusOr<bool> matcher_result = matcher.Match(identity, expectation);
  ASSERT_THAT(matcher_result, IsOk())
      << sgx::FormatProto(parsed_identity)
      << sgx::FormatProto(sgx_identity_expectation);
  EXPECT_TRUE(matcher_result.ValueOrDie())
      << sgx::FormatProto(parsed_identity)
      << sgx::FormatProto(sgx_identity_expectation);
}

// Tests that SgxIdentityExpectationMatcher will fail to evaluate a match for
// any legacy identity when the expectation itself is not a legacy expectation,
// given that at least one non-legacy field is set to "expected".
TEST(SgxIdentityExpectationMatcherTest,
     MatchLegacyIdentityNonLegacyExpectationIncompatible) {
  EnclaveIdentityExpectation expectation;
  SgxIdentityExpectation sgx_identity_expectation;
  ASSERT_THAT(sgx::SetRandomValidGenericExpectation(&expectation,
                                                    &sgx_identity_expectation),
              IsOk());

  // Backfill the expectation with a legacy identity.
  EnclaveIdentity identity;
  ASYLO_ASSERT_OK(sgx::SerializeSgxIdentity(
      sgx_identity_expectation.reference_identity().code_identity(),
      &identity));
  ASSERT_FALSE(identity.has_version());

  for (int i = 0;
       i < sgx::MachineConfigurationMatchSpec::GetDescriptor()->field_count();
       ++i) {
    SgxIdentityMatchSpec *match_spec =
        sgx_identity_expectation.mutable_match_spec();
    sgx::MachineConfigurationMatchSpec *machine_config_match_spec =
        match_spec->mutable_machine_configuration_match_spec();
    machine_config_match_spec->set_is_cpu_svn_match_required(i == 0);
    machine_config_match_spec->set_is_sgx_type_match_required(i == 1);

    ASYLO_ASSERT_OK(sgx::SerializeSgxMatchSpec(
        *match_spec, expectation.mutable_match_spec()));

    SgxIdentity parsed_identity;
    ASYLO_ASSERT_OK(sgx::ParseSgxIdentity(identity, &parsed_identity));

    SgxIdentityExpectationMatcher matcher;
    StatusOr<bool> matcher_result = matcher.Match(identity, expectation);
    ASSERT_THAT(matcher_result, Not(IsOk()))
        << sgx::FormatProto(parsed_identity)
        << sgx::FormatProto(sgx_identity_expectation);
  }
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

  if (result.ValueOrDie()) {
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
  EXPECT_THAT(matcher.Match(identity, expectation), Not(IsOk()))
      << sgx::FormatProto(identity)
      << sgx::FormatProto(sgx_identity_expectation);
}

TEST(SgxIdentityExpectationMatcherTest, MatchLegacyInvalidIdentity) {
  EnclaveIdentity identity;
  sgx::SetRandomInvalidGenericIdentity(&identity);

  EnclaveIdentityExpectation expectation;
  SgxIdentityExpectation sgx_identity_expectation;
  ASYLO_ASSERT_OK(sgx::SetRandomValidLegacyGenericExpectation(
      &expectation, &sgx_identity_expectation));

  SgxIdentityExpectationMatcher matcher;
  EXPECT_THAT(matcher.Match(identity, expectation), Not(IsOk()))
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
  ASSERT_THAT(matcher.Match(identity, expectation), Not(IsOk()))
      << sgx::FormatProto(sgx_identity) << sgx::FormatProto(expectation);
}

TEST(SgxIdentityExpectationMatcherTest, MatcherLegacyInvalidExpectation) {
  EnclaveIdentity identity;
  SgxIdentity sgx_identity;
  sgx::SetRandomValidLegacyGenericIdentity(&identity, &sgx_identity);

  EnclaveIdentityExpectation expectation;
  SgxIdentityExpectation sgx_identity_expectation;
  ASYLO_ASSERT_OK(sgx::SetRandomInvalidGenericExpectation(&expectation));

  SgxIdentityExpectationMatcher matcher;
  ASSERT_THAT(matcher.Match(identity, expectation), Not(IsOk()))
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
  EXPECT_THAT(matcher.Match(identity, expectation), Not(IsOk()))
      << sgx::FormatProto(identity) << sgx::FormatProto(expectation);
}

}  // namespace
}  // namespace asylo
