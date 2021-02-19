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

#include "asylo/identity/identity_expectation_matcher.h"

#include <string>

#include <google/protobuf/util/message_differencer.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/status/status.h"
#include "absl/strings/str_format.h"
#include "asylo/identity/delegating_identity_expectation_matcher.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/identity/named_identity_expectation_matcher.h"
#include "asylo/platform/common/static_map.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace {

using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::Not;

// Makes an identity description whose authority_type string is constructed
// based on the template parameter |C|.
template <char C>
EnclaveIdentityDescription MakeDescription() {
  EnclaveIdentityDescription description;
  description.set_identity_type(UNKNOWN_IDENTITY);
  description.set_authority_type(std::string(4, C));
  return description;
}

// Makes an identity whose description().authority_type() string is constructed
// based on the template parameter |C|.
template <char C>
EnclaveIdentity MakeIdentity(std::string id) {
  EnclaveIdentity identity;
  *identity.mutable_description() = MakeDescription<C>();
  identity.set_identity(std::move(id));
  return identity;
}

// Makes an expectation whose
// reference_identity().description().authority_type() string is constructed
// based on the template parameter |C|.
template <char C>
EnclaveIdentityExpectation MakeExpectation(std::string id) {
  EnclaveIdentityExpectation expectation;
  *expectation.mutable_reference_identity() = MakeIdentity<C>(std::move(id));
  return expectation;
}

// Matcher whose Description().authority_type() string is constructed based on
// the template parameter |C|, and which considers an identity to match an
// expectation if the identity simply equals the expectation's reference
// identity.
template <char C>
class TestMatcher final : public NamedIdentityExpectationMatcher {
 public:
  TestMatcher() = default;
  ~TestMatcher() override = default;

  EnclaveIdentityDescription Description() const override {
    return MakeDescription<C>();
  }

  StatusOr<bool> MatchAndExplain(const EnclaveIdentity &identity,
                                 const EnclaveIdentityExpectation &expectation,
                                 std::string *explanation) const override {
    const EnclaveIdentity &reference_identity =
        expectation.reference_identity();
    if (!::google::protobuf::util::MessageDifferencer::Equivalent(identity.description(),
                                                        Description()) ||
        !::google::protobuf::util::MessageDifferencer::Equivalent(
            reference_identity.description(), Description())) {
      return absl::InternalError("Incorrect description");
    }

    if (identity.identity() != reference_identity.identity()) {
      if (explanation != nullptr) {
        *explanation =
            absl::StrFormat("Identity %s does not match expected identity %s",
                            identity.identity(), reference_identity.identity());
      }
      return false;
    }
    return true;
  }
};

using TestMatcherA = TestMatcher<'A'>;
using TestMatcherB = TestMatcher<'B'>;

// Static registration of TestMatcher<'A'>.
SET_STATIC_MAP_VALUE_OF_DERIVED_TYPE(IdentityExpectationMatcherMap,
                                     TestMatcherA);

// Static registration of TestMatcher<'B'>.
SET_STATIC_MAP_VALUE_OF_DERIVED_TYPE(IdentityExpectationMatcherMap,
                                     TestMatcherB);

// Tests that identity and expectation of type 'A' match each other if their ID
// strings are the same.
TEST(IdentityExpectationMatcherTest, MatchIfDescriptionsAndIdentitiesMatch) {
  EnclaveIdentity identity = MakeIdentity<'A'>("foo");
  EnclaveIdentityExpectation expectation = MakeExpectation<'A'>("foo");

  std::string explanation;
  DelegatingIdentityExpectationMatcher matcher;
  EXPECT_THAT(matcher.MatchAndExplain(identity, expectation, &explanation),
              IsOkAndHolds(true));
  EXPECT_THAT(explanation, Eq(""));
}

// Tests that identity and expectation of type 'A' do not match each other if
// their ID strings are different.
TEST(IdentityExpectationMatcherTest, MatchFailsIfIdentityMatchFails) {
  EnclaveIdentity identity = MakeIdentity<'A'>("foo");
  EnclaveIdentityExpectation expectation = MakeExpectation<'A'>("bar");

  std::string explanation;
  DelegatingIdentityExpectationMatcher matcher;
  ASSERT_THAT(matcher.MatchAndExplain(identity, expectation, &explanation),
              IsOkAndHolds(false));
  EXPECT_THAT(explanation, HasSubstr("does not match expected identity"));
}

// Tests that identity of type 'A' does not match expectation of type 'B'. Since
// TestMatcherA and TestMatcherB are both registered in the static map, the
// MatchAndExplain() method of the delegating matcher returns false.
TEST(IdentityExpectationMatcherTest, MatchFailsIfDescriptionMatchFails) {
  EnclaveIdentity identity = MakeIdentity<'A'>("foo");
  EnclaveIdentityExpectation expectation = MakeExpectation<'B'>("foo");

  std::string explanation;
  DelegatingIdentityExpectationMatcher matcher;
  EXPECT_THAT(matcher.MatchAndExplain(identity, expectation, &explanation),
              IsOkAndHolds(false));
  EXPECT_THAT(explanation, HasSubstr("incompatible with reference identity"));
}

// Tests that identity of type 'C' does not match expectation of type 'A'.
// However, since TestMatcher<'C'> is not registered in the static map, the
// MatchAndExplain() method of the delegating matcher returns a non-ok status.
TEST(IdentityExpectationMatcherTest, MatchFailsIfIdentityDescriptionInvalid) {
  EnclaveIdentity identity = MakeIdentity<'C'>("foo");
  EnclaveIdentityExpectation expectation = MakeExpectation<'A'>("foo");

  DelegatingIdentityExpectationMatcher matcher;
  StatusOr<bool> match_result =
      matcher.MatchAndExplain(identity, expectation, /*explanation=*/nullptr);

  EXPECT_THAT(match_result, Not(IsOk()));
}

// Tests that identity of type 'A' does not match expectation of type 'C'.
// However, since TestMatcher<'C'> is not registered in the static map, the
// MatchAndExplain() method of the delegating matcher returns a non-ok status.
TEST(IdentityExpectationMatcherTest,
     MatchFailsIfExpectationDescriptionInvalid) {
  EnclaveIdentity identity = MakeIdentity<'A'>("foo");
  EnclaveIdentityExpectation expectation = MakeExpectation<'C'>("foo");

  DelegatingIdentityExpectationMatcher matcher;
  StatusOr<bool> match_result =
      matcher.MatchAndExplain(identity, expectation, /*explanation=*/nullptr);

  EXPECT_THAT(match_result, Not(IsOk()));
}

}  // namespace
}  // namespace asylo
