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

#include "asylo/test/util/status_matchers.h"

#include <sstream>
#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/strings/str_cat.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace {

using ::testing::Eq;
using ::testing::Gt;
using ::testing::HasSubstr;
using ::testing::IsEmpty;
using ::testing::Lt;
using ::testing::Matcher;
using ::testing::Not;
using ::testing::SafeMatcherCast;
using ::testing::StringMatchResultListener;

// Returns the description of |matcher| as a matcher for MatcheeT.
template <typename MatcheeT, typename MatcherT>
std::string MatcherDescription(const MatcherT &matcher) {
  Matcher<const MatcheeT &> converted_matcher =
      SafeMatcherCast<const MatcheeT &>(matcher);

  std::stringstream description_stream;
  converted_matcher.DescribeTo(&description_stream);
  return description_stream.str();
}

// Returns the explanation of |matcher|'s match or failure to match with
// |matchee|.
template <typename MatcheeT, typename MatcherT>
std::string MatchExplanation(const MatcherT &matcher, const MatcheeT &value) {
  Matcher<const MatcheeT &> converted_matcher =
      SafeMatcherCast<const MatcheeT &>(matcher);

  StringMatchResultListener listener;
  converted_matcher.MatchAndExplain(value, &listener);
  return listener.str();
}

// Tests that IsOkAndHolds(value_matcher) matches an OK StatusOr<T> when the
// contained value matches value_matcher.
TEST(StatusMatchersTest, IsOkAndHoldsMatchesOkStatusWithMatchingValue) {
  const StatusOr<int> int_statusor = 5;
  const StatusOr<std::string> string_statusor = std::string("foobar");

  EXPECT_THAT(int_statusor, IsOkAndHolds(Eq(5)));
  EXPECT_THAT(int_statusor, IsOkAndHolds(Gt(2)));
  EXPECT_THAT(string_statusor, IsOkAndHolds(HasSubstr("oba")));
}

// Tests that IsOkAndHolds(some_value) matches an OK StatusOr<T> when the
// contained value equals some_value.
TEST(StatusMatchersTest, IsOkAndHoldsConvertsNonMatcherArgsToEqMatchers) {
  const StatusOr<int> int_statusor = 5;
  const StatusOr<std::string> string_statusor = std::string("foobar");

  EXPECT_THAT(int_statusor, IsOkAndHolds(5));
  EXPECT_THAT(string_statusor, IsOkAndHolds("foobar"));
}

// Tests that IsOkAndHolds(value_matcher) does not match a non-OK StatusOr<T>,
// regardless of the value of value_matcher.
TEST(StatusMatchersTest, IsOkAndHoldsDoesNotMatchNonOkStatus) {
  const StatusOr<int> non_ok_statusor =
      Status(error::GoogleError::INTERNAL, "some_error");

  EXPECT_THAT(non_ok_statusor, Not(IsOkAndHolds(Lt(3))));
  EXPECT_THAT(non_ok_statusor, Not(IsOkAndHolds(Eq(3))));
  EXPECT_THAT(non_ok_statusor, Not(IsOkAndHolds(Gt(3))));
}

// Tests that IsOkAndHolds(value_matcher) does not match an OK StatusOr<T> if
// the contained value does not match value_matcher.
TEST(StatusMatchersTest, IsOkAndHoldsDoesNotMatchIfValueMatcherFails) {
  const StatusOr<int> int_statusor = 5;
  const StatusOr<std::string> string_statusor = std::string("foobar");

  EXPECT_THAT(int_statusor, Not(IsOkAndHolds(Lt(4))));
  EXPECT_THAT(int_statusor, Not(IsOkAndHolds(Eq(7))));
  EXPECT_THAT(string_statusor, Not(IsOkAndHolds(HasSubstr("baz"))));
  EXPECT_THAT(string_statusor, Not(IsOkAndHolds(IsEmpty())));
}

// Tests that IsOkAndHolds(value_matcher) describes a successful matchee as
// being OK and matching value_matcher.
TEST(StatusMatchersTest,
     IsOkAndHoldsDescribesMatchAsOkAndMatchingValueMatcher) {
  EXPECT_EQ(MatcherDescription<StatusOr<int>>(IsOkAndHolds(Eq(5))),
            absl::StrCat("is OK and contains a value that ",
                         MatcherDescription<int>(Eq(5))));
  EXPECT_EQ(MatcherDescription<StatusOr<int>>(IsOkAndHolds(Lt(7))),
            absl::StrCat("is OK and contains a value that ",
                         MatcherDescription<int>(Lt(7))));
  EXPECT_EQ(
      MatcherDescription<StatusOr<std::string>>(IsOkAndHolds(HasSubstr("foo"))),
      absl::StrCat("is OK and contains a value that ",
                   MatcherDescription<std::string>(HasSubstr("foo"))));
}

// Tests that IsOkAndHolds(value_matcher) describes a failed matchee as being
// non-OK or not matching value_matcher.
TEST(StatusMatchersTest,
     IsOkAndHoldsDescribesNonMatchAsNonOkOrNotMatchingValueMatcher) {
  EXPECT_EQ(MatcherDescription<StatusOr<int>>(Not(IsOkAndHolds(Eq(5)))),
            absl::StrCat("is not OK or contains a value that ",
                         MatcherDescription<int>(Not(Eq(5)))));
  EXPECT_EQ(MatcherDescription<StatusOr<int>>(Not(IsOkAndHolds(Lt(7)))),
            absl::StrCat("is not OK or contains a value that ",
                         MatcherDescription<int>(Not(Lt(7)))));
  EXPECT_EQ(
      MatcherDescription<StatusOr<std::string>>(Not(IsOkAndHolds(HasSubstr("foo")))),
      absl::StrCat("is not OK or contains a value that ",
                   MatcherDescription<std::string>(Not(HasSubstr("foo")))));
}

// Tests that IsOkAndHolds() offers no explanation for a successful match.
TEST(StatusMatchersTest, IsOkAndHoldsDoesNotExplainSuccessfulMatch) {
  const std::vector<int> empty_vector;
  const StatusOr<std::vector<int>> matching_statusor = empty_vector;

  ASSERT_THAT(matching_statusor, IsOkAndHolds(IsEmpty()));
  EXPECT_EQ(MatchExplanation(IsOkAndHolds(IsEmpty()), matching_statusor), "");
}

// Tests that IsOkAndHolds() explains a failed match correctly.
TEST(StatusMatchersTest, IsOkAndHoldsExplainsNonMatchCorrectly) {
  const std::vector<int> non_empty_vector = {8, 6, 7, 5, 3, 0, 9};
  const StatusOr<std::vector<int>> non_ok_statusor =
      Status(error::GoogleError::INTERNAL, "some_error");
  const StatusOr<std::vector<int>> non_matching_statusor = non_empty_vector;

  ASSERT_THAT(non_ok_statusor, Not(IsOkAndHolds(IsEmpty())));
  EXPECT_EQ(MatchExplanation(IsOkAndHolds(IsEmpty()), non_ok_statusor),
            "which is not OK");

  ASSERT_THAT(non_matching_statusor, Not(IsOkAndHolds(IsEmpty())));
  EXPECT_EQ(MatchExplanation(IsOkAndHolds(IsEmpty()), non_matching_statusor),
            absl::StrCat("which contains a value ",
                         MatchExplanation(IsEmpty(), non_empty_vector)));
}

}  // namespace
}  // namespace asylo
