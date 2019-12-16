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
#include <gtest/gtest-spi.h>
#include <gtest/gtest.h>
#include "absl/strings/str_cat.h"
#include "asylo/util/status.h"
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

TEST(StatusMatchersTest, IsOkMatchesStatus) {
  EXPECT_THAT(Status::OkStatus(), IsOk());
  EXPECT_THAT(Status(error::GoogleError::UNKNOWN, "error"), Not(IsOk()));
}

TEST(StatusMatchersTest, IsOkMatchesStatusOr) {
  EXPECT_THAT(StatusOr<int>(42), IsOk());
  EXPECT_THAT(
      StatusOr<std::string>(Status(error::GoogleError::UNKNOWN, "error")),
      Not(IsOk()));
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
      MatcherDescription<StatusOr<std::string>>(
          Not(IsOkAndHolds(HasSubstr("foo")))),
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

// Tests that StatusIs matches Status objects correctly.
TEST(StatusMatchersTest, StatusIsMatchesStatusObjects) {
  const std::string kMessage = "something very bad!";
  const std::string kWrongMessage = "this is not the same error";

  constexpr auto kErrorCode = error::GoogleError::INVALID_ARGUMENT;
  constexpr auto kWrongErrorCode = error::GoogleError::INTERNAL;
  const Status kError(kErrorCode, kMessage);

  EXPECT_THAT(kError, StatusIs(kErrorCode));
  EXPECT_THAT(kError, StatusIs(kErrorCode, kMessage));
  EXPECT_THAT(kError, Not(StatusIs(kWrongErrorCode)));
  EXPECT_THAT(kError, Not(StatusIs(kErrorCode, kWrongMessage)));

  EXPECT_NONFATAL_FAILURE(EXPECT_THAT(kError, StatusIs(kWrongErrorCode)),
                          "INTERNAL");
  EXPECT_NONFATAL_FAILURE(
      EXPECT_THAT(kError, StatusIs(kErrorCode, kWrongMessage)), kWrongMessage);
  EXPECT_NONFATAL_FAILURE(EXPECT_THAT(kError, Not(StatusIs(kErrorCode))),
                          "does not match error code INVALID_ARGUMENT");
  EXPECT_NONFATAL_FAILURE(
      EXPECT_THAT(kError, Not(StatusIs(kErrorCode, kMessage))), kMessage);
}

// Tests that StatusIs matches StatusOr objects correctly.
TEST(StatusMatchersTest, StatusIsMatchesStatusOrObjects) {
  const std::string kMessage = "oops";
  const std::string kWrongMessage = "different error message";
  constexpr auto kErrorCode = error::GoogleError::FAILED_PRECONDITION;
  constexpr auto kWrongErrorCode = error::GoogleError::INTERNAL;
  const StatusOr<int> kFailure = Status(kErrorCode, kMessage);

  EXPECT_THAT(kFailure, StatusIs(kErrorCode));
  EXPECT_THAT(kFailure, StatusIs(kErrorCode, kMessage));

  EXPECT_NONFATAL_FAILURE(EXPECT_THAT(kFailure, StatusIs(kWrongErrorCode)),
                          "INTERNAL");
  EXPECT_NONFATAL_FAILURE(
      EXPECT_THAT(kFailure, StatusIs(kErrorCode, kWrongMessage)),
      kWrongMessage);
  EXPECT_NONFATAL_FAILURE(EXPECT_THAT(kFailure, Not(StatusIs(kErrorCode))),
                          "does not match error code FAILED_PRECONDITION");
  EXPECT_NONFATAL_FAILURE(
      EXPECT_THAT(kFailure, Not(StatusIs(kErrorCode, kMessage))), kMessage);

  const StatusOr<int> kSuccess = 1;
  EXPECT_THAT(kSuccess, StatusIs(error::GoogleError::OK));
  EXPECT_THAT(kSuccess, StatusIs(error::GoogleError::OK, ""));
  EXPECT_THAT(kSuccess, Not(StatusIs(kErrorCode)));
  EXPECT_THAT(kSuccess, Not(StatusIs(error::GoogleError::OK, kMessage)));

  EXPECT_NONFATAL_FAILURE(EXPECT_THAT(kSuccess, StatusIs(kErrorCode)),
                          "FAILED_PRECONDITION");
  EXPECT_NONFATAL_FAILURE(
      EXPECT_THAT(kSuccess, StatusIs(error::GoogleError::OK, kMessage)),
      kMessage);
  EXPECT_NONFATAL_FAILURE(
      EXPECT_THAT(kSuccess, Not(StatusIs(error::GoogleError::OK))),
      "does not match error code OK");
  EXPECT_NONFATAL_FAILURE(
      EXPECT_THAT(kSuccess, Not(StatusIs(error::GoogleError::OK, ""))),
      "does not have an error message");
}

// Tests that StatusIs only matches a Status or StatusOr if its message matches
// the message matcher.
TEST(StatusMatchersTest, StatusIsUsesMessageMatcherToCheckMessage) {
  constexpr auto kErrorCode = error::GoogleError::FAILED_PRECONDITION;

  EXPECT_THAT(Status(kErrorCode, "Foobar"),
              StatusIs(kErrorCode, HasSubstr("Foo")));
  EXPECT_THAT(StatusOr<int>(Status(kErrorCode, "Foobar")),
              StatusIs(kErrorCode, HasSubstr("Foo")));
  EXPECT_THAT(Status(kErrorCode, ""), StatusIs(kErrorCode, IsEmpty()));
  EXPECT_THAT(StatusOr<int>(Status(kErrorCode, "")),
              StatusIs(kErrorCode, IsEmpty()));

  EXPECT_NONFATAL_FAILURE(EXPECT_THAT(Status(kErrorCode, "Barbaz"),
                                      StatusIs(kErrorCode, HasSubstr("Foo"))),
                          "which has an error message");
  EXPECT_NONFATAL_FAILURE(
      EXPECT_THAT(StatusOr<int>(Status(kErrorCode, "Barbaz")),
                  StatusIs(kErrorCode, HasSubstr("Foo"))),
      "which has an error message");
  EXPECT_NONFATAL_FAILURE(EXPECT_THAT(Status(kErrorCode, "Barbaz"),
                                      StatusIs(kErrorCode, IsEmpty())),
                          "which has an error message");
  EXPECT_NONFATAL_FAILURE(
      EXPECT_THAT(StatusOr<int>(Status(kErrorCode, "Barbaz")),
                  StatusIs(kErrorCode, IsEmpty())),
      "which has an error message");
}

}  // namespace
}  // namespace asylo
