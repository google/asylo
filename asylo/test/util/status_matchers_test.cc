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
#include <utility>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest-spi.h>
#include <gtest/gtest.h>
#include "absl/status/status.h"
#include "absl/status/statusor.h"
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
using ::testing::Test;
using ::testing::Types;

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

// A typed test fixture for testing status matchers. Each specialization must
// expose four type aliases:
//
//   * StatusType: a Status-like type
//   * StatusOrInt: a type like StatusOr<int>
//   * StatusOrString: a type like StatusOr<std::string>
//   * StatusOrVectorInt: a type like StatusOr<std::vector<int>>
template <typename StatusT>
class StatusMatchersTest;

template <>
class StatusMatchersTest<Status> : public Test {
 public:
  using StatusType = Status;
  using StatusOrInt = StatusOr<int>;
  using StatusOrString = StatusOr<std::string>;
  using StatusOrVectorInt = StatusOr<std::vector<int>>;
};

template <>
class StatusMatchersTest<absl::Status> : public Test {
 public:
  using StatusType = absl::Status;
  using StatusOrInt = absl::StatusOr<int>;
  using StatusOrString = absl::StatusOr<std::string>;
  using StatusOrVectorInt = absl::StatusOr<std::vector<int>>;
};

using StatusTypes = Types<Status, absl::Status>;
TYPED_TEST_SUITE(StatusMatchersTest, StatusTypes);

TYPED_TEST(StatusMatchersTest, IsOkMatchesStatus) {
  using StatusType = typename TestFixture::StatusType;

  EXPECT_THAT(StatusType(), IsOk());
  EXPECT_THAT(StatusType(absl::StatusCode::kUnknown, "error"), Not(IsOk()));
}

TYPED_TEST(StatusMatchersTest, IsOkMatchesStatusOr) {
  using StatusType = typename TestFixture::StatusType;
  using StatusOrInt = typename TestFixture::StatusOrInt;
  using StatusOrString = typename TestFixture::StatusOrString;

  EXPECT_THAT(StatusOrInt(42), IsOk());
  EXPECT_THAT(StatusOrString(StatusType(absl::StatusCode::kUnknown, "error")),
              Not(IsOk()));
}

// Tests that IsOkAndHolds(value_matcher) matches an OK StatusOr<T> when the
// contained value matches value_matcher.
TYPED_TEST(StatusMatchersTest, IsOkAndHoldsMatchesOkStatusWithMatchingValue) {
  using StatusOrInt = typename TestFixture::StatusOrInt;
  using StatusOrString = typename TestFixture::StatusOrString;

  const StatusOrInt int_statusor = 5;
  const StatusOrString string_statusor = std::string("foobar");

  EXPECT_THAT(int_statusor, IsOkAndHolds(Eq(5)));
  EXPECT_THAT(int_statusor, IsOkAndHolds(Gt(2)));
  EXPECT_THAT(string_statusor, IsOkAndHolds(HasSubstr("oba")));
}

// Tests that IsOkAndHolds(some_value) matches an OK StatusOr<T> when the
// contained value equals some_value.
TYPED_TEST(StatusMatchersTest, IsOkAndHoldsConvertsNonMatcherArgsToEqMatchers) {
  using StatusOrInt = typename TestFixture::StatusOrInt;
  using StatusOrString = typename TestFixture::StatusOrString;

  const StatusOrInt int_statusor = 5;
  const StatusOrString string_statusor = std::string("foobar");

  EXPECT_THAT(int_statusor, IsOkAndHolds(5));
  EXPECT_THAT(string_statusor, IsOkAndHolds("foobar"));
}

// Tests that IsOkAndHolds(value_matcher) does not match a non-OK StatusOr<T>,
// regardless of the value of value_matcher.
TYPED_TEST(StatusMatchersTest, IsOkAndHoldsDoesNotMatchNonOkStatus) {
  using StatusType = typename TestFixture::StatusType;
  using StatusOrInt = typename TestFixture::StatusOrInt;

  const StatusOrInt non_ok_statusor =
      StatusType(absl::StatusCode::kInternal, "some_error");

  EXPECT_THAT(non_ok_statusor, Not(IsOkAndHolds(Lt(3))));
  EXPECT_THAT(non_ok_statusor, Not(IsOkAndHolds(Eq(3))));
  EXPECT_THAT(non_ok_statusor, Not(IsOkAndHolds(Gt(3))));
}

// Tests that IsOkAndHolds(value_matcher) does not match an OK StatusOr<T> if
// the contained value does not match value_matcher.
TYPED_TEST(StatusMatchersTest, IsOkAndHoldsDoesNotMatchIfValueMatcherFails) {
  using StatusOrInt = typename TestFixture::StatusOrInt;
  using StatusOrString = typename TestFixture::StatusOrString;

  const StatusOrInt int_statusor = 5;
  const StatusOrString string_statusor = std::string("foobar");

  EXPECT_THAT(int_statusor, Not(IsOkAndHolds(Lt(4))));
  EXPECT_THAT(int_statusor, Not(IsOkAndHolds(Eq(7))));
  EXPECT_THAT(string_statusor, Not(IsOkAndHolds(HasSubstr("baz"))));
  EXPECT_THAT(string_statusor, Not(IsOkAndHolds(IsEmpty())));
}

// Tests that IsOkAndHolds(value_matcher) describes a successful matchee as
// being OK and matching value_matcher.
TYPED_TEST(StatusMatchersTest,
           IsOkAndHoldsDescribesMatchAsOkAndMatchingValueMatcher) {
  using StatusOrInt = typename TestFixture::StatusOrInt;
  using StatusOrString = typename TestFixture::StatusOrString;

  EXPECT_EQ(MatcherDescription<StatusOrInt>(IsOkAndHolds(Eq(5))),
            absl::StrCat("is OK and contains a value that ",
                         MatcherDescription<int>(Eq(5))));
  EXPECT_EQ(MatcherDescription<StatusOrInt>(IsOkAndHolds(Lt(7))),
            absl::StrCat("is OK and contains a value that ",
                         MatcherDescription<int>(Lt(7))));
  EXPECT_EQ(MatcherDescription<StatusOrString>(IsOkAndHolds(HasSubstr("foo"))),
            absl::StrCat("is OK and contains a value that ",
                         MatcherDescription<std::string>(HasSubstr("foo"))));
}

// Tests that IsOkAndHolds(value_matcher) describes a failed matchee as being
// non-OK or not matching value_matcher.
TYPED_TEST(StatusMatchersTest,
           IsOkAndHoldsDescribesNonMatchAsNonOkOrNotMatchingValueMatcher) {
  using StatusOrInt = typename TestFixture::StatusOrInt;
  using StatusOrString = typename TestFixture::StatusOrString;

  EXPECT_EQ(MatcherDescription<StatusOrInt>(Not(IsOkAndHolds(Eq(5)))),
            absl::StrCat("is not OK or contains a value that ",
                         MatcherDescription<int>(Not(Eq(5)))));
  EXPECT_EQ(MatcherDescription<StatusOrInt>(Not(IsOkAndHolds(Lt(7)))),
            absl::StrCat("is not OK or contains a value that ",
                         MatcherDescription<int>(Not(Lt(7)))));
  EXPECT_EQ(
      MatcherDescription<StatusOrString>(Not(IsOkAndHolds(HasSubstr("foo")))),
      absl::StrCat("is not OK or contains a value that ",
                   MatcherDescription<std::string>(Not(HasSubstr("foo")))));
}

// Tests that IsOkAndHolds() offers no explanation for a successful match.
TYPED_TEST(StatusMatchersTest, IsOkAndHoldsDoesNotExplainSuccessfulMatch) {
  using StatusOrVectorInt = typename TestFixture::StatusOrVectorInt;

  const std::vector<int> empty_vector;
  const StatusOrVectorInt matching_statusor = empty_vector;

  ASSERT_THAT(matching_statusor, IsOkAndHolds(IsEmpty()));
  EXPECT_EQ(MatchExplanation(IsOkAndHolds(IsEmpty()), matching_statusor), "");
}

// Tests that IsOkAndHolds() explains a failed match correctly.
TYPED_TEST(StatusMatchersTest, IsOkAndHoldsExplainsNonMatchCorrectly) {
  using StatusType = typename TestFixture::StatusType;
  using StatusOrVectorInt = typename TestFixture::StatusOrVectorInt;

  const std::vector<int> non_empty_vector = {8, 6, 7, 5, 3, 0, 9};
  const StatusOrVectorInt non_ok_statusor =
      StatusType(absl::StatusCode::kInternal, "some_error");
  const StatusOrVectorInt non_matching_statusor = non_empty_vector;

  ASSERT_THAT(non_ok_statusor, Not(IsOkAndHolds(IsEmpty())));
  EXPECT_EQ(MatchExplanation(IsOkAndHolds(IsEmpty()), non_ok_statusor),
            "which is not OK");

  ASSERT_THAT(non_matching_statusor, Not(IsOkAndHolds(IsEmpty())));
  EXPECT_EQ(MatchExplanation(IsOkAndHolds(IsEmpty()), non_matching_statusor),
            absl::StrCat("which contains a value ",
                         MatchExplanation(IsEmpty(), non_empty_vector)));
}

// Tests that StatusIs matches Status objects correctly.
TYPED_TEST(StatusMatchersTest, StatusIsMatchesStatusObjects) {
  using StatusType = typename TestFixture::StatusType;

  const std::string kMessage = "something very bad!";
  const std::string kWrongMessage = "this is not the same error";

  constexpr auto kErrorCode = absl::StatusCode::kInvalidArgument;
  constexpr auto kWrongErrorCode = absl::StatusCode::kInternal;
  const StatusType kError(kErrorCode, kMessage);

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
TYPED_TEST(StatusMatchersTest, StatusIsMatchesStatusOrObjects) {
  using StatusType = typename TestFixture::StatusType;
  using StatusOrInt = typename TestFixture::StatusOrInt;

  const std::string kMessage = "oops";
  const std::string kWrongMessage = "different error message";

  constexpr auto kErrorCode = absl::StatusCode::kFailedPrecondition;
  constexpr auto kWrongErrorCode = absl::StatusCode::kInternal;
  const StatusOrInt kFailure = StatusType(kErrorCode, kMessage);

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

  const StatusOrInt kSuccess = 1;
  EXPECT_THAT(kSuccess, StatusIs(absl::StatusCode::kOk));
  EXPECT_THAT(kSuccess, StatusIs(absl::StatusCode::kOk, ""));
  EXPECT_THAT(kSuccess, Not(StatusIs(kErrorCode)));
  EXPECT_THAT(kSuccess, Not(StatusIs(absl::StatusCode::kOk, kMessage)));

  EXPECT_NONFATAL_FAILURE(EXPECT_THAT(kSuccess, StatusIs(kErrorCode)),
                          "FAILED_PRECONDITION");
  EXPECT_NONFATAL_FAILURE(
      EXPECT_THAT(kSuccess, StatusIs(absl::StatusCode::kOk, kMessage)),
      kMessage);
  EXPECT_NONFATAL_FAILURE(
      EXPECT_THAT(kSuccess, Not(StatusIs(absl::StatusCode::kOk))),
      "does not match error code OK");
  EXPECT_NONFATAL_FAILURE(
      EXPECT_THAT(kSuccess, Not(StatusIs(absl::StatusCode::kOk, ""))),
      "does not have an error message");
}

// Tests that StatusIs only matches a Status or StatusOr if its message matches
// the message matcher.
TYPED_TEST(StatusMatchersTest, StatusIsUsesMessageMatcherToCheckMessage) {
  using StatusType = typename TestFixture::StatusType;
  using StatusOrInt = typename TestFixture::StatusOrInt;

  constexpr auto kErrorCode = absl::StatusCode::kFailedPrecondition;

  EXPECT_THAT(StatusType(kErrorCode, "Foobar"),
              StatusIs(kErrorCode, HasSubstr("Foo")));
  EXPECT_THAT(StatusOrInt(StatusType(kErrorCode, "Foobar")),
              StatusIs(kErrorCode, HasSubstr("Foo")));
  EXPECT_THAT(StatusType(kErrorCode, ""), StatusIs(kErrorCode, IsEmpty()));
  EXPECT_THAT(StatusOrInt(StatusType(kErrorCode, "")),
              StatusIs(kErrorCode, IsEmpty()));

  EXPECT_NONFATAL_FAILURE(EXPECT_THAT(StatusType(kErrorCode, "Barbaz"),
                                      StatusIs(kErrorCode, HasSubstr("Foo"))),
                          "which has an error message");
  EXPECT_NONFATAL_FAILURE(
      EXPECT_THAT(StatusOrInt(StatusType(kErrorCode, "Barbaz")),
                  StatusIs(kErrorCode, HasSubstr("Foo"))),
      "which has an error message");
  EXPECT_NONFATAL_FAILURE(EXPECT_THAT(StatusType(kErrorCode, "Barbaz"),
                                      StatusIs(kErrorCode, IsEmpty())),
                          "which has an error message");
  EXPECT_NONFATAL_FAILURE(
      EXPECT_THAT(StatusOrInt(StatusType(kErrorCode, "Barbaz")),
                  StatusIs(kErrorCode, IsEmpty())),
      "which has an error message");
}

}  // namespace
}  // namespace asylo
