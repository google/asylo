/*
 *
 * Copyright 2017 Asylo authors
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

#ifndef ASYLO_TEST_UTIL_STATUS_MATCHERS_H_
#define ASYLO_TEST_UTIL_STATUS_MATCHERS_H_

#include <gmock/gmock-matchers.h>
#include "asylo/test/util/statusor_test_util.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace internal {

// Implements a gMock matcher for checking error-code expectations on
// asylo::Status objects.
template <typename Enum>
class StatusCodeMatcher : public ::testing::MatcherInterface<const Status &> {
 public:
  StatusCodeMatcher(Enum code)
      : code_(code),
        error_space_(error::error_enum_traits<Enum>::get_error_space()) {}

  // From testing::MatcherInterface.
  //
  // Describes the expected error code.
  void DescribeTo(std::ostream *os) const override {
    *os << "error code " << error_space_->SpaceName()
        << "::" << error_space_->String(static_cast<int>(code_));
  }

  // From testing::MatcherInterface.
  //
  // Tests whether |status| has an error code that meets this matcher's
  // expectation.
  bool MatchAndExplain(
      const Status &status,
      ::testing::MatchResultListener *listener) const override {
    if (!status.Is(code_)) {
      *listener << "whose error code is " << status.error_space()->SpaceName()
                << "::" << status.error_space()->String(status.error_code());
      return false;
    }
    return true;
  }

 private:
  // Expected error code.
  Enum code_;

  // Error space of the expected error code.
  const error::ErrorSpace *error_space_;
};

// Implements a gMock matcher that checks whether a status container (e.g.
// asylo::Status or asylo::StatusOr<T>) has an OK status.
template <class T>
class IsOkMatcherImpl : public ::testing::MatcherInterface<T> {
 public:
  IsOkMatcherImpl() = default;

  // From testing::MatcherInterface.
  //
  // Describes the OK expectation.
  void DescribeTo(std::ostream *os) const override { *os << "is OK"; }

  // From testing::MatcherInterface.
  //
  // Describes the negative OK expectation.
  void DescribeNegationTo(std::ostream *os) const override {
    *os << "is not OK";
  }

  // From testing::MatcherInterface.
  //
  // Tests whether |status_container|'s OK value meets this matcher's
  // expectation.
  bool MatchAndExplain(
      const T &status_container,
      ::testing::MatchResultListener *listener) const override {
    if (!status_container.ok()) {
      *listener << "which is not OK";
      return false;
    }
    return true;
  }
};

// IsOkMatcherGenerator is an intermediate object returned by asylo::IsOk().
// It implements implicit type-cast operators to supported matcher types:
// Matcher<const Status &> and Matcher<const StatusOr<T> &>. These typecast
// operators create gMock matchers that test OK expectations on a status
// container.
class IsOkMatcherGenerator {
 public:
  // Type-cast operator for Matcher<const asylo::Status &>.
  operator ::testing::Matcher<const Status &>() const {
    return ::testing::MakeMatcher(
        new internal::IsOkMatcherImpl<const Status &>());
  }

  // Type-cast operator for Matcher<const asylo::StatusOr<T> &>.
  template <class T>
  operator ::testing::Matcher<const StatusOr<T> &>() const {
    return ::testing::MakeMatcher(
        new internal::IsOkMatcherImpl<const StatusOr<T> &>());
  }
};

}  // namespace internal

// Returns a gMock matcher that expects an asylo::Status object to have the
// given |code|.
template <typename Enum>
::testing::Matcher<const Status &> StatusIs(Enum code) {
  return ::testing::MakeMatcher(new internal::StatusCodeMatcher<Enum>(code));
}

// Returns an internal::IsOkMatcherGenerator, which may be typecast to a
// Matcher<asylo::Status> or Matcher<asylo::StatusOr<T>>. These gMock
// matchers test that a given status container has an OK status.
inline internal::IsOkMatcherGenerator IsOk() {
  return internal::IsOkMatcherGenerator();
}

}  // namespace asylo

#endif  // ASYLO_TEST_UTIL_STATUS_MATCHERS_H_
