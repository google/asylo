/*
 * Copyright 2021 Asylo authors
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
 */

#include "asylo/util/posix_error_matchers.h"

#include <ostream>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/posix_errors.h"
#include "asylo/util/status.h"

namespace asylo {
namespace {

// A monomorphic Status matcher for POSIX errors.
class PosixErrorMatcher : public ::testing::MatcherInterface<const Status &> {
 public:
  explicit PosixErrorMatcher(int errnum) : errnum_(errnum) {}

  void DescribeTo(std::ostream *os) const override {
    *os << "is a POSIX error with errnum " << errnum_;
  }

  void DescribeNegationTo(std::ostream *os) const override {
    *os << "is not a POSIX error with errnum " << errnum_;
  }

  bool MatchAndExplain(
      const Status &status,
      ::testing::MatchResultListener *listener) const override {
    int actual_errnum = GetErrno(status);
    if (actual_errnum == 0) {
      *listener << "which is not a POSIX error";
      return false;
    }
    if (actual_errnum != errnum_) {
      *listener << "which has errnum " << actual_errnum;
      return false;
    }
    return true;
  }

 private:
  int errnum_;
};

}  // namespace

PolymorphicStatusMatcherType PosixErrorIs(int errnum) {
  return MakePolymorphicStatusMatcher(
      ::testing::MakeMatcher(new PosixErrorMatcher(errnum)));
}

}  // namespace asylo
