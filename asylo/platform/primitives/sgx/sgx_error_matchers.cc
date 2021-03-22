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

#include "asylo/platform/primitives/sgx/sgx_error_matchers.h"

#include <ostream>
#include <utility>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/platform/primitives/sgx/sgx_errors.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status.h"
#include "include/sgx_error.h"

namespace asylo {
namespace {

// A monomorphic Status matcher for SGX errors.
class SgxErrorMatcher : public ::testing::MatcherInterface<const Status &> {
 public:
  explicit SgxErrorMatcher(sgx_status_t sgx_status) : sgx_status_(sgx_status) {}

  void DescribeTo(std::ostream *os) const override {
    *os << "is an SGX error with error code " << DescribeSgxStatus(sgx_status_);
  }

  void DescribeNegationTo(std::ostream *os) const override {
    *os << "is not an SGX error with error code "
        << DescribeSgxStatus(sgx_status_);
  }

  bool MatchAndExplain(
      const Status &status,
      ::testing::MatchResultListener *listener) const override {
    sgx_status_t actual_error = GetSgxErrorCode(status);
    if (actual_error == SGX_SUCCESS) {
      *listener << "which is not an SGX error";
      return false;
    }
    if (actual_error != sgx_status_) {
      *listener << "which has SGX error code "
                << DescribeSgxStatus(actual_error);
      return false;
    }
    return true;
  }

 private:
  sgx_status_t sgx_status_;
};

}  // namespace

PolymorphicStatusMatcherType SgxErrorIs(sgx_status_t sgx_status) {
  return MakePolymorphicStatusMatcher(
      ::testing::MakeMatcher(new SgxErrorMatcher(sgx_status)));
}

}  // namespace asylo
