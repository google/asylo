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

#include "asylo/grpc/auth/core/ekep_error_matchers.h"

#include <ostream>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/types/optional.h"
#include "asylo/grpc/auth/core/ekep_errors.h"
#include "asylo/grpc/auth/core/handshake.pb.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/proto_enum_util.h"
#include "asylo/util/status.h"

namespace asylo {
namespace {

// A monomorphic Status matcher for EKEP abort errors.
class EkepErrorMatcher : public ::testing::MatcherInterface<const Status &> {
 public:
  explicit EkepErrorMatcher(Abort_ErrorCode code) : code_(code) {}

  void DescribeTo(std::ostream *os) const override {
    *os << "is an EKEP abort error with code " << ProtoEnumValueName(code_);
  }

  void DescribeNegationTo(std::ostream *os) const override {
    *os << "is not an EKEP abort error with code " << ProtoEnumValueName(code_);
  }

  bool MatchAndExplain(
      const Status &status,
      ::testing::MatchResultListener *listener) const override {
    absl::optional<Abort_ErrorCode> actual_code = GetEkepErrorCode(status);
    if (!actual_code.has_value()) {
      *listener << "which is not an EKEP abort error";
      return false;
    }
    if (actual_code.value() != code_) {
      *listener << "which is a(n) " << ProtoEnumValueName(actual_code.value())
                << " error";
      return false;
    }
    return true;
  }

 private:
  Abort_ErrorCode code_;
};

}  // namespace

PolymorphicStatusMatcherType EkepErrorIs(Abort_ErrorCode code) {
  return MakePolymorphicStatusMatcher(
      ::testing::MakeMatcher<const Status &>(new EkepErrorMatcher(code)));
}

}  // namespace asylo
