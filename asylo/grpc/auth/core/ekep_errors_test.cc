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

#include "asylo/grpc/auth/core/ekep_errors.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/status/status.h"
#include "absl/types/optional.h"
#include "asylo/grpc/auth/core/ekep_error_matchers.h"
#include "asylo/grpc/auth/core/handshake.pb.h"
#include "asylo/test/util/status_matchers.h"

namespace asylo {
namespace {

using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::Not;
using ::testing::Optional;

TEST(EkepErrorsTest, EkepErrorIsNotOk) {
  EXPECT_THAT(EkepError(Abort::BAD_RECORD_PROTOCOL, "message"), Not(IsOk()));
}

TEST(EkepErrorsTest, EkepErrorContainsUserMessage) {
  constexpr absl::string_view kMessage = "test message";
  EXPECT_THAT(EkepError(Abort::BAD_RECORD_PROTOCOL, kMessage).message(),
              HasSubstr(kMessage));
}

TEST(EkepErrorsTest, GetEkepErrorCodeReturnsNulloptOnNonEkepStatus) {
  EXPECT_THAT(GetEkepErrorCode(OkStatus()), Eq(absl::nullopt));
  EXPECT_THAT(GetEkepErrorCode(absl::InvalidArgumentError("foobar")),
              Eq(absl::nullopt));
}

TEST(EkepErrorsTest, GetEkepErrorCodeReturnsEkepErrorCodeFromEkepError) {
  EXPECT_THAT(
      GetEkepErrorCode(EkepError(Abort::BAD_RECORD_PROTOCOL, "message")),
      Optional(Abort::BAD_RECORD_PROTOCOL));
}

TEST(EkepErrorsTest, EkepErrorIsDoesNotMatchOnNonEkepStatus) {
  EXPECT_THAT(absl::OkStatus(), Not(EkepErrorIs(Abort::BAD_RECORD_PROTOCOL)));
  EXPECT_THAT(absl::InvalidArgumentError("foobar"),
              Not(EkepErrorIs(Abort::BAD_RECORD_PROTOCOL)));
}

TEST(EkepErrorsTest, EkepErrorIsDoesNotMatchEkepErrorWithDifferentCode) {
  EXPECT_THAT(EkepError(Abort::BAD_HANDSHAKE_CIPHER, "message"),
              Not(EkepErrorIs(Abort::BAD_RECORD_PROTOCOL)));
}

TEST(EkepErrorsTest, EkepErrorIsMatchesEkepErrorWithEqualCode) {
  EXPECT_THAT(EkepError(Abort::BAD_RECORD_PROTOCOL, "message"),
              EkepErrorIs(Abort::BAD_RECORD_PROTOCOL));
  EXPECT_THAT(EkepError(Abort::BAD_RECORD_PROTOCOL, "other message"),
              EkepErrorIs(Abort::BAD_RECORD_PROTOCOL));
}

}  // namespace
}  // namespace asylo
