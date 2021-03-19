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

#include "asylo/platform/primitives/sgx/sgx_errors.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "asylo/platform/primitives/sgx/sgx_error_matchers.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status.h"
#include "include/sgx_error.h"

namespace asylo {
namespace {

using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::Not;

TEST(SgxErrorsTest, SgxErrorReturnsOkIfSgxStatusIsSuccess) {
  ASYLO_EXPECT_OK(SgxError(SGX_SUCCESS, "message"));
}

TEST(SgxErrorsTest, SgxErrorIsNotOkIfSgxStatusIsNotSuccess) {
  EXPECT_THAT(SgxError(SGX_ERROR_OUT_OF_TCS, "message"), Not(IsOk()));
}

TEST(SgxErrorsTest, SgxErrorContainsUserMessage) {
  constexpr absl::string_view kMessage = "test message";
  EXPECT_THAT(SgxError(SGX_ERROR_OUT_OF_TCS, kMessage).message(),
              HasSubstr(kMessage));
}

TEST(SgxErrorsTest, GetSgxErrorCodeReturnsSuccessOnNonSgxStatus) {
  EXPECT_THAT(GetSgxErrorCode(OkStatus()), Eq(SGX_SUCCESS));
  EXPECT_THAT(GetSgxErrorCode(absl::InvalidArgumentError("foobar")),
              Eq(SGX_SUCCESS));
}

TEST(SgxErrorsTest, GetSgxErrorCodeReturnsSgxErrorCodeFromSgxError) {
  EXPECT_THAT(GetSgxErrorCode(SgxError(SGX_ERROR_OUT_OF_TCS, "message")),
              Eq(SGX_ERROR_OUT_OF_TCS));
}

TEST(SgxErrorsTest, SgxErrorIsDoesNotMatchOnNonSgxStatus) {
  EXPECT_THAT(absl::OkStatus(), Not(SgxErrorIs(SGX_ERROR_OUT_OF_TCS)));
  EXPECT_THAT(absl::InvalidArgumentError("foobar"),
              Not(SgxErrorIs(SGX_ERROR_OUT_OF_TCS)));
}

TEST(SgxErrorsTest, SgxErrorIsDoesNotMatchSgxErrorWithDifferentCode) {
  EXPECT_THAT(SgxError(SGX_ERROR_ENCLAVE_LOST, "message"),
              Not(SgxErrorIs(SGX_ERROR_OUT_OF_TCS)));
}

TEST(SgxErrorsTest, SgxErrorIsMatchesSgxErrorWithEqualCode) {
  EXPECT_THAT(SgxError(SGX_ERROR_OUT_OF_TCS, "message"),
              SgxErrorIs(SGX_ERROR_OUT_OF_TCS));
  EXPECT_THAT(SgxError(SGX_ERROR_OUT_OF_TCS, "other message"),
              SgxErrorIs(SGX_ERROR_OUT_OF_TCS));
}

}  // namespace
}  // namespace asylo
