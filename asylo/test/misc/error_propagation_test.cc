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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/status/status.h"
#include "asylo/test/util/enclave_test.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/posix_error_matchers.h"
#include "asylo/util/status.h"

namespace asylo {
namespace {

constexpr char kErrorString[] = "Secret error message";

using ::testing::HasSubstr;
using ::testing::Not;

// Tests error propagation over the enclave boundary.
class ErrorPropagationTest : public EnclaveTest {
 protected:
  void SetUp() override { SetUpBase(); }
};

// Tests end-to-end flow of returning an OK status from inside the enclave.
TEST_F(ErrorPropagationTest, NoError) {
  EnclaveInput enclave_input;
  SetEnclaveInputTestString(&enclave_input, "OK");

  Status status = client_->EnterAndRun(enclave_input, /*output=*/nullptr);
  EXPECT_THAT(status, IsOk());
}

// Tests end-to-end flow of returning an non-OK status with a canonical error
// code from inside the enclave.
TEST_F(ErrorPropagationTest, ErrorCanonical) {
  EnclaveInput enclave_input;
  SetEnclaveInputTestString(&enclave_input,
                            "absl::StatusCode::kUnauthenticated");

  Status status = client_->EnterAndRun(enclave_input, /*output=*/nullptr);
  EXPECT_THAT(status, Not(IsOk()));
  EXPECT_THAT(status, StatusIs(absl::StatusCode::kUnauthenticated));
  EXPECT_EQ(status.message(), kErrorString);
}

// Tests end-to-end flow of returning an non-OK status with a non-canonical
// error code from inside the enclave.
TEST_F(ErrorPropagationTest, ErrorNonCanonical) {
  EnclaveInput enclave_input;
  SetEnclaveInputTestString(&enclave_input, "EINVAL");

  Status status = client_->EnterAndRun(enclave_input, /*output=*/nullptr);
  EXPECT_THAT(status, Not(IsOk()));
  EXPECT_THAT(status, PosixErrorIs(EINVAL));
  EXPECT_THAT(status.message(), HasSubstr(kErrorString));
}

}  // namespace
}  // namespace asylo
