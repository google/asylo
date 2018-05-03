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

#include "asylo/test/util/fake_local_enclave_client.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/test/util/status_matchers.h"

namespace asylo {
namespace {

// A mock enclave that implements the Run/Initialize/Finalize methods by
// returning the status it is currently set to use.
class TrivialMockEnclave {
 public:
  explicit TrivialMockEnclave(const Status &status) : status_(status) {}

  Status Run(const EnclaveInput &input, EnclaveOutput *output) {
    return status_;
  }

  Status Initialize(const EnclaveConfig &config) { return status_; }

  Status Finalize(const EnclaveFinal &final_input) { return status_; }

 private:
  // The status to run when called.
  Status status_;
};

TEST(FakeLocalEnclaveClientTest, RunReturnsStatus) {
  FakeLocalEnclaveClient<TrivialMockEnclave> client(
      absl::make_unique<TrivialMockEnclave>(
          Status(error::GoogleError::INVALID_ARGUMENT, "test")));

  EnclaveInput input;
  EnclaveOutput output;
  EXPECT_THAT(client.EnterAndRun(input, &output),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}


}  // namespace
}  // namespace asylo
