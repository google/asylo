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

#include <signal.h>

#include <gtest/gtest.h>
#include "asylo/test/util/enclave_test.h"
#include "asylo/test/util/status_matchers.h"

namespace asylo {
namespace {

class InactiveEnclaveSignalTest : public EnclaveTest {};

TEST_F(InactiveEnclaveSignalTest, SignalTest) {
  // First run the enclave to register the signal handler, and close the frame.
  // At this moment no signals have been delivered yet, so enclave returns
  // non-OK status.
  EXPECT_THAT(client_->EnterAndRun({}, nullptr), testing::Not(IsOk()));
  raise(SIGUSR1);
  // Run the enclave again, this time a signal is raised and should have been
  // sent to enclave, so enclave should return OK status.
  EXPECT_THAT(client_->EnterAndRun({}, nullptr), IsOk());
}

}  // namespace
}  // namespace asylo
