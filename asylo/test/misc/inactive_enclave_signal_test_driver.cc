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
#include "absl/status/status.h"
#include "asylo/test/misc/signal_test.pb.h"
#include "asylo/test/util/enclave_test.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"

namespace asylo {
namespace {

class InactiveEnclaveSignalTest : public EnclaveTest {
 protected:
  Status RunSignalTest(const EnclaveInput &enclave_input) {
    EnclaveOutput enclave_output;
    // First run the enclave to register the signal handler, and close the
    // frame. At this moment no signals have been delivered yet.
    ASYLO_RETURN_IF_ERROR(client_->EnterAndRun(enclave_input, &enclave_output));
    if (enclave_output.GetExtension(signal_received)) {
      return absl::InternalError("Signal received in enclave before sent");
    }
    raise(SIGUSR1);
    // Run the enclave again, this time a signal is raised and should have been
    // sent to enclave, so enclave should return OK status.
    ASYLO_RETURN_IF_ERROR(client_->EnterAndRun(enclave_input, &enclave_output));
    if (!enclave_output.GetExtension(signal_received)) {
      return absl::InternalError("Signal not received in enclave");
    }
    return absl::OkStatus();
  }
};

TEST_F(InactiveEnclaveSignalTest, HandlerTest) {
  // Test signal handled by sa_handler.
  EnclaveInput enclave_input;
  enclave_input.MutableExtension(signal_test_input)
      ->set_signal_test_type(SignalTestInput::HANDLER);
  EXPECT_THAT(RunSignalTest(enclave_input), IsOk());
}

TEST_F(InactiveEnclaveSignalTest, SignalTest) {
  // Test signal registered by signal(2).
  EnclaveInput enclave_input;
  enclave_input.MutableExtension(signal_test_input)
      ->set_signal_test_type(SignalTestInput::SIGNAL);
  EXPECT_THAT(RunSignalTest(enclave_input), IsOk());
}

TEST_F(InactiveEnclaveSignalTest, SigactionTest) {
  // Test signal handled by sa_sigaction.
  EnclaveInput enclave_input;
  enclave_input.MutableExtension(signal_test_input)
      ->set_signal_test_type(SignalTestInput::SIGACTION);
  EXPECT_THAT(RunSignalTest(enclave_input), IsOk());
}

}  // namespace
}  // namespace asylo
