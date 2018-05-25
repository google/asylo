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
#include <stdio.h>
#include <unistd.h>

#include "asylo/test/misc/signal_test.pb.h"
#include "asylo/test/util/enclave_test_application.h"
#include "asylo/util/status.h"

namespace asylo {

static thread_local volatile bool signal_handled = false;

void HandleSignalWithHandler(int signum) {
  if (signum == SIGUSR1) {
    signal_handled = true;
  }
}

void HandleSignalWithSigAction(int signum, siginfo_t *info, void *ucontext) {
  if (signum == SIGUSR1) {
    signal_handled = true;
  }
}

class ActiveEnclaveSignalTest : public TrustedApplication {
 public:
  ActiveEnclaveSignalTest() = default;

  Status Run(const EnclaveInput &input, EnclaveOutput *output) {
    if (!input.HasExtension(signal_test_input)) {
      return Status(error::GoogleError::INVALID_ARGUMENT,
                    "Missing input extension");
    }
    SignalTestInput test_input = input.GetExtension(signal_test_input);
    if (!test_input.has_signal_test_type()) {
      return Status(error::GoogleError::INVALID_ARGUMENT,
                    "Missing signal_handler_type");
    }
    struct sigaction act, oldact;
    if (test_input.signal_test_type() == SignalTestInput::HANDLER) {
      act.sa_handler = &HandleSignalWithHandler;
    } else if (test_input.signal_test_type() == SignalTestInput::SIGACTION) {
      act.sa_sigaction = &HandleSignalWithSigAction;
      act.sa_flags |= SA_SIGINFO;
    } else {
      return Status(error::GoogleError::INVALID_ARGUMENT,
                    "No valid handler type");
    }
    sigaction(SIGUSR1, &act, &oldact);
    // Print to the pipe so that the signal thread will start sending the
    // signal.
    printf("ready to receive signal!");
    fclose(stdout);
    // Wait till the signal is received. If it's not working, this test should
    // time out.
    while (!signal_handled) {
      sleep(1);
    }
    return Status::OkStatus();
  }
};

TrustedApplication *BuildTrustedApplication() {
  return new ActiveEnclaveSignalTest;
}

}  // namespace asylo
