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

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "asylo/test/misc/signal_test.pb.h"
#include "asylo/test/util/enclave_test_application.h"
#include "asylo/util/status.h"

namespace asylo {

static bool signal_handled = false;

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

class InactiveEnclaveSignalTest : public EnclaveTestCase {
 public:
  InactiveEnclaveSignalTest() = default;

  Status Run(const EnclaveInput &input, EnclaveOutput *output) {
    if (!input.HasExtension(signal_test_input)) {
      return absl::InvalidArgumentError("Missing input extension");
    }
    SignalTestInput test_input = input.GetExtension(signal_test_input);
    if (!test_input.has_signal_test_type()) {
      return absl::InvalidArgumentError("Missing signal_handler_type");
    }
    struct sigaction act = {};
    switch (test_input.signal_test_type()) {
      case SignalTestInput::HANDLER:
        act.sa_handler = &HandleSignalWithHandler;
        break;
      case SignalTestInput::SIGACTION:
        act.sa_sigaction = &HandleSignalWithSigAction;
        act.sa_flags |= SA_SIGINFO;
        break;
      case SignalTestInput::SIGNAL: {
        auto result = signal(SIGUSR1, &HandleSignalWithHandler);
        if (result == SIG_ERR) {
          return Status(
              error::GoogleError::INTERNAL,
              absl::StrCat("Error installing signal handler with `signal`: ",
                           errno));
        }
      } break;
      default:
        return absl::InvalidArgumentError("No valid test type");
    }
    if (test_input.signal_test_type() != SignalTestInput::SIGNAL) {
      struct sigaction oldact;
      if (sigaction(SIGUSR1, &act, &oldact)) {
        return Status(
            error::GoogleError::INTERNAL,
            absl::StrCat("Error installing signal handler with `sigaction`: ",
                         errno));
      }
    }
    output->SetExtension(signal_received, signal_handled);
    return absl::OkStatus();
  }
};

TrustedApplication *BuildTrustedApplication() {
  return new InactiveEnclaveSignalTest;
}

}  // namespace asylo
