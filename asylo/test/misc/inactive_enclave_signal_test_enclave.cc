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

#include "asylo/test/util/enclave_test_application.h"
#include "asylo/util/status.h"

namespace asylo {

static bool signal_received = false;

static void HandleSignal(int signum) {
  if (signum == SIGUSR1) {
    signal_received = true;
  }
}

class InactiveEnclaveSignalTest : public EnclaveTestCase {
 public:
  InactiveEnclaveSignalTest() = default;

  Status Run(const EnclaveInput &input, EnclaveOutput *output) {
    struct sigaction act, oldact;
    act.sa_handler = &HandleSignal;
    sigaction(SIGUSR1, &act, &oldact);
    // This enclave is run twice. The first time the signal handler is
    // registered, but no signal has been sent, so it returns error. After this
    // enclave run finishes, a |SIGUSR1| is sent from the host and handled by
    // the enclave when the enclave is not actively running. Then this enclave
    // is run again, this time |SIGUSR1| is handled so it should return success.
    if (!signal_received) {
      return Status(error::GoogleError::INTERNAL, "signal not handled!");
    }
    return Status::OkStatus();
  }
};

TrustedApplication *BuildTrustedApplication() {
  return new InactiveEnclaveSignalTest;
}

}  // namespace asylo
