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

#include "asylo/test/util/enclave_test_application.h"
#include "asylo/util/status.h"

namespace asylo {

static thread_local volatile bool signal_received = false;

void HandleSignal(int signum) {
  if (signum == SIGUSR1) {
    signal_received = true;
  }
}

class ActiveEnclaveSignalTest : public TrustedApplication {
 public:
  ActiveEnclaveSignalTest() = default;

  Status Run(const EnclaveInput &input, EnclaveOutput *output) {
    struct sigaction act, oldact;
    act.sa_handler = &HandleSignal;
    sigaction(SIGUSR1, &act, &oldact);
    // Print to the pipe so that the signal thread will start sending the
    // signal.
    printf("ready to receive signal!");
    fclose(stdout);
    // Wait till the signal is received. If it's not working, this test should
    // time out.
    while (!signal_received) {
      sleep(1);
    }
    return Status::OkStatus();
  }
};

TrustedApplication *BuildTrustedApplication() {
  return new ActiveEnclaveSignalTest;
}

}  // namespace asylo
