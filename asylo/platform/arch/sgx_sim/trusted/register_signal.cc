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

#include "asylo/platform/arch/include/trusted/register_signal.h"

#include <signal.h>

#include "asylo/platform/arch/include/trusted/host_calls.h"
#include "asylo/platform/common/bridge_functions.h"
#include "asylo/platform/common/bridge_types.h"
#include "asylo/platform/posix/signal/signal_manager.h"

namespace asylo {

// Translates |bridge_signum| to the value inside the enclave, and passes it to
// the signal handler registered inside enclave.
void TranslateAndHandleSignal(int bridge_signum,
                              bridge_siginfo_t *bridge_siginfo,
                              void *ucontext) {
  int signum = FromBridgeSignal(bridge_signum);
  if (signum < 0) {
    return;
  }
  siginfo_t info;
  if (!FromBridgeSigInfo(bridge_siginfo, &info)) {
    // Malformed siginfo struct.
    return;
  }
  SignalManager *signal_manager = SignalManager::GetInstance();
  sigset_t mask = signal_manager->GetSignalMask();
  // If the signal is blocked and still passed into the enclave. The signal
  // masks inside the enclave is out of sync with the untrusted signal mask.
  if (sigismember(&mask, signum)) {
    return;
  }
  Status status = signal_manager->HandleSignal(signum, &info, ucontext);
  if (!status.ok()) {
    LOG(ERROR) << status;
  }
}

}  // namespace asylo

extern "C" int enc_register_signal(int signum, const sigset_t mask, int flags,
                                   const char *enclave_name) {
  return enc_untrusted_register_signal_handler(
      signum, &asylo::TranslateAndHandleSignal, mask, flags, enclave_name);
}
