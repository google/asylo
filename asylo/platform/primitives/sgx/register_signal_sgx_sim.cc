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

#include "asylo/platform/posix/signal/signal_manager.h"
#include "asylo/platform/primitives/sgx/trusted_sgx.h"
#include "asylo/platform/primitives/trusted_primitives.h"
#include "asylo/platform/system_call/type_conversions/types_functions.h"

namespace asylo {

// Translates |klinux_signum| to the value inside the enclave, and passes it to
// the signal handler registered inside enclave.
void TranslateAndHandleSignal(int klinux_signum,
                              klinux_siginfo_t *klinux_siginfo,
                              void *ucontext) {
  absl::optional<int> signum = FromkLinuxSignalNumber(klinux_signum);
  if (!signum) {
    ::asylo::primitives::TrustedPrimitives::BestEffortAbort(
        "received unexpected signal number from untrusted code");
    return;
  }
  siginfo_t info;
  if (!FromkLinuxSiginfo(klinux_siginfo, &info)) {
    ::asylo::primitives::TrustedPrimitives::BestEffortAbort(
        "signal handler received malformed siginfo structure");
    return;
  }
  SignalManager *signal_manager = SignalManager::GetInstance();
  sigset_t mask = signal_manager->GetSignalMask();
  // If the signal is blocked and still passed into the enclave. The signal
  // masks inside the enclave is out of sync with the untrusted signal mask.
  // This is not considered a fatal error, as untrusted code could conceivably
  // altered the signal mask, leaving the trusted code out of the loop. The best
  // course of action is to ignore the unexpected signal.
  if (sigismember(&mask, *signum)) {
    return;
  }
  signal_manager->HandleSignal(*signum, &info, ucontext);
}

}  // namespace asylo

extern "C" int enc_register_signal(int signum, const sigset_t mask, int flags) {
  return asylo::primitives::RegisterSignalHandler(
      signum, &asylo::TranslateAndHandleSignal, mask, flags);
}
