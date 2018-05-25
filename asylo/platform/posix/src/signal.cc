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

#include <signal.h>

#include <pthread.h>
#include <cstdlib>

#include "absl/synchronization/mutex.h"
#include "asylo/platform/arch/include/trusted/register_signal.h"
#include "asylo/platform/core/trusted_global_state.h"
#include "asylo/platform/posix/signal/signal_manager.h"

extern "C" {

int pthread_sigmask(int how, const sigset_t *set, sigset_t *oldset) { abort(); }

// Guards sigaction calls. This is to ensure that the signal handlers are not
// overwritten between the time sigaction gets |oldact| and sets|act|.
static absl::Mutex sigaction_lock;

// Registers a signal handler for |signum|.
//
// This method registers a signal handler in two parts:
// * On the host-side, registers a signal-handling function that calls into the
// enclave to handle the signal.
// * Inside the enclave, registers the user-provided function |act| as the
// actual signal handler.
//
// When a signal is subsequently invoked on the host, it will first be passed to
// the host-side signal handler. The host-side signal handler will then enter
// enclave to invoke the corresponding signal handler registered inside the
// enclave.
// Note that the behavior described above applies if either the enclave is run
// in hardware mode, or it is run in simulation mode and the TCS is inactive. If
// the enclave is run in simulation mode and TCS is active (i.e. a thread is
// running inside the enclave), then this function will call the signal handler
// registered inside the enclave directly.
int sigaction(int signum, const struct sigaction *act,
              struct sigaction *oldact) {
  {
    absl::MutexLock lock(&sigaction_lock);
    asylo::SignalManager *signal_manager = asylo::SignalManager::GetInstance();
    if (oldact) {
      if (signal_manager->GetSigAction(signum)) {
        oldact = const_cast<struct sigaction *>(
            signal_manager->GetSigAction(signum));
      } else {
        oldact->sa_handler = SIG_DFL;
      }
    }
    signal_manager->SetSigAction(signum, act);
  }
  const std::string enclave_name = asylo::GetEnclaveName();
  // Pass a C string because enc_register_signal has C linkage. This string is
  // copied to untrusted memory when going across enclave boundary.
  return enc_register_signal(signum, enclave_name.c_str());
}

}  // extern "C"
