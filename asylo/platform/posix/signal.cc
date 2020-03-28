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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <signal.h>

#include <cstdlib>

#include "absl/synchronization/mutex.h"
#include "asylo/platform/core/trusted_global_state.h"
#include "asylo/platform/host_call/trusted/host_calls.h"
#include "asylo/platform/posix/signal/signal_manager.h"
#include "asylo/platform/posix/syscall/signal_syscalls.h"
#include "asylo/platform/primitives/trusted_runtime.h"

extern "C" {

#ifndef ASYLO_NEWLIB_SIGNAL_DEFINED
int sigaction(int signum, const struct sigaction *act,
              struct sigaction *oldact) {
  return asylo::RtSigaction(signum, act, oldact, sizeof(sigset_t));
}

int sigprocmask(int how, const sigset_t *set, sigset_t *oldset) {
  return asylo::RtSigprocmask(how, set, oldset, sizeof(sigset_t));
}

int pthread_sigmask(int how, const sigset_t *set, sigset_t *oldset) {
  return sigprocmask(how, set, oldset);
}

// Registers a signal handler for |signum| with |handler|.
//
// This method is a special case of sigaction. It calls sigaction with only
// sa_handler in |act| field set.
sighandler_t signal(int signum, sighandler_t handler) {
  struct sigaction act;
  act.sa_handler = handler;
  sigemptyset(&act.sa_mask);
  struct sigaction oldact;
  if (sigaction(signum, &act, &oldact)) {
    // Errno is set by sigaction.
    return SIG_ERR;
  }
  return oldact.sa_handler;
}
#endif  // !defined(ASYLO_NEWLIB_SIGNAL_DEFINED)

// Raise a signal to be handled.
//
// If a signal is raised inside an enclave, it exits the enclave and raises the
// signal on the host. If a handler has been registered for this signal in the
// enclave, the signal handler on the host enters the enclave to invoke the
// registered handler.
int raise(int sig) { return enc_untrusted_raise(sig); }

}  // extern "C"
