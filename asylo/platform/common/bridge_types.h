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

#ifndef ASYLO_PLATFORM_COMMON_BRIDGE_TYPES_H_
#define ASYLO_PLATFORM_COMMON_BRIDGE_TYPES_H_

#include <signal.h>
#include <stdint.h>

#include "absl/base/attributes.h"

// This file provides a set of type definitions used both inside and outside the
// enclave.

#ifdef __cplusplus
extern "C" {
#endif

// Replace size_t, ssize_t, and sigset_t with types of known width for
// transmission across the enclave boundary.
typedef uint64_t bridge_size_t;
typedef int64_t bridge_sigset_t;

// All the signals that are supported to be registered inside enclave (except
// SIGSTOP and SIGKILL).
enum SignalNumber {
  BRIDGE_SIGHUP = 1,
  BRIDGE_SIGINT = 2,
  BRIDGE_SIGQUIT = 3,
  BRIDGE_SIGILL = 4,
  BRIDGE_SIGTRAP = 5,
  BRIDGE_SIGABRT = 6,
  BRIDGE_SIGBUS = 7,
  BRIDGE_SIGFPE = 8,
  BRIDGE_SIGKILL = 9,
  BRIDGE_SIGUSR1 = 10,
  BRIDGE_SIGSEGV = 11,
  BRIDGE_SIGUSR2 = 12,
  BRIDGE_SIGPIPE = 13,
  BRIDGE_SIGALRM = 14,
  BRIDGE_SIGTERM = 15,
  BRIDGE_SIGCHLD = 16,
  BRIDGE_SIGCONT = 17,
  BRIDGE_SIGSTOP = 18,
  BRIDGE_SIGTSTP = 19,
  BRIDGE_SIGTTIN = 20,
  BRIDGE_SIGTTOU = 21,
  BRIDGE_SIGURG = 22,
  BRIDGE_SIGXCPU = 23,
  BRIDGE_SIGXFSZ = 24,
  BRIDGE_SIGVTALRM = 25,
  BRIDGE_SIGPROF = 26,
  BRIDGE_SIGWINCH = 27,
  BRIDGE_SIGSYS = 28,
  BRIDGE_SIGRTMIN = 32,
  BRIDGE_SIGRTMAX = 64,
};

// The code that describes the cause of a signal.
enum SignalCode {
  BRIDGE_SI_USER = 1,
  BRIDGE_SI_QUEUE = 2,
  BRIDGE_SI_TIMER = 3,
  BRIDGE_SI_ASYNCIO = 4,
  BRIDGE_SI_MESGQ = 5,
};

struct bridge_siginfo_t {
  int32_t si_signo;
  int32_t si_code;
};

struct BridgeSignalHandler {
  void (*sigaction)(int, struct bridge_siginfo_t *, void *);
  bridge_sigset_t mask;
  int64_t flags;
};

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // ASYLO_PLATFORM_COMMON_BRIDGE_TYPES_H_
