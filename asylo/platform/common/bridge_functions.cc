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

#include "asylo/platform/common/bridge_functions.h"

// Get POLLRDHUP from poll.h.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif  // _GNU_SOURCE

// Get POLL(RD|WR)(NORM|BAND) from poll.h.
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE
#endif  // _XOPEN_SOURCE

#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include <utime.h>

#include <algorithm>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <unordered_map>

#include "asylo/util/logging.h"
#include "asylo/platform/common/bridge_types.h"
#include "asylo/platform/system_call/type_conversions/types_functions.h"

namespace asylo {
namespace {

void BridgeSigAddSet(bridge_sigset_t *bridge_set, const int sig) {
  *bridge_set |= (UINT64_C(1) << sig);
}

bool BridgeSigIsMember(const bridge_sigset_t *bridge_set, const int sig) {
  return (*bridge_set & (UINT64_C(1) << sig)) != 0;
}

void BridgeSigEmptySet(bridge_sigset_t *bridge_set) { *bridge_set = 0; }

const std::unordered_map<int, int> *CreateBridgeSignalMap() {
  auto signal_map = new std::unordered_map<int, int>;
  signal_map->insert({SIGHUP, BRIDGE_SIGHUP});
  signal_map->insert({SIGINT, BRIDGE_SIGINT});
  signal_map->insert({SIGQUIT, BRIDGE_SIGQUIT});
  signal_map->insert({SIGILL, BRIDGE_SIGILL});
  signal_map->insert({SIGTRAP, BRIDGE_SIGTRAP});
  signal_map->insert({SIGABRT, BRIDGE_SIGABRT});
  signal_map->insert({SIGBUS, BRIDGE_SIGBUS});
  signal_map->insert({SIGFPE, BRIDGE_SIGFPE});
  signal_map->insert({SIGKILL, BRIDGE_SIGKILL});
  signal_map->insert({SIGUSR1, BRIDGE_SIGUSR1});
  signal_map->insert({SIGSEGV, BRIDGE_SIGSEGV});
  signal_map->insert({SIGUSR2, BRIDGE_SIGUSR2});
  signal_map->insert({SIGPIPE, BRIDGE_SIGPIPE});
  signal_map->insert({SIGALRM, BRIDGE_SIGALRM});
  signal_map->insert({SIGCHLD, BRIDGE_SIGCHLD});
  signal_map->insert({SIGCONT, BRIDGE_SIGCONT});
  signal_map->insert({SIGSTOP, BRIDGE_SIGSTOP});
  signal_map->insert({SIGTSTP, BRIDGE_SIGTSTP});
  signal_map->insert({SIGTTIN, BRIDGE_SIGTTIN});
  signal_map->insert({SIGTTOU, BRIDGE_SIGTTOU});
  signal_map->insert({SIGURG, BRIDGE_SIGURG});
  signal_map->insert({SIGXCPU, BRIDGE_SIGXCPU});
  signal_map->insert({SIGXFSZ, BRIDGE_SIGXFSZ});
  signal_map->insert({SIGVTALRM, BRIDGE_SIGVTALRM});
  signal_map->insert({SIGPROF, BRIDGE_SIGPROF});
  signal_map->insert({SIGWINCH, BRIDGE_SIGWINCH});
  signal_map->insert({SIGSYS, BRIDGE_SIGSYS});
  signal_map->insert({SIGTERM, BRIDGE_SIGTERM});
#if defined(SIGRTMIN) && defined(SIGRTMAX)
  for (int signal = SIGRTMIN; signal <= SIGRTMAX; ++signal) {
    signal_map->insert({signal, signal - SIGRTMIN + BRIDGE_SIGRTMIN});
  }
#endif  // defined(SIGRTMIN) && defined(SIGRTMAX)
  return signal_map;
}

const std::unordered_map<int, int> *GetSignalToBridgeSignalMap() {
  static const std::unordered_map<int, int> *signal_to_bridge_signal_map =
      CreateBridgeSignalMap();
  return signal_to_bridge_signal_map;
}

}  // namespace

sigset_t *FromBridgeSigSet(const bridge_sigset_t *bridge_set, sigset_t *set) {
  if (!bridge_set || !set) return nullptr;
  sigemptyset(set);
  for (auto signal : *GetSignalToBridgeSignalMap()) {
    if (BridgeSigIsMember(bridge_set, signal.second)) {
      sigaddset(set, signal.first);
    }
  }
  return set;
}

bridge_sigset_t *ToBridgeSigSet(const sigset_t *set,
                                bridge_sigset_t *bridge_set) {
  if (!set || !bridge_set) return nullptr;
  BridgeSigEmptySet(bridge_set);
  for (auto signal : *GetSignalToBridgeSignalMap()) {
    if (sigismember(set, signal.first)) {
      BridgeSigAddSet(bridge_set, signal.second);
    }
  }
  return bridge_set;
}

siginfo_t *FromBridgeSigInfo(const struct bridge_siginfo_t *bridge_siginfo,
                             siginfo_t *siginfo) {
  if (!bridge_siginfo || !siginfo) return nullptr;
  siginfo->si_signo = FromkLinuxSignalNumber(bridge_siginfo->si_signo);
  siginfo->si_code = FromkLinuxSignalCode(bridge_siginfo->si_code);
  return siginfo;
}

struct bridge_siginfo_t *ToBridgeSigInfo(
    const siginfo_t *siginfo, struct bridge_siginfo_t *bridge_siginfo) {
  if (!siginfo || !bridge_siginfo) return nullptr;
  bridge_siginfo->si_signo = TokLinuxSignalNumber(siginfo->si_signo);
  bridge_siginfo->si_code = TokLinuxSignalCode(siginfo->si_code);
  return bridge_siginfo;
}

}  // namespace asylo
