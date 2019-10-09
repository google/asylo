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

namespace asylo {
namespace {

int FromBridgeSysLogLevel(int bridge_syslog_level) {
  if (bridge_syslog_level == BRIDGE_LOG_EMERG) return LOG_EMERG;
  if (bridge_syslog_level == BRIDGE_LOG_ALERT) return LOG_ALERT;
  if (bridge_syslog_level == BRIDGE_LOG_CRIT) return LOG_CRIT;
  if (bridge_syslog_level == BRIDGE_LOG_ERR) return LOG_ERR;
  if (bridge_syslog_level == BRIDGE_LOG_WARNING) return LOG_WARNING;
  if (bridge_syslog_level == BRIDGE_LOG_NOTICE) return LOG_NOTICE;
  if (bridge_syslog_level == BRIDGE_LOG_INFO) return LOG_INFO;
  if (bridge_syslog_level == BRIDGE_LOG_DEBUG) return LOG_DEBUG;
  return 0;
}

int ToBridgeSysLogLevel(int syslog_level) {
  if (syslog_level == LOG_EMERG) return BRIDGE_LOG_EMERG;
  if (syslog_level == LOG_ALERT) return BRIDGE_LOG_ALERT;
  if (syslog_level == LOG_CRIT) return BRIDGE_LOG_CRIT;
  if (syslog_level == LOG_ERR) return BRIDGE_LOG_ERR;
  if (syslog_level == LOG_WARNING) return BRIDGE_LOG_WARNING;
  if (syslog_level == LOG_NOTICE) return BRIDGE_LOG_NOTICE;
  if (syslog_level == LOG_INFO) return BRIDGE_LOG_INFO;
  if (syslog_level == LOG_DEBUG) return BRIDGE_LOG_DEBUG;
  return 0;
}

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

int FromBridgeSignal(int bridge_signum) {
  for (auto signal : *GetSignalToBridgeSignalMap()) {
    if (bridge_signum == signal.second) {
      return signal.first;
    }
  }
  return -1;
}

int ToBridgeSignal(int signum) {
  auto iterator = GetSignalToBridgeSignalMap()->find(signum);
  if (iterator == GetSignalToBridgeSignalMap()->end()) {
    return -1;
  }
  return iterator->second;
}

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

int FromBridgeSignalCode(int bridge_si_code) {
  if (bridge_si_code == BRIDGE_SI_USER) return SI_USER;
  if (bridge_si_code == BRIDGE_SI_QUEUE) return SI_QUEUE;
  if (bridge_si_code == BRIDGE_SI_TIMER) return SI_TIMER;
  if (bridge_si_code == BRIDGE_SI_ASYNCIO) return SI_ASYNCIO;
  if (bridge_si_code == BRIDGE_SI_MESGQ) return SI_MESGQ;
  return -1;
}

int ToBridgeSignalCode(int si_code) {
  if (si_code == SI_USER) return BRIDGE_SI_USER;
  if (si_code == SI_QUEUE) return BRIDGE_SI_QUEUE;
  if (si_code == SI_TIMER) return BRIDGE_SI_TIMER;
  if (si_code == SI_ASYNCIO) return BRIDGE_SI_ASYNCIO;
  if (si_code == SI_MESGQ) return BRIDGE_SI_MESGQ;
  return -1;
}

siginfo_t *FromBridgeSigInfo(const struct bridge_siginfo_t *bridge_siginfo,
                             siginfo_t *siginfo) {
  if (!bridge_siginfo || !siginfo) return nullptr;
  siginfo->si_signo = FromBridgeSignal(bridge_siginfo->si_signo);
  siginfo->si_code = FromBridgeSignalCode(bridge_siginfo->si_code);
  return siginfo;
}

struct bridge_siginfo_t *ToBridgeSigInfo(
    const siginfo_t *siginfo, struct bridge_siginfo_t *bridge_siginfo) {
  if (!siginfo || !bridge_siginfo) return nullptr;
  bridge_siginfo->si_signo = ToBridgeSignal(siginfo->si_signo);
  bridge_siginfo->si_code = ToBridgeSignalCode(siginfo->si_code);
  return bridge_siginfo;
}

int FromBridgeSignalFlags(int bridge_sa_flags) {
  int sa_flags = 0;
  if (bridge_sa_flags & BRIDGE_SA_NODEFER) sa_flags |= SA_NODEFER;
  if (bridge_sa_flags & BRIDGE_SA_RESETHAND) sa_flags |= SA_RESETHAND;
  return sa_flags;
}

int ToBridgeSignalFlags(int sa_flags) {
  int bridge_sa_flags = 0;
  if (sa_flags & SA_NODEFER) bridge_sa_flags |= BRIDGE_SA_NODEFER;
  if (sa_flags & SA_RESETHAND) bridge_sa_flags |= BRIDGE_SA_RESETHAND;
  return bridge_sa_flags;
}

int FromBridgeSysLogOption(int bridge_syslog_option) {
  int syslog_option = 0;
  if (bridge_syslog_option & BRIDGE_LOG_PID) syslog_option |= LOG_PID;
  if (bridge_syslog_option & BRIDGE_LOG_CONS) syslog_option |= LOG_CONS;
  if (bridge_syslog_option & BRIDGE_LOG_ODELAY) syslog_option |= LOG_ODELAY;
  if (bridge_syslog_option & BRIDGE_LOG_NDELAY) syslog_option |= LOG_NDELAY;
  if (bridge_syslog_option & BRIDGE_LOG_NOWAIT) syslog_option |= LOG_NOWAIT;
  if (bridge_syslog_option & BRIDGE_LOG_PERROR) syslog_option |= LOG_PERROR;
  return syslog_option;
}

int ToBridgeSysLogOption(int syslog_option) {
  int bridge_syslog_option = 0;
  if (syslog_option & LOG_PID) bridge_syslog_option |= BRIDGE_LOG_PID;
  if (syslog_option & LOG_CONS) bridge_syslog_option |= BRIDGE_LOG_CONS;
  if (syslog_option & LOG_ODELAY) bridge_syslog_option |= BRIDGE_LOG_ODELAY;
  if (syslog_option & LOG_NDELAY) bridge_syslog_option |= BRIDGE_LOG_NDELAY;
  if (syslog_option & LOG_NOWAIT) bridge_syslog_option |= BRIDGE_LOG_NOWAIT;
  if (syslog_option & LOG_PERROR) bridge_syslog_option |= BRIDGE_LOG_PERROR;
  return bridge_syslog_option;
}

int FromBridgeSysLogFacility(int bridge_syslog_facility) {
  if (bridge_syslog_facility == BRIDGE_LOG_USER) return LOG_USER;
  if (bridge_syslog_facility == BRIDGE_LOG_LOCAL0) return LOG_LOCAL0;
  if (bridge_syslog_facility == BRIDGE_LOG_LOCAL1) return LOG_LOCAL1;
  if (bridge_syslog_facility == BRIDGE_LOG_LOCAL2) return LOG_LOCAL2;
  if (bridge_syslog_facility == BRIDGE_LOG_LOCAL3) return LOG_LOCAL3;
  if (bridge_syslog_facility == BRIDGE_LOG_LOCAL4) return LOG_LOCAL4;
  if (bridge_syslog_facility == BRIDGE_LOG_LOCAL5) return LOG_LOCAL5;
  if (bridge_syslog_facility == BRIDGE_LOG_LOCAL6) return LOG_LOCAL6;
  if (bridge_syslog_facility == BRIDGE_LOG_LOCAL7) return LOG_LOCAL7;
  return 0;
}

int ToBridgeSysLogFacility(int syslog_facility) {
  if (syslog_facility == LOG_USER) return BRIDGE_LOG_USER;
  if (syslog_facility == LOG_LOCAL0) return BRIDGE_LOG_LOCAL0;
  if (syslog_facility == LOG_LOCAL1) return BRIDGE_LOG_LOCAL1;
  if (syslog_facility == LOG_LOCAL2) return BRIDGE_LOG_LOCAL2;
  if (syslog_facility == LOG_LOCAL3) return BRIDGE_LOG_LOCAL3;
  if (syslog_facility == LOG_LOCAL4) return BRIDGE_LOG_LOCAL4;
  if (syslog_facility == LOG_LOCAL5) return BRIDGE_LOG_LOCAL5;
  if (syslog_facility == LOG_LOCAL6) return BRIDGE_LOG_LOCAL6;
  if (syslog_facility == LOG_LOCAL7) return BRIDGE_LOG_LOCAL7;
  return 0;
}

// Priorities are encoded into a single 32-bit integer. The bottom 3 bits are
// the level and the rest are the facility.
int FromBridgeSysLogPriority(int bridge_syslog_priority) {
  int bridge_syslog_level = bridge_syslog_priority & 0x07;
  int bridge_syslog_facility = bridge_syslog_priority & ~0x07;
  return FromBridgeSysLogLevel(bridge_syslog_level) |
         FromBridgeSysLogFacility(bridge_syslog_facility);
}

int ToBridgeSysLogPriority(int syslog_priority) {
  int syslog_level = syslog_priority & 0x07;
  int syslog_facility = syslog_priority & ~0x07;
  return ToBridgeSysLogLevel(syslog_level) |
         ToBridgeSysLogFacility(syslog_facility);
}

}  // namespace asylo
