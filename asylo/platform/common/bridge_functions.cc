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

bool BridgeWIfExited(BridgeWStatus bridge_wstatus) {
  return bridge_wstatus.code == 0;
}

bool BridgeWIfStopped(BridgeWStatus bridge_wstatus) {
  return bridge_wstatus.code == BRIDGE_WSTOPPED;
}

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

int FromBridgeTcpOptionName(int bridge_tcp_option_name) {
  if (bridge_tcp_option_name == BRIDGE_TCP_NODELAY) return TCP_NODELAY;
  if (bridge_tcp_option_name == BRIDGE_TCP_KEEPIDLE) return TCP_KEEPIDLE;
  if (bridge_tcp_option_name == BRIDGE_TCP_KEEPINTVL) return TCP_KEEPINTVL;
  if (bridge_tcp_option_name == BRIDGE_TCP_KEEPCNT) return TCP_KEEPCNT;
  return -1;
}

int FromBridgeIpV6OptionName(int bridge_ipv6_option_name) {
  if (bridge_ipv6_option_name == BRIDGE_IPV6_V6ONLY) return IPV6_V6ONLY;
  return -1;
}

int ToBridgeIpV6OptionName(int ipv6_option_name) {
  if (ipv6_option_name == IPV6_V6ONLY) return BRIDGE_IPV6_V6ONLY;
  return -1;
}

int ToBridgeTcpOptionName(int tcp_option_name) {
  if (tcp_option_name == TCP_NODELAY) return BRIDGE_TCP_NODELAY;
  if (tcp_option_name == TCP_KEEPIDLE) return BRIDGE_TCP_KEEPIDLE;
  if (tcp_option_name == TCP_KEEPINTVL) return BRIDGE_TCP_KEEPINTVL;
  if (tcp_option_name == TCP_KEEPCNT) return BRIDGE_TCP_KEEPCNT;
  return -1;
}

int FromBridgeSocketOptionName(int bridge_socket_option_name) {
  if (bridge_socket_option_name == BRIDGE_SO_DEBUG) return SO_DEBUG;
  if (bridge_socket_option_name == BRIDGE_SO_REUSEADDR) return SO_REUSEADDR;
  if (bridge_socket_option_name == BRIDGE_SO_TYPE) return SO_TYPE;
  if (bridge_socket_option_name == BRIDGE_SO_ERROR) return SO_ERROR;
  if (bridge_socket_option_name == BRIDGE_SO_DONTROUTE) return SO_DONTROUTE;
  if (bridge_socket_option_name == BRIDGE_SO_BROADCAST) return SO_BROADCAST;
  if (bridge_socket_option_name == BRIDGE_SO_SNDBUF) return SO_SNDBUF;
  if (bridge_socket_option_name == BRIDGE_SO_RCVBUF) return SO_RCVBUF;
  if (bridge_socket_option_name == BRIDGE_SO_SNDTIMEO) return SO_SNDTIMEO;
  if (bridge_socket_option_name == BRIDGE_SO_RCVTIMEO) return SO_RCVTIMEO;
  if (bridge_socket_option_name == BRIDGE_SO_SNDBUFFORCE) return SO_SNDBUFFORCE;
  if (bridge_socket_option_name == BRIDGE_SO_RCVBUFFORCE) return SO_RCVBUFFORCE;
  if (bridge_socket_option_name == BRIDGE_SO_KEEPALIVE) return SO_KEEPALIVE;
  if (bridge_socket_option_name == BRIDGE_SO_OOBINLINE) return SO_OOBINLINE;
  if (bridge_socket_option_name == BRIDGE_SO_NO_CHECK) return SO_NO_CHECK;
  if (bridge_socket_option_name == BRIDGE_SO_PRIORITY) return SO_PRIORITY;
  if (bridge_socket_option_name == BRIDGE_SO_LINGER) return SO_LINGER;
  if (bridge_socket_option_name == BRIDGE_SO_BSDCOMPAT) return SO_BSDCOMPAT;
  if (bridge_socket_option_name == BRIDGE_SO_REUSEPORT) return SO_REUSEPORT;
  return -1;
}

int ToBridgeSocketOptionName(int socket_option_name) {
  if (socket_option_name == SO_DEBUG) return BRIDGE_SO_DEBUG;
  if (socket_option_name == SO_REUSEADDR) return BRIDGE_SO_REUSEADDR;
  if (socket_option_name == SO_TYPE) return BRIDGE_SO_TYPE;
  if (socket_option_name == SO_ERROR) return BRIDGE_SO_ERROR;
  if (socket_option_name == SO_DONTROUTE) return BRIDGE_SO_DONTROUTE;
  if (socket_option_name == SO_BROADCAST) return BRIDGE_SO_BROADCAST;
  if (socket_option_name == SO_SNDBUF) return BRIDGE_SO_SNDBUF;
  if (socket_option_name == SO_RCVBUF) return BRIDGE_SO_RCVBUF;
  if (socket_option_name == SO_SNDTIMEO) return BRIDGE_SO_SNDTIMEO;
  if (socket_option_name == SO_RCVTIMEO) return BRIDGE_SO_RCVTIMEO;
  if (socket_option_name == SO_SNDBUFFORCE) return BRIDGE_SO_SNDBUFFORCE;
  if (socket_option_name == SO_RCVBUFFORCE) return BRIDGE_SO_RCVBUFFORCE;
  if (socket_option_name == SO_KEEPALIVE) return BRIDGE_SO_KEEPALIVE;
  if (socket_option_name == SO_OOBINLINE) return BRIDGE_SO_OOBINLINE;
  if (socket_option_name == SO_NO_CHECK) return BRIDGE_SO_NO_CHECK;
  if (socket_option_name == SO_PRIORITY) return BRIDGE_SO_PRIORITY;
  if (socket_option_name == SO_LINGER) return BRIDGE_SO_LINGER;
  if (socket_option_name == SO_BSDCOMPAT) return BRIDGE_SO_BSDCOMPAT;
  if (socket_option_name == SO_REUSEPORT) return BRIDGE_SO_REUSEPORT;
  return -1;
}

uint8_t BridgeFDIsSet(int fd, const struct BridgeFDSet *bridge_fds) {
  if (bridge_fds && fd < BRIDGE_FD_SETSIZE) {
    return bridge_fds->file_descriptor_set[fd];
  }
  return 0;
}

void BridgeFDSet(int fd, struct BridgeFDSet *bridge_fds) {
  if (bridge_fds && fd < BRIDGE_FD_SETSIZE) {
    bridge_fds->file_descriptor_set[fd] = 1;
  }
}

void BridgeFDZero(struct BridgeFDSet *bridge_fds) {
  if (bridge_fds) {
    for (int fd = 0; fd < BRIDGE_FD_SETSIZE; ++fd) {
      bridge_fds->file_descriptor_set[fd] = 0;
    }
  }
}

int FromBridgePollEvents(int events) {
  int result = 0;
  if (events & POLLIN) result |= BRIDGE_POLLIN;
  if (events & POLLPRI) result |= BRIDGE_POLLPRI;
  if (events & POLLOUT) result |= BRIDGE_POLLOUT;
  if (events & POLLRDHUP) result |= BRIDGE_POLLRDHUP;
  if (events & POLLERR) result |= BRIDGE_POLLERR;
  if (events & POLLHUP) result |= BRIDGE_POLLHUP;
  if (events & POLLNVAL) result |= BRIDGE_POLLNVAL;
  if (events & POLLRDNORM) result |= BRIDGE_POLLRDNORM;
  if (events & POLLRDBAND) result |= BRIDGE_POLLRDBAND;
  if (events & POLLWRNORM) result |= BRIDGE_POLLWRNORM;
  if (events & POLLWRBAND) result |= BRIDGE_POLLWRBAND;
  return result;
}

int ToBridgePollEvents(int bridge_events) {
  int result = 0;
  if (bridge_events & BRIDGE_POLLIN) result |= POLLIN;
  if (bridge_events & BRIDGE_POLLPRI) result |= POLLPRI;
  if (bridge_events & BRIDGE_POLLOUT) result |= POLLOUT;
  if (bridge_events & BRIDGE_POLLRDHUP) result |= POLLRDHUP;
  if (bridge_events & BRIDGE_POLLERR) result |= POLLERR;
  if (bridge_events & BRIDGE_POLLHUP) result |= POLLHUP;
  if (bridge_events & BRIDGE_POLLNVAL) result |= POLLNVAL;
  if (bridge_events & BRIDGE_POLLRDNORM) result |= POLLRDNORM;
  if (bridge_events & BRIDGE_POLLRDBAND) result |= POLLRDBAND;
  if (bridge_events & BRIDGE_POLLWRNORM) result |= POLLWRNORM;
  if (bridge_events & BRIDGE_POLLWRBAND) result |= POLLWRBAND;
  return result;
}

}  // namespace

int FromBridgeFLockOperation(int bridge_flock_operation) {
  int flock_operation = 0;
  if (bridge_flock_operation & BRIDGE_LOCK_SH) flock_operation |= LOCK_SH;
  if (bridge_flock_operation & BRIDGE_LOCK_EX) flock_operation |= LOCK_EX;
  if (bridge_flock_operation & BRIDGE_LOCK_NB) flock_operation |= LOCK_NB;
  if (bridge_flock_operation & BRIDGE_LOCK_UN) flock_operation |= LOCK_UN;
  return flock_operation;
}

int ToBridgeFLockOperation(int flock_operation) {
  int bridge_flock_operation = 0;
  if (flock_operation & LOCK_SH) bridge_flock_operation |= BRIDGE_LOCK_SH;
  if (flock_operation & LOCK_EX) bridge_flock_operation |= BRIDGE_LOCK_EX;
  if (flock_operation & LOCK_NB) bridge_flock_operation |= BRIDGE_LOCK_NB;
  if (flock_operation & LOCK_UN) bridge_flock_operation |= BRIDGE_LOCK_UN;
  return bridge_flock_operation;
}

int FromBridgeSysconfConstants(enum SysconfConstants bridge_sysconf_constant) {
  switch (bridge_sysconf_constant) {
    case BRIDGE_SC_NPROCESSORS_CONF:
      return _SC_NPROCESSORS_CONF;
    case BRIDGE_SC_NPROCESSORS_ONLN:
      return _SC_NPROCESSORS_ONLN;
    default:
      return -1;
  }
}

enum SysconfConstants ToBridgeSysconfConstants(int sysconf_constant) {
  switch (sysconf_constant) {
    case _SC_NPROCESSORS_CONF:
      return BRIDGE_SC_NPROCESSORS_CONF;
    case _SC_NPROCESSORS_ONLN:
      return BRIDGE_SC_NPROCESSORS_ONLN;
    default:
      return BRIDGE_SC_UNKNOWN;
  }
}

int FromBridgeTimerType(enum TimerType bridge_timer_type) {
  if (bridge_timer_type == BRIDGE_ITIMER_REAL) return ITIMER_REAL;
  if (bridge_timer_type == BRIDGE_ITIMER_VIRTUAL) return ITIMER_VIRTUAL;
  if (bridge_timer_type == BRIDGE_ITIMER_PROF) return ITIMER_PROF;
  return -1;
}

enum TimerType ToBridgeTimerType(int timer_type) {
  if (timer_type == ITIMER_REAL) return BRIDGE_ITIMER_REAL;
  if (timer_type == ITIMER_VIRTUAL) return BRIDGE_ITIMER_VIRTUAL;
  if (timer_type == ITIMER_PROF) return BRIDGE_ITIMER_PROF;
  return BRIDGE_ITIMER_UNKNOWN;
}

int FromBridgeWaitOptions(int bridge_wait_options) {
  int wait_options = 0;
  if (bridge_wait_options & BRIDGE_WNOHANG) wait_options |= WNOHANG;
  return wait_options;
}

int ToBridgeWaitOptions(int wait_options) {
  int bridge_wait_options = 0;
  if (wait_options & WNOHANG) bridge_wait_options |= BRIDGE_WNOHANG;
  return bridge_wait_options;
}

int FromBridgeRUsageTarget(enum RUsageTarget bridge_rusage_target) {
  if (bridge_rusage_target == BRIDGE_RUSAGE_SELF) return RUSAGE_SELF;
  if (bridge_rusage_target == BRIDGE_RUSAGE_CHILDREN) return RUSAGE_CHILDREN;
  return -1;
}

enum RUsageTarget ToBridgeRUsageTarget(int rusage_target) {
  if (rusage_target == RUSAGE_SELF) return BRIDGE_RUSAGE_SELF;
  if (rusage_target == RUSAGE_CHILDREN) return BRIDGE_RUSAGE_CHILDREN;
  return BRIDGE_RUSAGE_UNKNOWN;
}

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

int FromBridgeSigMaskAction(int bridge_how) {
  if (bridge_how == BRIDGE_SIG_BLOCK) return SIG_BLOCK;
  if (bridge_how == BRIDGE_SIG_UNBLOCK) return SIG_UNBLOCK;
  if (bridge_how == BRIDGE_SIG_SETMASK) return SIG_SETMASK;
  return -1;
}

int ToBridgeSigMaskAction(int how) {
  if (how == SIG_BLOCK) return BRIDGE_SIG_BLOCK;
  if (how == SIG_UNBLOCK) return BRIDGE_SIG_UNBLOCK;
  if (how == SIG_SETMASK) return BRIDGE_SIG_SETMASK;
  return -1;
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

int FromBridgeAddressInfoFlags(int bridge_ai_flag) {
  int ai_flag = 0;
  if (bridge_ai_flag & BRIDGE_AI_CANONNAME) ai_flag |= AI_CANONNAME;
  if (bridge_ai_flag & BRIDGE_AI_NUMERICHOST) ai_flag |= AI_NUMERICHOST;
  if (bridge_ai_flag & BRIDGE_AI_V4MAPPED) ai_flag |= AI_V4MAPPED;
  if (bridge_ai_flag & BRIDGE_AI_ADDRCONFIG) ai_flag |= AI_ADDRCONFIG;
  if (bridge_ai_flag & BRIDGE_AI_ALL) ai_flag |= AI_ALL;
  if (bridge_ai_flag & BRIDGE_AI_PASSIVE) ai_flag |= AI_PASSIVE;
  if (bridge_ai_flag & BRIDGE_AI_NUMERICSERV) ai_flag |= AI_NUMERICSERV;
  if (bridge_ai_flag & BRIDGE_AI_IDN) ai_flag |= AI_IDN;
  if (bridge_ai_flag & BRIDGE_AI_CANONIDN) ai_flag |= AI_CANONIDN;
  if (bridge_ai_flag & BRIDGE_AI_IDN_ALLOW_UNASSIGNED) {
    ai_flag |= AI_IDN_ALLOW_UNASSIGNED;
  }
  if (bridge_ai_flag & BRIDGE_AI_IDN_USE_STD3_ASCII_RULES) {
    ai_flag |= AI_IDN_USE_STD3_ASCII_RULES;
  }
  return ai_flag;
}

int ToBridgeAddressInfoFlags(int ai_flag) {
  int bridge_ai_flag = 0;
  if (ai_flag & AI_CANONNAME) bridge_ai_flag |= BRIDGE_AI_CANONNAME;
  if (ai_flag & AI_NUMERICHOST) bridge_ai_flag |= BRIDGE_AI_NUMERICHOST;
  if (ai_flag & AI_V4MAPPED) bridge_ai_flag |= BRIDGE_AI_V4MAPPED;
  if (ai_flag & AI_ADDRCONFIG) bridge_ai_flag |= BRIDGE_AI_ADDRCONFIG;
  if (ai_flag & AI_ALL) bridge_ai_flag |= BRIDGE_AI_ALL;
  if (ai_flag & AI_PASSIVE) bridge_ai_flag |= BRIDGE_AI_PASSIVE;
  if (ai_flag & AI_NUMERICSERV) bridge_ai_flag |= BRIDGE_AI_NUMERICSERV;
  if (ai_flag & AI_IDN) bridge_ai_flag |= BRIDGE_AI_IDN;
  if (ai_flag & AI_CANONIDN) bridge_ai_flag |= BRIDGE_AI_CANONIDN;
  if (ai_flag & AI_IDN_ALLOW_UNASSIGNED) {
    bridge_ai_flag |= BRIDGE_AI_IDN_ALLOW_UNASSIGNED;
  }
  if (ai_flag & AI_IDN_USE_STD3_ASCII_RULES) {
    bridge_ai_flag |= BRIDGE_AI_IDN_USE_STD3_ASCII_RULES;
  }
  return bridge_ai_flag;
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

int FromBridgeFcntlCmd(int bridge_fcntl_cmd) {
  switch (bridge_fcntl_cmd) {
    case BRIDGE_F_GETFD:
      return F_GETFD;
    case BRIDGE_F_SETFD:
      return F_SETFD;
    case BRIDGE_F_GETFL:
      return F_GETFL;
    case BRIDGE_F_SETFL:
      return F_SETFL;
    case BRIDGE_F_GETPIPE_SZ:
      return F_GETPIPE_SZ;
    case BRIDGE_F_SETPIPE_SZ:
      return F_SETPIPE_SZ;
    default:
      return -1;
  }
}

int ToBridgeFcntlCmd(int fcntl_cmd) {
  switch (fcntl_cmd) {
    case F_GETFD:
      return BRIDGE_F_GETFD;
    case F_SETFD:
      return BRIDGE_F_SETFD;
    case F_GETFL:
      return BRIDGE_F_GETFL;
    case F_SETFL:
      return BRIDGE_F_SETFL;
    case F_GETPIPE_SZ:
      return BRIDGE_F_GETPIPE_SZ;
    case F_SETPIPE_SZ:
      return BRIDGE_F_SETPIPE_SZ;
    default:
      return -1;
  }
}

int FromBridgeFileFlags(int bridge_file_flag) {
  int file_flag = 0;
  if (bridge_file_flag & BRIDGE_RDONLY) file_flag |= O_RDONLY;
  if (bridge_file_flag & BRIDGE_WRONLY) file_flag |= O_WRONLY;
  if (bridge_file_flag & BRIDGE_RDWR) file_flag |= O_RDWR;
  if (bridge_file_flag & BRIDGE_CREAT) file_flag |= O_CREAT;
  if (bridge_file_flag & BRIDGE_APPEND) file_flag |= O_APPEND;
  if (bridge_file_flag & BRIDGE_EXCL) file_flag |= O_EXCL;
  if (bridge_file_flag & BRIDGE_TRUNC) file_flag |= O_TRUNC;
  if (bridge_file_flag & BRIDGE_NONBLOCK) file_flag |= O_NONBLOCK;
  if (bridge_file_flag & BRIDGE_DIRECT) file_flag |= O_DIRECT;
  if (bridge_file_flag & BRIDGE_O_CLOEXEC) file_flag |= O_CLOEXEC;
  return file_flag;
}

int ToBridgeFileFlags(int file_flag) {
  int bridge_file_flag = 0;
  if (file_flag & O_RDONLY) bridge_file_flag |= BRIDGE_RDONLY;
  if (file_flag & O_WRONLY) bridge_file_flag |= BRIDGE_WRONLY;
  if (file_flag & O_RDWR) bridge_file_flag |= BRIDGE_RDWR;
  if (file_flag & O_CREAT) bridge_file_flag |= BRIDGE_CREAT;
  if (file_flag & O_APPEND) bridge_file_flag |= BRIDGE_APPEND;
  if (file_flag & O_EXCL) bridge_file_flag |= BRIDGE_EXCL;
  if (file_flag & O_TRUNC) bridge_file_flag |= BRIDGE_TRUNC;
  if (file_flag & O_NONBLOCK) bridge_file_flag |= BRIDGE_NONBLOCK;
  if (file_flag & O_DIRECT) bridge_file_flag |= BRIDGE_DIRECT;
  if (file_flag & O_CLOEXEC) bridge_file_flag |= BRIDGE_O_CLOEXEC;
  return bridge_file_flag;
}

int FromBridgeFDFlags(int bridge_fd_flag) {
  int fd_flag = 0;
  if (bridge_fd_flag & BRIDGE_CLOEXEC) fd_flag |= FD_CLOEXEC;
  return fd_flag;
}

int ToBridgeFDFlags(int fd_flag) {
  int bridge_fd_flag = 0;
  if (fd_flag & FD_CLOEXEC) bridge_fd_flag |= BRIDGE_CLOEXEC;
  return bridge_fd_flag;
}

int FromBridgeOptionName(int level, int bridge_option_name) {
  if (level == IPPROTO_TCP) {
    return FromBridgeTcpOptionName(bridge_option_name);
  }
  if (level == IPPROTO_IPV6) {
    return FromBridgeIpV6OptionName(bridge_option_name);
  }
  if (level == SOL_SOCKET) {
    return FromBridgeSocketOptionName(bridge_option_name);
  }
  return -1;
}

int ToBridgeOptionName(int level, int option_name) {
  if (level == IPPROTO_TCP) {
    return ToBridgeTcpOptionName(option_name);
  }
  if (level == IPPROTO_IPV6) {
    return ToBridgeIpV6OptionName(option_name);
  }
  if (level == SOL_SOCKET) {
    return ToBridgeSocketOptionName(option_name);
  }
  return -1;
}

struct stat *FromBridgeStat(const struct bridge_stat *bridge_statbuf,
                            struct stat *statbuf) {
  if (!bridge_statbuf || !statbuf) return nullptr;
  statbuf->st_dev = bridge_statbuf->st_dev;
  statbuf->st_ino = bridge_statbuf->st_ino;
  statbuf->st_mode = bridge_statbuf->st_mode;
  statbuf->st_nlink = bridge_statbuf->st_nlink;
  statbuf->st_uid = bridge_statbuf->st_uid;
  statbuf->st_gid = bridge_statbuf->st_gid;
  statbuf->st_rdev = bridge_statbuf->st_rdev;
  statbuf->st_size = bridge_statbuf->st_size;
  statbuf->st_atime = bridge_statbuf->st_atime_enc;
  statbuf->st_mtime = bridge_statbuf->st_mtime_enc;
  statbuf->st_ctime = bridge_statbuf->st_ctime_enc;
  statbuf->st_blksize = bridge_statbuf->st_blksize;
  statbuf->st_blocks = bridge_statbuf->st_blocks;
  return statbuf;
}

struct bridge_stat *ToBridgeStat(const struct stat *statbuf,
                                 struct bridge_stat *bridge_statbuf) {
  if (!statbuf || !bridge_statbuf) return nullptr;
  bridge_statbuf->st_dev = statbuf->st_dev;
  bridge_statbuf->st_ino = statbuf->st_ino;
  bridge_statbuf->st_mode = statbuf->st_mode;
  bridge_statbuf->st_nlink = statbuf->st_nlink;
  bridge_statbuf->st_uid = statbuf->st_uid;
  bridge_statbuf->st_gid = statbuf->st_gid;
  bridge_statbuf->st_rdev = statbuf->st_rdev;
  bridge_statbuf->st_size = statbuf->st_size;
  bridge_statbuf->st_atime_enc = statbuf->st_atime;
  bridge_statbuf->st_mtime_enc = statbuf->st_mtime;
  bridge_statbuf->st_ctime_enc = statbuf->st_ctime;
  bridge_statbuf->st_blksize = statbuf->st_blksize;
  bridge_statbuf->st_blocks = statbuf->st_blocks;
  return bridge_statbuf;
}

template <typename T, typename U>
void ReinterpretCopySingle(T *dst, const U *src) {
  memcpy(dst, src, std::min(sizeof(T), sizeof(U)));
}

template <typename T, size_t M, typename U, size_t N>
void ReinterpretCopyArray(T (&dst)[M], const U (&src)[N],
                          size_t max_len = SIZE_MAX) {
  memcpy(dst, src, std::min(max_len, std::min(sizeof(T) * M, sizeof(U) * N)));
}

template <typename T>
void InitializeToZeroSingle(T *ptr) {
  memset(ptr, 0, sizeof(T));
}

template <typename T, size_t M>
void InitializeToZeroArray(T (&ptr)[M]) {
  memset(ptr, 0, sizeof(T) * M);
}

// Helper for implementing standard POSIX semantics for returning sockaddr
// structures. CopySockaddr copies the sockaddr in |source|, of length
// |source_len|, into the buffer pointed to by |addr_dest|, which has
// |addrlen_dest| bytes available. The copy is truncated if the destination
// buffer is too small. The number of bytes in the un-truncated structure is
// written to addrlen_dest.
//
// Returns |addr_dest|.
static struct sockaddr *CopySockaddr(void *source, socklen_t source_len,
                                     struct sockaddr *addr_dest,
                                     socklen_t *addrlen_dest) {
  memcpy(addr_dest, source, std::min(*addrlen_dest, source_len));
  *addrlen_dest = source_len;
  return addr_dest;
}

struct sockaddr *FromBridgeSockaddr(const struct bridge_sockaddr *bridge_addr,
                                    struct sockaddr *addr, socklen_t *addrlen) {
  if (bridge_addr == nullptr || addr == nullptr || addrlen == nullptr) {
    return nullptr;
  }
  sa_family_t family = FromBridgeAfFamily(bridge_addr->sa_family);
  if (family == AF_UNIX || family == AF_LOCAL) {
    struct sockaddr_un sockaddr_un_out;
    sockaddr_un_out.sun_family = family;
    InitializeToZeroArray(sockaddr_un_out.sun_path);
    ReinterpretCopyArray(sockaddr_un_out.sun_path,
                         bridge_addr->addr_un.sun_path,
                         bridge_addr->addr_un.len - sizeof(family));
    return CopySockaddr(&sockaddr_un_out, bridge_addr->addr_un.len, addr,
                        addrlen);
  } else if (family == AF_INET6) {
    struct sockaddr_in6 sockaddr_in6_out;
    sockaddr_in6_out.sin6_family = family;
    sockaddr_in6_out.sin6_port = bridge_addr->addr_in6.sin6_port;
    sockaddr_in6_out.sin6_flowinfo = bridge_addr->addr_in6.sin6_flowinfo;
    InitializeToZeroSingle(&sockaddr_in6_out.sin6_addr);
    ReinterpretCopySingle(&sockaddr_in6_out.sin6_addr,
                          &bridge_addr->addr_in6.sin6_addr);
    sockaddr_in6_out.sin6_scope_id = bridge_addr->addr_in6.sin6_scope_id;
    return CopySockaddr(&sockaddr_in6_out, sizeof(sockaddr_in6_out), addr,
                        addrlen);
  } else if (family == AF_INET) {
    struct sockaddr_in sockaddr_in_out;
    sockaddr_in_out.sin_family = family;
    sockaddr_in_out.sin_port = bridge_addr->addr_in.sin_port;
    InitializeToZeroSingle(&sockaddr_in_out.sin_addr);
    ReinterpretCopySingle(&sockaddr_in_out.sin_addr,
                          &bridge_addr->addr_in.sin_addr);
    InitializeToZeroArray(sockaddr_in_out.sin_zero);
    ReinterpretCopyArray(sockaddr_in_out.sin_zero,
                         bridge_addr->addr_in.sin_zero);
    return CopySockaddr(&sockaddr_in_out, sizeof(sockaddr_in_out), addr,
                        addrlen);
  } else if (family == AF_UNSPEC) {
    struct sockaddr sockaddr_out;
    sockaddr_out.sa_family = family;
    return CopySockaddr(&sockaddr_out, sizeof(sockaddr_out), addr, addrlen);
  } else {
    LOG(ERROR) << "sockaddr family is not supported: " << family;
    abort();
  }
}

struct bridge_sockaddr *ToBridgeSockaddr(const struct sockaddr *addr,
                                         socklen_t addrlen,
                                         struct bridge_sockaddr *bridge_addr) {
  if (!addr || !bridge_addr) return nullptr;
  bridge_addr->sa_family = ToBridgeAfFamily(addr->sa_family);
  if (bridge_addr->sa_family == BRIDGE_AF_UNSUPPORTED) {
    return nullptr;
  }
  if (bridge_addr->sa_family == BRIDGE_AF_UNIX ||
      bridge_addr->sa_family == BRIDGE_AF_LOCAL) {
    struct sockaddr_un *sockaddr_un_in = const_cast<struct sockaddr_un *>(
        reinterpret_cast<const struct sockaddr_un *>(addr));
    InitializeToZeroArray(bridge_addr->addr_un.sun_path);
    if (addrlen <= sizeof(bridge_addr->sa_family)) {
      return nullptr;
    }
    ReinterpretCopyArray(bridge_addr->addr_un.sun_path,
                         sockaddr_un_in->sun_path,
                         addrlen - sizeof(bridge_addr->sa_family));
    bridge_addr->addr_un.len = addrlen;
  } else if (bridge_addr->sa_family == BRIDGE_AF_INET6) {
    if (addrlen < sizeof(struct sockaddr_in6)) {
      return nullptr;
    }
    struct sockaddr_in6 *sockaddr_in6_in = const_cast<struct sockaddr_in6 *>(
        reinterpret_cast<const struct sockaddr_in6 *>(addr));
    bridge_addr->addr_in6.sin6_port = sockaddr_in6_in->sin6_port;
    bridge_addr->addr_in6.sin6_flowinfo = sockaddr_in6_in->sin6_flowinfo;
    InitializeToZeroSingle(&bridge_addr->addr_in6.sin6_addr);
    ReinterpretCopySingle(&bridge_addr->addr_in6.sin6_addr,
                          &sockaddr_in6_in->sin6_addr);
    bridge_addr->addr_in6.sin6_scope_id = sockaddr_in6_in->sin6_scope_id;
  } else if (bridge_addr->sa_family == BRIDGE_AF_INET) {
    if (addrlen < sizeof(struct sockaddr_in)) {
      return nullptr;
    }
    struct sockaddr_in *sockaddr_in_in = const_cast<struct sockaddr_in *>(
        reinterpret_cast<const struct sockaddr_in *>(addr));
    bridge_addr->addr_in.sin_port = sockaddr_in_in->sin_port;
    InitializeToZeroSingle(&bridge_addr->addr_in.sin_addr);
    ReinterpretCopySingle(&bridge_addr->addr_in.sin_addr,
                          &sockaddr_in_in->sin_addr);
    InitializeToZeroArray(bridge_addr->addr_in.sin_zero);
    ReinterpretCopyArray(bridge_addr->addr_in.sin_zero,
                         sockaddr_in_in->sin_zero);
  } else if (bridge_addr->sa_family == BRIDGE_AF_UNSPEC) {
    // Do nothing
  } else {
    LOG(ERROR) << "sockaddr family is not supported: "
               << bridge_addr->sa_family;
    abort();
  }
  return bridge_addr;
}

int FromBridgeAddressInfoErrors(int bridge_eai_code) {
  switch (bridge_eai_code) {
    case BRIDGE_EAI_SUCCESS:
      return 0;
    case BRIDGE_EAI_ADDRFAMILY:
      return EAI_ADDRFAMILY;
    case BRIDGE_EAI_BADFLAGS:
      return EAI_BADFLAGS;
    case BRIDGE_EAI_NONAME:
      return EAI_NONAME;
    case BRIDGE_EAI_AGAIN:
      return EAI_AGAIN;
    case BRIDGE_EAI_FAIL:
      return EAI_FAIL;
    case BRIDGE_EAI_FAMILY:
      return EAI_FAMILY;
    case BRIDGE_EAI_MEMORY:
      return EAI_MEMORY;
    case BRIDGE_EAI_NODATA:
      return EAI_NODATA;
    case BRIDGE_EAI_SERVICE:
      return EAI_SERVICE;
    case BRIDGE_EAI_SOCKTYPE:
      return EAI_SOCKTYPE;
    case BRIDGE_EAI_OVERFLOW:
      return EAI_OVERFLOW;
    case BRIDGE_EAI_INPROGRESS:
      return EAI_INPROGRESS;
    case BRIDGE_EAI_CANCELED:
      return EAI_CANCELED;
    case BRIDGE_EAI_ALLDONE:
      return EAI_ALLDONE;
    case BRIDGE_EAI_SYSTEM:
      return EAI_SYSTEM;
    default:
      return 1;
  }
}

int ToBridgeAddressInfoErrors(int eai_code) {
  switch (eai_code) {
    case 0:
      return BRIDGE_EAI_SUCCESS;
    case EAI_BADFLAGS:
      return BRIDGE_EAI_BADFLAGS;
    case EAI_NONAME:
      return BRIDGE_EAI_NONAME;
    case EAI_AGAIN:
      return BRIDGE_EAI_AGAIN;
    case EAI_FAIL:
      return BRIDGE_EAI_FAIL;
    case EAI_FAMILY:
      return BRIDGE_EAI_FAMILY;
    case EAI_SOCKTYPE:
      return BRIDGE_EAI_SOCKTYPE;
    case EAI_SERVICE:
      return BRIDGE_EAI_SERVICE;
    case EAI_MEMORY:
      return BRIDGE_EAI_MEMORY;
    case EAI_SYSTEM:
      return BRIDGE_EAI_SYSTEM;
    case EAI_OVERFLOW:
      return BRIDGE_EAI_OVERFLOW;
    case EAI_NODATA:
      return BRIDGE_EAI_NODATA;
    case EAI_ADDRFAMILY:
      return BRIDGE_EAI_ADDRFAMILY;
    case EAI_INPROGRESS:
      return BRIDGE_EAI_INPROGRESS;
    case EAI_CANCELED:
      return BRIDGE_EAI_CANCELED;
    case EAI_ALLDONE:
      return BRIDGE_EAI_ALLDONE;
    case EAI_INTR:
      return BRIDGE_EAI_IDN_ENCODE;
    default:
      return BRIDGE_EAI_UNKNOWN;
  }
}

AfFamily ToBridgeAfFamily(int af_family) {
  // AF_UNIX and AF_LOCAL may be the same value, so they are outside the switch
  // statement.
  if (af_family == AF_UNIX) return BRIDGE_AF_UNIX;
  if (af_family == AF_LOCAL) return BRIDGE_AF_LOCAL;
  switch (af_family) {
    case AF_INET:
      return BRIDGE_AF_INET;
    case AF_INET6:
      return BRIDGE_AF_INET6;
    case AF_UNSPEC:
      return BRIDGE_AF_UNSPEC;
    case AF_IPX:
      return BRIDGE_AF_IPX;
    case AF_NETLINK:
      return BRIDGE_AF_NETLINK;
    case AF_X25:
      return BRIDGE_AF_X25;
    case AF_AX25:
      return BRIDGE_AF_AX25;
    case AF_ATMPVC:
      return BRIDGE_AF_ATMPVC;
    case AF_APPLETALK:
      return BRIDGE_AF_APPLETALK;
    case AF_PACKET:
      return BRIDGE_AF_PACKET;
    case AF_ALG:
      return BRIDGE_AF_ALG;
    default:
      LOG(ERROR) << "Unsupported address family: " << af_family;
      return BRIDGE_AF_UNSUPPORTED;
  }
}

int FromBridgeAfFamily(int bridge_af_family) {
  switch (bridge_af_family) {
    case BRIDGE_AF_INET:
      return AF_INET;
    case BRIDGE_AF_INET6:
      return AF_INET6;
    case BRIDGE_AF_UNSPEC:
      return AF_UNSPEC;
    case BRIDGE_AF_UNIX:
      return AF_UNIX;
    case BRIDGE_AF_LOCAL:
      return AF_LOCAL;
    case BRIDGE_AF_IPX:
      return AF_IPX;
    case BRIDGE_AF_NETLINK:
      return AF_NETLINK;
    case BRIDGE_AF_X25:
      return AF_X25;
    case BRIDGE_AF_AX25:
      return AF_AX25;
    case BRIDGE_AF_ATMPVC:
      return AF_ATMPVC;
    case BRIDGE_AF_APPLETALK:
      return AF_APPLETALK;
    case BRIDGE_AF_PACKET:
      return AF_PACKET;
    case BRIDGE_AF_ALG:
      return AF_ALG;
    default:
      return AF_UNSPEC;
  }
}

int FromBridgeSocketType(int bridge_sock_type) {
  int sock_type = 0;
  int enum_bits = bridge_sock_type & (~BRIDGE_SOCK_TYPE_FLAGS);
  switch (enum_bits) {
    case BRIDGE_SOCK_STREAM:
      sock_type = SOCK_STREAM;
      break;
    case BRIDGE_SOCK_DGRAM:
      sock_type = SOCK_DGRAM;
      break;
    case BRIDGE_SOCK_SEQPACKET:
      sock_type = SOCK_SEQPACKET;
      break;
    case BRIDGE_SOCK_RAW:
      sock_type = SOCK_RAW;
      break;
    case BRIDGE_SOCK_RDM:
      sock_type = SOCK_RDM;
      break;
    case BRIDGE_SOCK_PACKET:
      sock_type = SOCK_PACKET;
      break;
    default:
      return -1;  // Unsupported
  }
  if (bridge_sock_type & BRIDGE_SOCK_O_NONBLOCK) sock_type |= SOCK_NONBLOCK;
  if (bridge_sock_type & BRIDGE_SOCK_O_CLOEXEC) sock_type |= SOCK_CLOEXEC;
  return sock_type;
}

int ToBridgeSocketType(int sock_type) {
  constexpr int kSockTypeFlagMask = ~(SOCK_CLOEXEC | SOCK_NONBLOCK);
  int bridge_sock_type = 0;
  int enum_bits = sock_type & kSockTypeFlagMask;
  switch (enum_bits) {
    case SOCK_STREAM:
      bridge_sock_type = BRIDGE_SOCK_STREAM;
      break;
    case SOCK_DGRAM:
      bridge_sock_type = BRIDGE_SOCK_DGRAM;
      break;
    case SOCK_SEQPACKET:
      bridge_sock_type = BRIDGE_SOCK_SEQPACKET;
      break;
    case SOCK_RAW:
      bridge_sock_type = BRIDGE_SOCK_RAW;
      break;
    case SOCK_RDM:
      bridge_sock_type = BRIDGE_SOCK_RDM;
      break;
    case SOCK_PACKET:
      bridge_sock_type = BRIDGE_SOCK_PACKET;
      break;
    default:
      return BRIDGE_SOCK_UNSUPPORTED;
  }
  if (sock_type & SOCK_NONBLOCK) bridge_sock_type |= BRIDGE_SOCK_O_NONBLOCK;
  if (sock_type & SOCK_CLOEXEC) bridge_sock_type |= BRIDGE_SOCK_O_CLOEXEC;
  return bridge_sock_type;
}

struct pollfd *FromBridgePollfd(const struct bridge_pollfd *bridge_fd,
                                struct pollfd *fd) {
  if (!bridge_fd || !fd) return nullptr;
  fd->fd = bridge_fd->fd;
  fd->events = FromBridgePollEvents(bridge_fd->events);
  fd->revents = FromBridgePollEvents(bridge_fd->revents);
  return fd;
}

struct bridge_pollfd *ToBridgePollfd(const struct pollfd *fd,
                                     struct bridge_pollfd *bridge_fd) {
  if (!fd || !bridge_fd) return nullptr;
  bridge_fd->fd = fd->fd;
  bridge_fd->events = ToBridgePollEvents(fd->events);
  bridge_fd->revents = ToBridgePollEvents(fd->revents);
  return bridge_fd;
}

struct msghdr *FromBridgeMsgHdr(const struct bridge_msghdr *bridge_msg,
                                struct msghdr *msg) {
  if (!bridge_msg || !msg) return nullptr;
  msg->msg_name = bridge_msg->msg_name;
  msg->msg_namelen = bridge_msg->msg_namelen;
  msg->msg_iov = reinterpret_cast<struct iovec *>(bridge_msg->msg_iov);
  msg->msg_iovlen = bridge_msg->msg_iovlen;
  msg->msg_control = bridge_msg->msg_control;
  msg->msg_controllen = bridge_msg->msg_controllen;
  msg->msg_flags = bridge_msg->msg_flags;
  return msg;
}

struct bridge_msghdr *ToBridgeMsgHdr(const struct msghdr *msg,
                                     struct bridge_msghdr *bridge_msg) {
  if (!msg || !bridge_msg) return nullptr;
  bridge_msg->msg_name = msg->msg_name;
  bridge_msg->msg_namelen = msg->msg_namelen;
  bridge_msg->msg_iov = reinterpret_cast<struct bridge_iovec *>(msg->msg_iov);
  bridge_msg->msg_iovlen = msg->msg_iovlen;
  bridge_msg->msg_control = msg->msg_control;
  bridge_msg->msg_controllen = msg->msg_controllen;
  bridge_msg->msg_flags = msg->msg_flags;
  return bridge_msg;
}

struct msghdr *FromBridgeIovecArray(const struct bridge_msghdr *bridge_msg,
                                    struct msghdr *msg) {
  if (!bridge_msg || !msg) return nullptr;
  for (uint64_t i = 0; i < bridge_msg->msg_iovlen; ++i) {
    memcpy(msg->msg_iov[i].iov_base, bridge_msg->msg_iov[i].iov_base,
           bridge_msg->msg_iov[i].iov_len);
  }
  return msg;
}

struct bridge_msghdr *ToBridgeIovecArray(const struct msghdr *msg,
                                         struct bridge_msghdr *bridge_msg) {
  if (!msg || !bridge_msg) return nullptr;
  for (uint64_t i = 0; i < msg->msg_iovlen; ++i) {
    memcpy(bridge_msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_base,
           msg->msg_iov[i].iov_len);
  }
  return bridge_msg;
}

struct iovec *FromBridgeIovec(const struct bridge_iovec *bridge_iov,
                              struct iovec *iov) {
  if (!bridge_iov || !iov) return nullptr;
  iov->iov_base = bridge_iov->iov_base;
  iov->iov_len = bridge_iov->iov_len;
  return iov;
}

struct bridge_iovec *ToBridgeIovec(const struct iovec *iov,
                                   struct bridge_iovec *bridge_iov) {
  if (!iov || !bridge_iov) return nullptr;
  bridge_iov->iov_base = iov->iov_base;
  bridge_iov->iov_len = iov->iov_len;
  return bridge_iov;
}

struct tms *FromBridgeTms(const struct BridgeTms *bridge_times,
                          struct tms *times) {
  if (!bridge_times || !times) return nullptr;
  times->tms_utime = bridge_times->tms_utime;
  times->tms_stime = bridge_times->tms_stime;
  times->tms_cutime = bridge_times->tms_cutime;
  times->tms_cstime = bridge_times->tms_cstime;
  return times;
}

struct BridgeTms *ToBridgeTms(const struct tms *times,
                              struct BridgeTms *bridge_times) {
  if (!times || !bridge_times) return nullptr;
  bridge_times->tms_utime = times->tms_utime;
  bridge_times->tms_stime = times->tms_stime;
  bridge_times->tms_cutime = times->tms_cutime;
  bridge_times->tms_cstime = times->tms_cstime;
  return bridge_times;
}

struct timespec *FromBridgeTimespec(const struct bridge_timespec *bridge_tp,
                                    struct timespec *tp) {
  tp->tv_sec = bridge_tp->tv_sec;
  tp->tv_nsec = bridge_tp->tv_nsec;
  return tp;
}

struct bridge_timespec *ToBridgeTimespec(const struct timespec *tp,
                                         struct bridge_timespec *bridge_tp) {
  bridge_tp->tv_sec = tp->tv_sec;
  bridge_tp->tv_nsec = tp->tv_nsec;
  return bridge_tp;
}

struct utimbuf *FromBridgeUtimbuf(const struct bridge_utimbuf *bridge_ut,
                                  struct utimbuf *ut) {
  if (!ut || !bridge_ut) return nullptr;
  ut->actime = bridge_ut->actime;
  ut->modtime = bridge_ut->modtime;
  return ut;
}

struct bridge_utimbuf *ToBridgeUtimbuf(const struct utimbuf *ut,
                                       struct bridge_utimbuf *bridge_ut) {
  if (!ut || !bridge_ut) return nullptr;
  bridge_ut->actime = ut->actime;
  bridge_ut->modtime = ut->modtime;
  return bridge_ut;
}

struct timeval *FromBridgeTimeVal(const struct bridge_timeval *bridge_tv,
                                  struct timeval *tv) {
  if (!bridge_tv || !tv) return nullptr;
  tv->tv_sec = bridge_tv->tv_sec;
  tv->tv_usec = bridge_tv->tv_usec;
  return tv;
}

struct bridge_timeval *ToBridgeTimeVal(const struct timeval *tv,
                                       struct bridge_timeval *bridge_tv) {
  if (!tv || !bridge_tv) return nullptr;
  bridge_tv->tv_sec = tv->tv_sec;
  bridge_tv->tv_usec = tv->tv_usec;
  return bridge_tv;
}

struct itimerval *FromBridgeITimerVal(
    const struct BridgeITimerVal *bridge_timerval, struct itimerval *timerval) {
  if (!bridge_timerval || !timerval) return nullptr;
  FromBridgeTimeVal(&bridge_timerval->it_interval, &timerval->it_interval);
  FromBridgeTimeVal(&bridge_timerval->it_value, &timerval->it_value);
  return timerval;
}

struct BridgeITimerVal *ToBridgeITimerVal(
    const struct itimerval *timerval, struct BridgeITimerVal *bridge_timerval) {
  if (!timerval || !bridge_timerval) return nullptr;
  ToBridgeTimeVal(&timerval->it_interval, &bridge_timerval->it_interval);
  ToBridgeTimeVal(&timerval->it_value, &bridge_timerval->it_value);
  return bridge_timerval;
}

int FromBridgeWStatus(struct BridgeWStatus bridge_wstatus) {
  int wstatus = static_cast<int>(bridge_wstatus.info) << 8;
  if (BridgeWIfExited(bridge_wstatus)) {
    return wstatus;
  }
  if (BridgeWIfStopped(bridge_wstatus)) {
    return wstatus + BRIDGE_WSTOPPED;
  }
  return wstatus + bridge_wstatus.code;
}

BridgeWStatus ToBridgeWStatus(int wstatus) {
  BridgeWStatus bridge_wstatus;
  // The info byte is the byte before the code byte, which is the 9 - 16 from
  // the lowest bits.
  bridge_wstatus.info = wstatus >> 8 & 0xff;
  if (WIFEXITED(wstatus)) {
    bridge_wstatus.code = 0;
  } else if (WIFSTOPPED(wstatus)) {
    bridge_wstatus.code = BRIDGE_WSTOPPED;
  } else {
    bridge_wstatus.code = wstatus & BRIDGE_WSTOPPED;
  }
  return bridge_wstatus;
}

struct rusage *FromBridgeRUsage(const struct BridgeRUsage *bridge_rusage,
                                struct rusage *rusage) {
  if (!bridge_rusage || !rusage) return nullptr;
  FromBridgeTimeVal(&bridge_rusage->ru_utime, &rusage->ru_utime);
  FromBridgeTimeVal(&bridge_rusage->ru_stime, &rusage->ru_stime);
  return rusage;
}

struct BridgeRUsage *ToBridgeRUsage(const struct rusage *rusage,
                                    struct BridgeRUsage *bridge_rusage) {
  if (!rusage || !bridge_rusage) return nullptr;
  ToBridgeTimeVal(&rusage->ru_utime, &bridge_rusage->ru_utime);
  ToBridgeTimeVal(&rusage->ru_stime, &bridge_rusage->ru_stime);
  return bridge_rusage;
}

fd_set *FromBridgeFDSet(const struct BridgeFDSet *bridge_fds, fd_set *fds) {
  if (!bridge_fds || !fds) return nullptr;
  FD_ZERO(fds);
  for (int fd = 0; fd < std::min(FD_SETSIZE, BRIDGE_FD_SETSIZE); ++fd) {
    if (BridgeFDIsSet(fd, bridge_fds)) {
      FD_SET(fd, fds);
    }
  }
  return fds;
}

struct BridgeFDSet *ToBridgeFDSet(const fd_set *fds,
                                  struct BridgeFDSet *bridge_fds) {
  if (!fds || !bridge_fds) return nullptr;
  BridgeFDZero(bridge_fds);
  for (int fd = 0; fd < std::min(FD_SETSIZE, BRIDGE_FD_SETSIZE); ++fd) {
    if (FD_ISSET(fd, fds)) {
      BridgeFDSet(fd, bridge_fds);
    }
  }
  return bridge_fds;
}

inline uint64_t BridgeWordNum(int cpu) {
  return cpu / (8 * sizeof(BridgeCpuSetWord));
}

inline BridgeCpuSetWord BridgeBitNum(int cpu) {
  return cpu % (8 * sizeof(BridgeCpuSetWord));
}

// These functions follow the standard for the analogous functions in
// http://man7.org/linux/man-pages/man3/CPU_SET.3.html.

void BridgeCpuSetZero(BridgeCpuSet *set) {
  memset(set->words, 0, BRIDGE_CPU_SET_NUM_WORDS * sizeof(BridgeCpuSetWord));
}

void BridgeCpuSetAddBit(int cpu, BridgeCpuSet *set) {
  set->words[BridgeWordNum(cpu)] |= static_cast<BridgeCpuSetWord>(1)
                                    << BridgeBitNum(cpu);
}

int BridgeCpuSetCheckBit(int cpu, BridgeCpuSet *set) {
  return (set->words[BridgeWordNum(cpu)] &
          (static_cast<BridgeCpuSetWord>(1) << BridgeBitNum(cpu)))
             ? 1
             : 0;
}

bool CStringCopy(const char *source_buf, char *dest_buf, size_t size) {
  int ret = snprintf(dest_buf, size, "%s", source_buf);
  return ret >= 0 && static_cast<size_t>(ret) < size;
}

struct passwd *FromBridgePassWd(struct BridgePassWd *bridge_password,
                                struct passwd *password) {
  if (!bridge_password || !password) {
    return nullptr;
  }

  password->pw_name = bridge_password->pw_name;
  password->pw_passwd = bridge_password->pw_passwd;
  password->pw_uid = bridge_password->pw_uid;
  password->pw_gid = bridge_password->pw_gid;
  password->pw_gecos = bridge_password->pw_gecos;
  password->pw_dir = bridge_password->pw_dir;
  password->pw_shell = bridge_password->pw_shell;

  return password;
}

struct BridgePassWd *ToBridgePassWd(const struct passwd *password,
                                    struct BridgePassWd *bridge_password) {
  if (!password || !bridge_password) {
    return nullptr;
  }

  bridge_password->pw_uid = password->pw_uid;
  bridge_password->pw_gid = password->pw_gid;

  if (!CStringCopy(password->pw_name, bridge_password->pw_name,
                   sizeof(bridge_password->pw_name)) ||
      !CStringCopy(password->pw_passwd, bridge_password->pw_passwd,
                   sizeof(bridge_password->pw_passwd)) ||
      !CStringCopy(password->pw_gecos, bridge_password->pw_gecos,
                   sizeof(bridge_password->pw_gecos)) ||
      !CStringCopy(password->pw_dir, bridge_password->pw_dir,
                   sizeof(bridge_password->pw_dir)) ||
      !CStringCopy(password->pw_shell, bridge_password->pw_shell,
                   sizeof(bridge_password->pw_shell))) {
    return nullptr;
  }

  return bridge_password;
}

struct BridgePassWd *CopyBridgePassWd(
    const struct BridgePassWd *source_bridge_password,
    struct BridgePassWd *destination_bridge_password) {
  if (!source_bridge_password || !destination_bridge_password) {
    return nullptr;
  }

  destination_bridge_password->pw_uid = source_bridge_password->pw_uid;
  destination_bridge_password->pw_gid = source_bridge_password->pw_gid;

  if (!CStringCopy(source_bridge_password->pw_name,
                   destination_bridge_password->pw_name,
                   sizeof(destination_bridge_password->pw_name)) ||
      !CStringCopy(source_bridge_password->pw_passwd,
                   destination_bridge_password->pw_passwd,
                   sizeof(destination_bridge_password->pw_passwd)) ||
      !CStringCopy(source_bridge_password->pw_gecos,
                   destination_bridge_password->pw_gecos,
                   sizeof(destination_bridge_password->pw_gecos)) ||
      !CStringCopy(source_bridge_password->pw_dir,
                   destination_bridge_password->pw_dir,
                   sizeof(destination_bridge_password->pw_dir)) ||
      !CStringCopy(source_bridge_password->pw_shell,
                   destination_bridge_password->pw_shell,
                   sizeof(destination_bridge_password->pw_shell))) {
    return nullptr;
  }

  return destination_bridge_password;
}

}  // namespace asylo
