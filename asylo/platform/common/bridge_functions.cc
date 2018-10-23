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

#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include <utime.h>
#include <algorithm>

#include "absl/container/flat_hash_map.h"
#include "asylo/util/logging.h"

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

const absl::flat_hash_map<int, int> *CreateBridgeSignalMap() {
  auto signal_map = new absl::flat_hash_map<int, int>;
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

const absl::flat_hash_map<int, int> *GetSignalToBridgeSignalMap() {
  static const absl::flat_hash_map<int, int> *signal_to_bridge_signal_map =
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

int FromBridgeAddressInfoFlags(int bridge_ai_flag) {
  int ai_flag = 0;
  if (bridge_ai_flag & BRIDGE_AI_CANONNAME) ai_flag |= AI_CANONNAME;
  if (bridge_ai_flag & BRIDGE_AI_NUMERICHOST) ai_flag |= AI_NUMERICHOST;
  return ai_flag;
}

int ToBridgeAddressInfoFlags(int ai_flag) {
  int bridge_ai_flag = 0;
  if (ai_flag & AI_CANONNAME) bridge_ai_flag |= BRIDGE_AI_CANONNAME;
  if (ai_flag & AI_NUMERICHOST) bridge_ai_flag |= BRIDGE_AI_NUMERICHOST;
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
         ToBridgeSysLogLevel(syslog_facility);
}

int FromBridgeFileFlags(int bridge_file_flag) {
  int file_flag = 0;
  if (bridge_file_flag & RDONLY) file_flag |= O_RDONLY;
  if (bridge_file_flag & WRONLY) file_flag |= O_WRONLY;
  if (bridge_file_flag & RDWR) file_flag |= O_RDWR;
  if (bridge_file_flag & CREAT) file_flag |= O_CREAT;
  if (bridge_file_flag & APPEND) file_flag |= O_APPEND;
  if (bridge_file_flag & EXCL) file_flag |= O_EXCL;
  if (bridge_file_flag & TRUNC) file_flag |= O_TRUNC;
  if (bridge_file_flag & NONBLOCK) file_flag |= O_NONBLOCK;
  return file_flag;
}

int ToBridgeFileFlags(int file_flag) {
  int bridge_file_flag = 0;
  if (file_flag & O_RDONLY) bridge_file_flag |= RDONLY;
  if (file_flag & O_WRONLY) bridge_file_flag |= WRONLY;
  if (file_flag & O_RDWR) bridge_file_flag |= RDWR;
  if (file_flag & O_CREAT) bridge_file_flag |= CREAT;
  if (file_flag & O_APPEND) bridge_file_flag |= APPEND;
  if (file_flag & O_EXCL) bridge_file_flag |= EXCL;
  if (file_flag & O_TRUNC) bridge_file_flag |= TRUNC;
  if (file_flag & O_NONBLOCK) bridge_file_flag |= NONBLOCK;
  return bridge_file_flag;
}

int FromBridgeFDFlags(int bridge_fd_flag) {
  int fd_flag = 0;
  if (bridge_fd_flag & CLOEXEC) fd_flag |= FD_CLOEXEC;
  return fd_flag;
}

int ToBridgeFDFlags(int fd_flag) {
  int bridge_fd_flag = 0;
  if (fd_flag & FD_CLOEXEC) bridge_fd_flag |= CLOEXEC;
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
void ReinterpretCopyArray(T (&dst)[M], const U (&src)[N]) {
  memcpy(dst, src, std::min(sizeof(T) * M, sizeof(U) * N));
}

template <typename T>
void InitializeToZeroSingle(T *ptr) {
  memset(ptr, 0, sizeof(T));
}

template <typename T, size_t M>
void InitializeToZeroArray(T (&ptr)[M]) {
  memset(ptr, 0, sizeof(T) * M);
}

struct sockaddr *FromBridgeSockaddr(const struct bridge_sockaddr *bridge_addr,
                                    struct sockaddr *addr, socklen_t *addrlen) {
  if (!bridge_addr || !addr) return nullptr;
  addr->sa_family = bridge_addr->sa_family;
  if (addr->sa_family == AF_UNIX || addr->sa_family == AF_LOCAL) {
    struct sockaddr_un *sockaddr_un_out =
        reinterpret_cast<struct sockaddr_un *>(addr);
    InitializeToZeroArray(sockaddr_un_out->sun_path);
    ReinterpretCopyArray(sockaddr_un_out->sun_path,
                         bridge_addr->addr_un.sun_path);
    *addrlen = sizeof(struct sockaddr_un);
  } else if (addr->sa_family == AF_INET6) {
    struct sockaddr_in6 *sockaddr_in6_out =
        reinterpret_cast<struct sockaddr_in6 *>(addr);
    sockaddr_in6_out->sin6_port = bridge_addr->addr_in6.sin6_port;
    sockaddr_in6_out->sin6_flowinfo = bridge_addr->addr_in6.sin6_flowinfo;
    InitializeToZeroSingle(&sockaddr_in6_out->sin6_addr);
    ReinterpretCopySingle(&sockaddr_in6_out->sin6_addr,
                          &bridge_addr->addr_in6.sin6_addr);
    sockaddr_in6_out->sin6_scope_id = bridge_addr->addr_in6.sin6_scope_id;
    *addrlen = sizeof(sockaddr_in6);
  } else if (addr->sa_family == AF_INET) {
    struct sockaddr_in *sockaddr_in_out =
        reinterpret_cast<struct sockaddr_in *>(addr);
    sockaddr_in_out->sin_port = bridge_addr->addr_in.sin_port;
    InitializeToZeroSingle(&sockaddr_in_out->sin_addr);
    ReinterpretCopySingle(&sockaddr_in_out->sin_addr,
                          &bridge_addr->addr_in.sin_addr);
    InitializeToZeroArray(sockaddr_in_out->sin_zero);
    ReinterpretCopyArray(sockaddr_in_out->sin_zero,
                         bridge_addr->addr_in.sin_zero);
    *addrlen = sizeof(sockaddr_in);
  } else {
    LOG(ERROR) << "socket type is not supported";
    abort();
  }
  return addr;
}

struct bridge_sockaddr *ToBridgeSockaddr(const struct sockaddr *addr,
                                         socklen_t addrlen,
                                         struct bridge_sockaddr *bridge_addr) {
  if (!addr || !bridge_addr) return nullptr;
  bridge_addr->sa_family = addr->sa_family;
  if (bridge_addr->sa_family == AF_UNIX || bridge_addr->sa_family == AF_LOCAL) {
    if (addrlen < sizeof(struct sockaddr_un)) {
      return nullptr;
    }
    struct sockaddr_un *sockaddr_un_in = const_cast<struct sockaddr_un *>(
        reinterpret_cast<const struct sockaddr_un *>(addr));
    InitializeToZeroArray(bridge_addr->addr_un.sun_path);
    ReinterpretCopyArray(bridge_addr->addr_un.sun_path,
                         sockaddr_un_in->sun_path);
  } else if (bridge_addr->sa_family == AF_INET6) {
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
  } else if (bridge_addr->sa_family == AF_INET) {
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
  } else {
    LOG(ERROR) << "socket type is not supported";
    abort();
  }
  return bridge_addr;
}

AfFamily ToBridgeAfFamily(int af_family) {
  if (af_family == AF_INET) {
    return BRIDGE_AF_INET;
  } else if (af_family == AF_INET6) {
    return BRIDGE_AF_INET6;
  }
  return BRIDGE_AF_UNSUPPORTED;
}

int FromBridgeAfFamily(AfFamily bridge_af_family) {
  if (bridge_af_family == BRIDGE_AF_INET) {
    return AF_INET;
  } else if (bridge_af_family == BRIDGE_AF_INET6) {
    return AF_INET6;
  }
  return -1;
}

struct pollfd *FromBridgePollfd(const struct bridge_pollfd *bridge_fd,
                                struct pollfd *fd) {
  if (!bridge_fd || !fd) return nullptr;
  fd->fd = bridge_fd->fd;
  fd->events = bridge_fd->events;
  fd->revents = bridge_fd->revents;
  return fd;
}

struct bridge_pollfd *ToBridgePollfd(const struct pollfd *fd,
                                     struct bridge_pollfd *bridge_fd) {
  if (!fd || !bridge_fd) return nullptr;
  bridge_fd->fd = fd->fd;
  bridge_fd->events = fd->events;
  bridge_fd->revents = fd->revents;
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

}  // namespace asylo
