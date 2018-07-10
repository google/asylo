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

#include "asylo/platform/common/bridge_types.h"

#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <unordered_map>

#include "asylo/util/logging.h"

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

int FromSysconfConstants(enum SysconfConstants bridge_sysconf_constant) {
  switch (bridge_sysconf_constant) {
    case NPROCESSORS_ONLN:
      return _SC_NPROCESSORS_ONLN;
    default:
      return -1;
  }
}

enum SysconfConstants ToSysconfConstants(int sysconf_constant) {
  switch (sysconf_constant) {
    case _SC_NPROCESSORS_ONLN:
      return NPROCESSORS_ONLN;
    default:
      return UNKNOWN;
  }
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
                                    struct sockaddr *addr) {
  if (!bridge_addr || !addr) return nullptr;
  addr->sa_family = bridge_addr->sa_family;
  if (addr->sa_family == AF_UNIX || addr->sa_family == AF_LOCAL) {
    struct sockaddr_un *sockaddr_un_out =
        reinterpret_cast<struct sockaddr_un *>(addr);
    InitializeToZeroArray(sockaddr_un_out->sun_path);
    ReinterpretCopyArray(sockaddr_un_out->sun_path,
                         bridge_addr->addr_un.sun_path);
  } else if (addr->sa_family == AF_INET6) {
    struct sockaddr_in6 *sockaddr_in6_out =
        reinterpret_cast<struct sockaddr_in6 *>(addr);
    sockaddr_in6_out->sin6_port = bridge_addr->addr_in6.sin6_port;
    sockaddr_in6_out->sin6_flowinfo = bridge_addr->addr_in6.sin6_flowinfo;
    InitializeToZeroSingle(&sockaddr_in6_out->sin6_addr);
    ReinterpretCopySingle(&sockaddr_in6_out->sin6_addr,
                          &bridge_addr->addr_in6.sin6_addr);
    sockaddr_in6_out->sin6_scope_id = bridge_addr->addr_in6.sin6_scope_id;
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
  } else {
    LOG(ERROR) << "socket type is not supported";
    abort();
  }
  return addr;
}

struct bridge_sockaddr *ToBridgeSockaddr(const struct sockaddr *addr,
                                         struct bridge_sockaddr *bridge_addr) {
  if (!addr || !bridge_addr) return nullptr;
  bridge_addr->sa_family = addr->sa_family;
  if (bridge_addr->sa_family == AF_UNIX || bridge_addr->sa_family == AF_LOCAL) {
    struct sockaddr_un *sockaddr_un_in = const_cast<struct sockaddr_un *>(
        reinterpret_cast<const struct sockaddr_un *>(addr));
    InitializeToZeroArray(bridge_addr->addr_un.sun_path);
    ReinterpretCopyArray(bridge_addr->addr_un.sun_path,
                         sockaddr_un_in->sun_path);
  } else if (bridge_addr->sa_family == AF_INET6) {
    struct sockaddr_in6 *sockaddr_in6_in = const_cast<struct sockaddr_in6 *>(
        reinterpret_cast<const struct sockaddr_in6 *>(addr));
    bridge_addr->addr_in6.sin6_port = sockaddr_in6_in->sin6_port;
    bridge_addr->addr_in6.sin6_flowinfo = sockaddr_in6_in->sin6_flowinfo;
    InitializeToZeroSingle(&bridge_addr->addr_in6.sin6_addr);
    ReinterpretCopySingle(&bridge_addr->addr_in6.sin6_addr,
                          &sockaddr_in6_in->sin6_addr);
    bridge_addr->addr_in6.sin6_scope_id = sockaddr_in6_in->sin6_scope_id;
  } else if (bridge_addr->sa_family == AF_INET) {
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
    abort();
  }
  return bridge_addr;
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
