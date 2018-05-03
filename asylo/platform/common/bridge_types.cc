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
#include <string.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>

#include "asylo/util/logging.h"

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
  if (bridge_signum == BRIDGE_SIGHUP) return SIGHUP;
  if (bridge_signum == BRIDGE_SIGINT) return SIGINT;
  if (bridge_signum == BRIDGE_SIGQUIT) return SIGQUIT;
  if (bridge_signum == BRIDGE_SIGILL) return SIGILL;
  if (bridge_signum == BRIDGE_SIGTRAP) return SIGTRAP;
  if (bridge_signum == BRIDGE_SIGABRT) return SIGABRT;
  if (bridge_signum == BRIDGE_SIGBUS) return SIGBUS;
  if (bridge_signum == BRIDGE_SIGFPE) return SIGFPE;
  if (bridge_signum == BRIDGE_SIGKILL) return SIGKILL;
  if (bridge_signum == BRIDGE_SIGUSR1) return SIGUSR1;
  if (bridge_signum == BRIDGE_SIGSEGV) return SIGSEGV;
  if (bridge_signum == BRIDGE_SIGUSR2) return SIGUSR2;
  if (bridge_signum == BRIDGE_SIGPIPE) return SIGPIPE;
  if (bridge_signum == BRIDGE_SIGALRM) return SIGALRM;
  if (bridge_signum == BRIDGE_SIGTERM) return SIGTERM;
  if (bridge_signum == BRIDGE_SIGCHLD) return SIGCHLD;
  if (bridge_signum == BRIDGE_SIGCONT) return SIGCONT;
  if (bridge_signum == BRIDGE_SIGSTOP) return SIGSTOP;
  if (bridge_signum == BRIDGE_SIGTSTP) return SIGTSTP;
  if (bridge_signum == BRIDGE_SIGTTIN) return SIGTTIN;
  if (bridge_signum == BRIDGE_SIGTTOU) return SIGTTOU;
  if (bridge_signum == BRIDGE_SIGURG) return SIGURG;
  if (bridge_signum == BRIDGE_SIGXCPU) return SIGXCPU;
  if (bridge_signum == BRIDGE_SIGXFSZ) return SIGXFSZ;
  if (bridge_signum == BRIDGE_SIGVTALRM) return SIGVTALRM;
  if (bridge_signum == BRIDGE_SIGPROF) return SIGPROF;
  if (bridge_signum == BRIDGE_SIGWINCH) return SIGWINCH;
  if (bridge_signum == BRIDGE_SIGSYS) return SIGSYS;
#if defined(SIGRTMIN) && defined(SIGRTMAX)
  if ((bridge_signum >= BRIDGE_SIGRTMIN) && (bridge_signum <= BRIDGE_SIGRTMAX))
    return (bridge_signum - BRIDGE_SIGRTMIN + SIGRTMIN);
#endif  // defined(SIGRTMIN) && defined(SIGRMAX)
  return -1;
}

int ToBridgeSignal(int signum) {
  if (signum == SIGHUP) return BRIDGE_SIGHUP;
  if (signum == SIGINT) return BRIDGE_SIGINT;
  if (signum == SIGQUIT) return BRIDGE_SIGQUIT;
  if (signum == SIGILL) return BRIDGE_SIGILL;
  if (signum == SIGTRAP) return BRIDGE_SIGTRAP;
  if (signum == SIGABRT) return BRIDGE_SIGABRT;
  if (signum == SIGBUS) return BRIDGE_SIGBUS;
  if (signum == SIGFPE) return BRIDGE_SIGFPE;
  if (signum == SIGKILL) return BRIDGE_SIGKILL;
  if (signum == SIGUSR1) return BRIDGE_SIGUSR1;
  if (signum == SIGSEGV) return BRIDGE_SIGSEGV;
  if (signum == SIGUSR2) return BRIDGE_SIGUSR2;
  if (signum == SIGPIPE) return BRIDGE_SIGPIPE;
  if (signum == SIGALRM) return BRIDGE_SIGALRM;
  if (signum == SIGTERM) return BRIDGE_SIGTERM;
  if (signum == SIGCHLD) return BRIDGE_SIGCHLD;
  if (signum == SIGCONT) return BRIDGE_SIGCONT;
  if (signum == SIGSTOP) return BRIDGE_SIGSTOP;
  if (signum == SIGTSTP) return BRIDGE_SIGTSTP;
  if (signum == SIGTTIN) return BRIDGE_SIGTTIN;
  if (signum == SIGTTOU) return BRIDGE_SIGTTOU;
  if (signum == SIGURG) return BRIDGE_SIGURG;
  if (signum == SIGXCPU) return BRIDGE_SIGXCPU;
  if (signum == SIGXFSZ) return BRIDGE_SIGXFSZ;
  if (signum == SIGVTALRM) return BRIDGE_SIGVTALRM;
  if (signum == SIGPROF) return BRIDGE_SIGPROF;
  if (signum == SIGWINCH) return BRIDGE_SIGWINCH;
  if (signum == SIGSYS) return BRIDGE_SIGSYS;
#if defined(SIGRTMIN) && defined(SIGRTMAX)
  if (signum >= SIGRTMIN && signum <= SIGRTMAX)
    return (signum - SIGRTMIN + BRIDGE_SIGRTMIN);
#endif  // defined(SIGRTMIN) && defined(SIGRTMAX)
  return -1;
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
