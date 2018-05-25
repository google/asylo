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
#include <sys/socket.h>

// This file provides a set of type definitions used both inside and outside the
// enclave.

#ifdef __cplusplus
extern "C" {
#endif

// Replace size_t and ssize_t with types of known width for transmission across
// the enclave boundary.
typedef uint64_t bridge_size_t;
typedef int64_t bridge_ssize_t;

// This enum contains all of the sysconf name values that we allow to be called
// outside the enclave.
enum SysconfConstants { UNKNOWN = 0, NPROCESSORS_ONLN = 1 };

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

// All of the file operation flags that we allow to be called outside the
// enclave.
enum FileStatusFlags {
  RDONLY = 0x00,
  WRONLY = 0x01,
  RDWR = 0x02,
  CREAT = 0x40,
  EXCL = 0x80,
  TRUNC = 0x200,
  APPEND = 0x400,
  NONBLOCK = 0x800,
};

enum FileDescriptorFlags {
  CLOEXEC = 0x01,
};

struct bridge_in_addr {
  uint32_t inet_addr;
} __attribute__((__packed__));

struct bridge_in6_addr {
  uint8_t inet6_addr[16];
} __attribute__((__packed__));

struct bridge_sockaddr_in6 {
  uint16_t sin6_port;
  uint32_t sin6_flowinfo;
  struct bridge_in6_addr sin6_addr;
  uint32_t sin6_scope_id;
} __attribute__((__packed__));

struct bridge_sockaddr_in {
  uint16_t sin_port;
  struct bridge_in_addr sin_addr;
  char sin_zero[8];
} __attribute__((__packed__));

struct bridge_sockaddr_un {
  char sun_path[108];
} __attribute__((__packed__));

// This is max(sizeof(struct sockaddr_in), sizeof(struct sockaddr_un)). Struct
// bridge_sockaddr can be converted from/to struct sockaddr in ocalls. Since
// struct sockaddr can be the address of UNIX domain socket (sockaddr_un) in
// socket-related syscalls, struct bridge_sockaddr needs enough space to
// represent it.
struct bridge_sockaddr {
  uint16_t sa_family;
  union {
    struct bridge_sockaddr_in addr_in;
    struct bridge_sockaddr_in6 addr_in6;
    struct bridge_sockaddr_un addr_un;
  } __attribute__((__packed__));
} __attribute__((__packed__));

typedef int64_t bridge_clockid_t;

struct bridge_timeval {
  int64_t tv_sec;
  int64_t tv_usec;
} __attribute__((__packed__));

struct bridge_timespec {
  int64_t tv_sec;
  int64_t tv_nsec;
} __attribute__((__packed__));

struct bridge_stat {
  int64_t st_dev;
  int64_t st_ino;
  int64_t st_mode;
  int64_t st_nlink;
  int64_t st_uid;
  int64_t st_gid;
  int64_t st_rdev;
  int64_t st_size;
  int64_t st_atime_enc;
  int64_t st_mtime_enc;
  int64_t st_ctime_enc;
  int64_t st_blksize;
  int64_t st_blocks;
} __attribute__((__packed__));

struct bridge_pollfd {
  int32_t fd;
  int16_t events;
  int16_t revents;
};

struct bridge_msghdr {
  void *msg_name;
  uint64_t msg_namelen;
  struct bridge_iovec *msg_iov;
  uint64_t msg_iovlen;
  void *msg_control;
  uint64_t msg_controllen;
  int32_t msg_flags;
};

struct bridge_iovec {
  void *iov_base;
  uint64_t iov_len;
};

struct bridge_siginfo_t {
  int32_t si_signo;
  int32_t si_code;
};

struct bridge_signal_handler {
  void (*sigaction)(int, struct bridge_siginfo_t *, void *);
};

// The maximum number of CPUs we support. Chosen to be large enough to represent
// as many CPUs as an enclave-native cpu_set_t.
#define BRIDGE_CPU_SET_MAX_CPUS 1024

typedef uint64_t BridgeCpuSetWord;

#define BRIDGE_CPU_SET_NUM_WORDS                                  \
  ((BRIDGE_CPU_SET_MAX_CPUS / 8 + sizeof(BridgeCpuSetWord) - 1) / \
   sizeof(BridgeCpuSetWord))

// Represents a set of (up to) BRIDGE_CPU_SET_MAX_CPUS CPUs as a bitset. The nth
// bit of words[i] corresponds to CPU no. sizeof(BridgeCpuSetWord) * i + n.
struct BridgeCpuSet {
  BridgeCpuSetWord words[BRIDGE_CPU_SET_NUM_WORDS];
} __attribute__((__packed__));

// Converts |bridge_sysconf_constant| to a runtime sysconf constant. Returns -1
// if unsuccessful.
int FromSysconfConstants(enum SysconfConstants bridge_sysconf_constant);

// Converts |sysconf_constant| to a bridge constant. Returns UNKNOWN if
// unsuccessful.
enum SysconfConstants ToSysconfConstants(int sysconf_constant);

// Converts |bridge_signum| to a runtime signal number. Returns -1 if
// unsuccessful.
int FromBridgeSignal(int bridge_signum);

// Converts |signum| to a bridge signal number. Returns -1 if unsuccessful.
int ToBridgeSignal(int signum);

// Converts |bridge_si_code| to a runtime signal code. Returns -1 if
// unsuccessful.
int FromBridgeSignalCode(int bridge_si_code);

// Converts |si_code| to a bridge signal code. Returns -1 if unsuccessful.
int ToBridgeSignalCode(int si_code);

// Converts |bridge_siginfo| to a runtime siginfo_t. Returns nullptr if
// unsuccessful.
siginfo_t *FromBridgeSigInfo(const struct bridge_siginfo_t *bridge_siginfo,
                             siginfo_t *siginfo);

// Converts |siginfo| to a bridge siginfo_t. Returns nullptr if unsuccessful.
struct bridge_siginfo_t *ToBridgeSigInfo(
    const siginfo_t *siginfo, struct bridge_siginfo_t *bridge_siginfo);

// Converts |bridge_file_flag| to a runtime file flag.
int FromBridgeFileFlags(int bridge_file_flag);

// Converts |file_flag| to a bridge file flag.
int ToBridgeFileFlags(int file_flag);

// Converts |bridge_fd_flag| to a runtime file flag.
int FromBridgeFDFlags(int bridge_fd_flag);

// Converts |fd_flag| to a bridge FD flag.
int ToBridgeFDFlags(int fd_flag);

// Converts |bridge_st| to a runtime stat. Returns nullptr if unsuccessful.
struct stat *FromBridgeStat(const struct bridge_stat *bridge_statbuf,
                            struct stat *statbuf);

// Converts |st| to a bridge stat. Returns nullptr if unsuccessful.
struct bridge_stat *ToBridgeStat(const struct stat *statbuf,
                                 struct bridge_stat *bridge_statbuf);

// Copies |bridge_addr| to a runtime sockaddr up to sizeof(struct
// bridge_sockaddr). Returns nullptr if unsuccessful.
struct sockaddr *FromBridgeSockaddr(const struct bridge_sockaddr *bridge_addr,
                                    struct sockaddr *addr);

// Copies |addr| to a bridge sockaddr up to sizeof(struct bridge_sockaddr).
// Returns nullptr if unsuccessful.
struct bridge_sockaddr *ToBridgeSockaddr(const struct sockaddr *addr,
                                         struct bridge_sockaddr *bridge_addr);

// Converts |bridge_tp| to a runtime timespec.
struct timespec *FromBridgeTimespec(const struct bridge_timespec *bridge_tp,
                                    struct timespec *tp);

// Converts |tp| to a bridge timespec.
struct bridge_timespec *ToBridgeTimespec(const struct timespec *tp,
                                         struct bridge_timespec *bridge_tp);

// Converts |fd| to a bridge pollfd. Returns nullptr if unsuccessful.
struct pollfd *FromBridgePollfd(const struct bridge_pollfd *bridge_fd,
                                struct pollfd *fd);

// Converts |bridge_fd| to a runtime pollfd. Returns nullptr if unsuccessful.
struct bridge_pollfd *ToBridgePollfd(const struct pollfd *fd,
                                     struct bridge_pollfd *bridge_fd);

// Converts |bridge_msg| to a runtime msghdr. This only does a shallow copy of
// the pointers. A deep copy of the |iovec| array is done in a helper class
// |BridgeMsghdrWrapper| in host_calls. Returns nullptr if unsuccessful.
struct msghdr *FromBridgeMsgHdr(const struct bridge_msghdr *bridge_msg,
                                struct msghdr *msg);

// Converts |msg| to a bridge msghdr. This only does a shallow copy of the
// pointers. A deep copy of the |iovec| array is done in a helper class
// |BridgeMsghdrWrapper| in host_calls. Returns nullptr if unsuccessful.
struct bridge_msghdr *ToBridgeMsgHdr(const struct msghdr *msg,
                                     struct bridge_msghdr *bridge_msg);

// Copies all the iovec buffers from |bridge_msg| to |msg|. This conversion does
// not allocate memory, just copies data to already allocated memory. Returns
// nullptr if unsuccessful.
struct msghdr *FromBridgeIovecArray(const struct bridge_msghdr *bridge_msg,
                                    struct msghdr *msg);

// Copies all the iovec buffers from |msg| to |bridge_msg|. This conversion does
// not allocate memory, just copies data to already allocated memory. Returns
// nullptr is unsuccessful.
struct bridge_msghdr *ToBridgeIovecArray(const struct msghdr *msg,
                                         struct bridge_msghdr *bridge_msg);

// Converts |bridge_iov| to a runtime iovec. Returns nullptr if unsuccessful.
struct iovec *FromBridgeIovec(const struct bridge_iovec *bridge_iov,
                              struct iovec *iov);

// Converts |iov| to a bridge iovec. Returns nullptr if unsuccessful.
struct bridge_iovec *ToBridgeIovec(const struct iovec *iov,
                                   struct bridge_iovec *bridge_iov);

// These functions follow the standard for the analogous functions in
// http://man7.org/linux/man-pages/man3/CPU_SET.3.html.

void BridgeCpuSetZero(struct BridgeCpuSet *set);

void BridgeCpuSetAddBit(int cpu, struct BridgeCpuSet *set);

int BridgeCpuSetCheckBit(int cpu, struct BridgeCpuSet *set);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // ASYLO_PLATFORM_COMMON_BRIDGE_TYPES_H_
