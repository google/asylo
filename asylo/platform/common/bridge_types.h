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

#include <netdb.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdint.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <syslog.h>

#include "absl/base/attributes.h"

// This file provides a set of type definitions used both inside and outside the
// enclave.

#ifdef __cplusplus
extern "C" {
#endif

// Replace size_t, ssize_t, and sigset_t with types of known width for
// transmission across the enclave boundary.
typedef uint64_t bridge_size_t;
typedef int64_t bridge_ssize_t;
typedef int64_t bridge_sigset_t;

// The operations for flock that are supported inside the enclave.
enum FLockOperations {
  BRIDGE_LOCK_SH = 0x01,
  BRIDGE_LOCK_EX = 0x02,
  BRIDGE_LOCK_NB = 0x04,
  BRIDGE_LOCK_UN = 0x08,
};

// This enum contains all of the sysconf name values supported inside the
// enclave.
enum SysconfConstants {
  BRIDGE_SC_UNKNOWN = 0,
  BRIDGE_SC_NPROCESSORS_ONLN = 1,
  BRIDGE_SC_NPROCESSORS_CONF = 2,
};

// The timer type for getitimer/setitimer that are supported inside an enclave.
enum TimerType {
  BRIDGE_ITIMER_UNKNOWN = 0,
  BRIDGE_ITIMER_REAL = 1,
  BRIDGE_ITIMER_VIRTUAL = 2,
  BRIDGE_ITIMER_PROF = 3,
};

// The target for getrusage(2) that are supported inside the enclave.
enum RUsageTarget {
  BRIDGE_RUSAGE_UNKNOWN = 0,
  BRIDGE_RUSAGE_SELF = 1,
  BRIDGE_RUSAGE_CHILDREN = 2,
};

// The wait options that are supported inside the enclave.
enum WaitOptions {
  BRIDGE_WNOHANG = 1,
};

// The code byte of wstatus that are supported inside the enclave. The last 8
// bit of wstatus is the code byte. WIFEXITED returns true if the code byte is
// 0. WIFSTOPPED returns true if the code byte is 0x7f. Otherwise WIFSIGNALED
// returns true.
enum WStatusCode {
  BRIDGE_WCODEBYTE = 0xff,
  BRIDGE_WSTOPPED = 0x7f,
};

struct BridgeWStatus {
  uint8_t code;
  uint8_t info;
};

// The possible actions when calling sigprocmask.
enum SigMaskAction {
  BRIDGE_SIG_SETMASK = 0,
  BRIDGE_SIG_BLOCK = 1,
  BRIDGE_SIG_UNBLOCK = 2,
};

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

// The address info flags that specifies options of an addrinfo struct.
enum AddrInfoFlags {
  BRIDGE_AI_CANONNAME = 0x0002,
  BRIDGE_AI_NUMERICHOST = 0x0004,
};

// All of the file operation flags supported inside the enclave.
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

// All the syslog options supported inside the enclave.
enum SysLogOptions {
  BRIDGE_LOG_PID = 0x01,
  BRIDGE_LOG_CONS = 0x02,
  BRIDGE_LOG_ODELAY = 0x04,
  BRIDGE_LOG_NDELAY = 0x08,
  BRIDGE_LOG_NOWAIT = 0x10,
  BRIDGE_LOG_PERROR = 0x20,
};

// All the syslog facilities supported inside the enclave.
enum SysLogFacilities {
  BRIDGE_LOG_USER = 1 << 3,
  BRIDGE_LOG_LOCAL0 = 16 << 3,
  BRIDGE_LOG_LOCAL1 = 17 << 3,
  BRIDGE_LOG_LOCAL2 = 18 << 3,
  BRIDGE_LOG_LOCAL3 = 19 << 3,
  BRIDGE_LOG_LOCAL4 = 20 << 3,
  BRIDGE_LOG_LOCAL5 = 21 << 3,
  BRIDGE_LOG_LOCAL6 = 22 << 3,
  BRIDGE_LOG_LOCAL7 = 23 << 3,
};

// All the supported syslog level that are allowed to be called outside the
// enclave.
enum SysLogLevel {
  BRIDGE_LOG_EMERG = 0,
  BRIDGE_LOG_ALERT = 1,
  BRIDGE_LOG_CRIT = 2,
  BRIDGE_LOG_ERR = 3,
  BRIDGE_LOG_WARNING = 4,
  BRIDGE_LOG_NOTICE = 5,
  BRIDGE_LOG_INFO = 6,
  BRIDGE_LOG_DEBUG = 7,
};

// All tcp option names supported inside the enclave.
enum TcpOptionNames {
  BRIDGE_TCP_NODELAY = 1,
  BRIDGE_TCP_KEEPIDLE = 4,
  BRIDGE_TCP_KEEPINTVL = 5,
  BRIDGE_TCP_KEEPCNT = 6,
};

// All IPV6 option names supported inside the enclave.
enum IpV6OptionNames {
  BRIDGE_IPV6_V6ONLY = 1,
};

// All socket option names supported inside the enclave.
enum SocketOptionNames {
  BRIDGE_SO_DEBUG = 1,
  BRIDGE_SO_REUSEADDR = 2,
  BRIDGE_SO_TYPE = 3,
  BRIDGE_SO_ERROR = 4,
  BRIDGE_SO_DONTROUTE = 5,
  BRIDGE_SO_BROADCAST = 6,
  BRIDGE_SO_SNDBUF = 7,
  BRIDGE_SO_RCVBUF = 8,
  BRIDGE_SO_KEEPALIVE = 9,
  BRIDGE_SO_OOBINLINE = 10,
  BRIDGE_SO_NO_CHECK = 11,
  BRIDGE_SO_PRIORITY = 12,
  BRIDGE_SO_LINGER = 13,
  BRIDGE_SO_BSDCOMPAT = 14,
  BRIDGE_SO_REUSEPORT = 15,
  BRIDGE_SO_RCVTIMEO = 20,
  BRIDGE_SO_SNDTIMEO = 21,
  BRIDGE_SO_SNDBUFFORCE = 32,
  BRIDGE_SO_RCVBUFFORCE = 33,
};

enum AfFamily {
  BRIDGE_AF_INET = 1,
  BRIDGE_AF_INET6 = 2,
  BRIDGE_AF_UNSUPPORTED = 3,
};

struct bridge_in_addr {
  uint32_t inet_addr;
} ABSL_ATTRIBUTE_PACKED;

struct bridge_in6_addr {
  uint8_t inet6_addr[16];
} ABSL_ATTRIBUTE_PACKED;

struct bridge_sockaddr_in6 {
  uint16_t sin6_port;
  uint32_t sin6_flowinfo;
  struct bridge_in6_addr sin6_addr;
  uint32_t sin6_scope_id;
} ABSL_ATTRIBUTE_PACKED;

struct bridge_sockaddr_in {
  uint16_t sin_port;
  struct bridge_in_addr sin_addr;
  char sin_zero[8];
} ABSL_ATTRIBUTE_PACKED;

struct bridge_sockaddr_un {
  char sun_path[108];
} ABSL_ATTRIBUTE_PACKED;

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
  } ABSL_ATTRIBUTE_PACKED;
} ABSL_ATTRIBUTE_PACKED;

typedef int64_t bridge_clockid_t;

struct BridgeTms {
  clock_t tms_utime;
  clock_t tms_stime;
  clock_t tms_cutime;
  clock_t tms_cstime;
} ABSL_ATTRIBUTE_PACKED;

struct bridge_timeval {
  int64_t tv_sec;
  int64_t tv_usec;
} ABSL_ATTRIBUTE_PACKED;

struct BridgeITimerVal {
  struct bridge_timeval it_interval;
  struct bridge_timeval it_value;
} ABSL_ATTRIBUTE_PACKED;

struct bridge_timespec {
  int64_t tv_sec;
  int64_t tv_nsec;
} ABSL_ATTRIBUTE_PACKED;

struct bridge_utimbuf {
  int64_t actime;
  int64_t modtime;
} ABSL_ATTRIBUTE_PACKED;

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
} ABSL_ATTRIBUTE_PACKED;

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

struct BridgeSignalHandler {
  void (*sigaction)(int, struct bridge_siginfo_t *, void *);
  bridge_sigset_t mask;
};

struct BridgeRUsage {
  struct bridge_timeval ru_utime;
  struct bridge_timeval ru_stime;
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
} ABSL_ATTRIBUTE_PACKED;

// According to IETF RFC 1035, fully qualified domain names, such as those held
// in utsname::nodename, may contain up to 255 characters. Therefore, in Asylo,
// the fields of BridgeUtsname are defined to have length 256 in order to hold
// 255 characters and a null byte.
#define BRIDGE_UTSNAME_FIELD_LENGTH 256

struct BridgeUtsName {
  char sysname[BRIDGE_UTSNAME_FIELD_LENGTH];
  char nodename[BRIDGE_UTSNAME_FIELD_LENGTH];
  char release[BRIDGE_UTSNAME_FIELD_LENGTH];
  char version[BRIDGE_UTSNAME_FIELD_LENGTH];
  char machine[BRIDGE_UTSNAME_FIELD_LENGTH];

  // The |domainname| field is a GNU extension of POSIX. It is included
  // unconditionally here for compatibility with code that assumes its presence.
  char domainname[BRIDGE_UTSNAME_FIELD_LENGTH];
};

#ifndef BRIDGE_FD_SETSIZE
#define BRIDGE_FD_SETSIZE 1024
#endif

struct BridgeFDSet {
  uint8_t file_descriptor_set[BRIDGE_FD_SETSIZE];
};

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // ASYLO_PLATFORM_COMMON_BRIDGE_TYPES_H_
