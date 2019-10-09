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
typedef int64_t bridge_sigset_t;

// The wait options that are supported inside the enclave.
enum WaitOptions {
  BRIDGE_WNOHANG = 1,
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

// The signal behavior flags.
enum SignalFlags {
  BRIDGE_SA_NODEFER = 0x01,
  BRIDGE_SA_RESETHAND = 0x02,
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

struct bridge_timeval {
  int64_t tv_sec;
  int64_t tv_usec;
} ABSL_ATTRIBUTE_PACKED;

struct bridge_siginfo_t {
  int32_t si_signo;
  int32_t si_code;
};

struct BridgeSignalHandler {
  void (*sigaction)(int, struct bridge_siginfo_t *, void *);
  bridge_sigset_t mask;
  int flags;
};

struct BridgeRUsage {
  struct bridge_timeval ru_utime;
  struct bridge_timeval ru_stime;
};

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

// The maximum size of the passwd struct strings we support, including name,
// passwd, gecos, user information, home directory, and shell program.
#define BRIDGE_PASSWD_FIELD_LENGTH 1024

struct BridgePassWd {
  char pw_name[BRIDGE_PASSWD_FIELD_LENGTH];
  char pw_passwd[BRIDGE_PASSWD_FIELD_LENGTH];
  uid_t pw_uid;
  gid_t pw_gid;
  char pw_gecos[BRIDGE_PASSWD_FIELD_LENGTH];
  char pw_dir[BRIDGE_PASSWD_FIELD_LENGTH];
  char pw_shell[BRIDGE_PASSWD_FIELD_LENGTH];
};

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // ASYLO_PLATFORM_COMMON_BRIDGE_TYPES_H_
