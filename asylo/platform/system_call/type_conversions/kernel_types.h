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

#ifndef ASYLO_PLATFORM_SYSTEM_CALL_TYPE_CONVERSIONS_KERNEL_TYPES_H_
#define ASYLO_PLATFORM_SYSTEM_CALL_TYPE_CONVERSIONS_KERNEL_TYPES_H_

#include <stdint.h>

#include "asylo/platform/system_call/type_conversions/generated_types.h"

#define KLINUX_FD_SETSIZE 1024
#define KLINUX_NFDBITS (sizeof(int64_t) * 8)
#define KLINUX_FD_SET(n, p) \
  ((p)->fds_bits[(n) / KLINUX_NFDBITS] |= (1L << ((n) % KLINUX_NFDBITS)))
#define KLINUX_FD_CLR(n, p) \
  ((p)->fds_bits[(n) / KLINUX_NFDBITS] &= ~(1L << ((n) % KLINUX_NFDBITS)))
#define KLINUX_FD_ISSET(n, p) \
  ((p)->fds_bits[(n) / KLINUX_NFDBITS] & (1L << ((n) % KLINUX_NFDBITS)))
#define KLINUX_FD_ZERO(p)                                  \
  (__extension__(void)({                                   \
    size_t __i;                                            \
    char *__tmp = (char *)p;                               \
    for (__i = 0; __i < sizeof(*(p)); ++__i) *__tmp++ = 0; \
  }))

struct klinux_stat {
  uint64_t klinux_st_dev;
  uint64_t klinux_st_ino;
  uint64_t klinux_st_nlink;

  uint32_t klinux_st_mode;
  uint32_t klinux_st_uid;
  uint32_t klinux_st_gid;
  uint32_t klinux_unsed_pad0;
  uint64_t klinux_st_rdev;
  int64_t klinux_st_size;
  int64_t klinux_st_blksize;
  int64_t klinux_st_blocks;

  uint64_t klinux_st_atime;
  uint64_t klinux_st_atime_nsec;
  uint64_t klinux_st_mtime;
  uint64_t klinux_st_mtime_nsec;
  uint64_t klinux_st_ctime;
  uint64_t klinux_st_ctime_nsec;
  int64_t klinux_unused[3];
};

struct klinux_sockaddr {
  int16_t klinux_sa_family;
  char klinux_sa_data[14];
};

struct klinux_sockaddr_un {
  int16_t klinux_sun_family;
  char klinux_sun_path[108];
};

struct klinux_in_addr {
  uint32_t klinux_s_addr;
};

struct klinux_sockaddr_in {
  int16_t klinux_sin_family;              // Address family (AF_INET)
  uint16_t klinux_sin_port;               // Port number
  struct klinux_in_addr klinux_sin_addr;  // IPv4 address

  // Pad to size of klinux_sockaddr (16 bytes).
  unsigned char klinux_sin_zero[sizeof(struct klinux_sockaddr) -
                                sizeof(int16_t) /* klinux_sa_family */ -
                                sizeof(uint16_t) /* klinux_sin_port */ -
                                sizeof(struct klinux_in_addr)];
};

struct klinux_in6_addr {
  uint8_t klinux_s6_addr[16];
};

struct klinux_sockaddr_in6 {
  int16_t klinux_sin6_family;               // Address family (AF_INET6)
  uint16_t klinux_sin6_port;                // Port number
  uint32_t klinux_sin6_flowinfo;            // IPv6 flow information
  struct klinux_in6_addr klinux_sin6_addr;  // IPv6 address
  uint32_t klinux_sin6_scope_id;            // Scope ID
};

struct klinux_statfs {
  int64_t klinux_f_type;
  int64_t klinux_f_bsize;
  uint64_t klinux_f_blocks;
  uint64_t klinux_f_bfree;
  uint64_t klinux_f_bavail;
  uint64_t klinux_f_files;
  uint64_t klinux_f_ffree;
  struct {
    int32_t __val[2];
  } klinux_f_fsid;
  int64_t klinux_f_namelen;
  int64_t klinux_f_frsize;
  int64_t klinux_f_flags;  // Linux uses a signed long word for the flags.
  int64_t klinux_f_spare[4];
};

enum klinux_statfs_flag {
  kLinux_ST_RDONLY = (1 << 0),
  kLinux_ST_NOSUID = (1 << 1),
  kLinux_ST_NODEV = (1 << 2),
  kLinux_ST_NOEXEC = (1 << 3),
  kLinux_ST_SYNCHRONOUS = (1 << 4),
  kLinux_ST_VALID = (1 << 5),
  kLinux_ST_MANDLOCK = (1 << 6),
  kLinux_ST_WRITE = (1 << 7),
  kLinux_ST_APPEND = (1 << 8),
  kLinux_ST_IMMUTABLE = (1 << 9),
  kLinux_ST_NOATIME = (1 << 10),
  kLinux_ST_NODIRATIME = (1 << 11),
  kLinux_ST_RELATIME = (1 << 12),
};

struct klinux_fd_set {
  uint64_t fds_bits[(KLINUX_FD_SETSIZE / (8 * sizeof(uint64_t)))];
};

// The maximum number of CPUs we support. Chosen to be large enough to represent
// as many CPUs as an enclave-native cpu_set_t.
#define KLINUX_CPU_SET_MAX_CPUS 1024

typedef uint64_t klinux_cpu_set_word;

#define KLINUX_CPU_SET_NUM_WORDS \
  (KLINUX_CPU_SET_MAX_CPUS / (8 * sizeof(klinux_cpu_set_word)))

typedef struct {
  uint64_t words[KLINUX_CPU_SET_NUM_WORDS];
} klinux_cpu_set_t;

struct klinux_itimerval {
  struct kLinux_timeval klinux_it_interval;
  struct kLinux_timeval klinux_it_value;
};

struct klinux_pollfd {
  int klinux_fd;
  int16_t klinux_events;
  int16_t klinux_revents;
};

#define KLINUX_SIGSET_NWORDS (1024 / (8 * sizeof(uint64_t)))

typedef struct {
  uint64_t klinux_val[KLINUX_SIGSET_NWORDS];
} klinux_sigset_t;

typedef union klinux_epoll_data {
  void *ptr;
  int fd;
  uint32_t u32;
  uint64_t u64;
} klinux_epoll_data_t;

struct klinux_epoll_event {
  uint32_t events;
  klinux_epoll_data_t data;
} ABSL_ATTRIBUTE_PACKED;

struct klinux_rusage {
  struct kLinux_timeval ru_utime;
  struct kLinux_timeval ru_stime;
  int64_t ru_maxrss;
  int64_t ru_ixrss;
  int64_t ru_idrss;
  int64_t ru_isrss;
  int64_t ru_minflt;
  int64_t ru_majflt;
  int64_t ru_nswap;
  int64_t ru_inblock;
  int64_t ru_oublock;
  int64_t ru_msgsnd;
  int64_t ru_msgrcv;
  int64_t ru_nsignals;
  int64_t ru_nvcsw;
  int64_t ru_nivcsw;
};

#define KLINUX_WIFEXITED(status) (((status)&0x7f) == 0)
#define KLINUX_WIFSTOPPED(status) (((status)&0xff) == 0x7f)

struct klinux_utsname {
  char sysname[kLinux__UTSNAME_SYSNAME_LENGTH];
  char nodename[kLinux__UTSNAME_NODENAME_LENGTH];
  char release[kLinux__UTSNAME_RELEASE_LENGTH];
  char version[kLinux__UTSNAME_VERSION_LENGTH];
  char machine[kLinux__UTSNAME_MACHINE_LENGTH];

#if (defined(__USE_GNU) && __USE_GNU) || \
    (defined(__GNU_VISIBLE) && __GNU_VISIBLE)
  char domainname[kLinux__UTSNAME_DOMAIN_LENGTH];
#else
  char __domainname[kLinux__UTSNAME_DOMAIN_LENGTH];
#endif
};

#define KLINUX__SI_MAX_SIZE 128
#define KLINUX__SI_PAD_SIZE ((KLINUX__SI_MAX_SIZE / sizeof(int)) - 4)
#define KLINUX__SI_ALIGNMENT

typedef union klinux_sigval {
  int sival_int;
  void *sival_ptr;
} klinux_sigval_t;

typedef struct {
  int si_signo;  // Signal number.
  int si_errno;  // If non-zero, an errno value associated with this signal, as
                 // defined in <errno.h>.
  int si_code;   // Signal code.

  union {
    int klinux_pad[KLINUX__SI_PAD_SIZE];

    /* kill().  */
    struct {
      pid_t klinux_si_pid;  // Sending process ID.
      uid_t klinux_si_uid;  // Real user ID of sending process.
    } klinux_kill;

    /* POSIX.1b timers.  */
    struct {
      int klinux_si_tid;                 // Timer ID.
      int klinux_si_overrun;             // Overrun count.
      klinux_sigval_t klinux_si_sigval;  // Signal value.
    } klinux_timer;

    /* POSIX.1b signals.  */
    struct {
      pid_t klinux_si_pid;               // Sending process ID.
      uid_t klinux_si_uid;               // Real user ID of sending process.
      klinux_sigval_t klinux_si_sigval;  // Signal value.
    } klinux_rt;

    /* SIGCHLD.  */
    struct {
      pid_t klinux_si_pid;      // Which child.
      uid_t klinux_si_uid;      // Real user ID of sending process.
      int klinux_si_status;     // Exit value or signal.
      int64_t klinux_si_utime;  // Assumes clock_t on Linux is a long int type.
      int64_t klinux_si_stime;  // Assumes clock_t on Linux is a long int type.
    } klinux_sigchld;

    /* SIGILL, SIGFPE, SIGSEGV, SIGBUS.  */
    struct {
      void *klinux_si_addr;        // Faulting insn/memory ref.
      int16_t klinux_si_addr_lsb;  // Valid LSB of the reported address.
    } klinux_sigfault;

    /* SIGPOLL.  */
    struct {
      int64_t klinux_si_band;  // Band event for SIGPOLL.
      int klinux_si_fd;
    } klinux_sigpoll;

    /* SIGSYS.  */
    struct {
      void *klinux_call_addr;    // Calling user insn.
      int klinux_syscall;        // Triggering system call number.
      unsigned int klinux_arch;  // AUDIT_ARCH_* of syscall.
    } klinux_sigsys;
  } klinux_sifields;
} klinux_siginfo_t KLINUX__SI_ALIGNMENT;

#endif  // ASYLO_PLATFORM_SYSTEM_CALL_TYPE_CONVERSIONS_KERNEL_TYPES_H_
