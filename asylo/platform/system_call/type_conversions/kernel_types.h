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

enum StatFsFlag {
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

#endif  // ASYLO_PLATFORM_SYSTEM_CALL_TYPE_CONVERSIONS_KERNEL_TYPES_H_
