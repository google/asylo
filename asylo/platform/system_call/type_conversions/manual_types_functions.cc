/*
 *
 * Copyright 2019 Asylo authors
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

#include "asylo/platform/system_call/type_conversions/manual_types_functions.h"

#include <sched.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>

#include <algorithm>
#include <cstring>

#include "absl/strings/str_cat.h"
#include "asylo/platform/system_call/type_conversions/generated_types.h"
#include "asylo/platform/system_call/type_conversions/generated_types_functions.h"

namespace {

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
// structures. Copies the sockaddr in |source|, of length |source_len|, into the
// buffer pointed to by |addr_dest|, which has |addrlen_dest| bytes available.
// The copy is truncated if the destination buffer is too small. The number of
// bytes in the un-truncated structure is written to addrlen_dest.
void CopySockaddr(void *source, socklen_t source_len, void *addr_dest,
                  socklen_t *addrlen_dest) {
  memcpy(addr_dest, source, std::min(*addrlen_dest, source_len));
  *addrlen_dest = source_len;
}

inline void klinux_sigemptyset(klinux_sigset_t *klinux_set) {
  memset(klinux_set, 0, sizeof(klinux_sigset_t));
}

inline int klinux_sigismember(const klinux_sigset_t *klinux_set,
                              int klinux_sig) {
  uint64_t sig = klinux_sig - 1;
  return 1 & (klinux_set->klinux_val[0] >> sig);
}

inline void klinux_sigaddset(klinux_sigset_t *klinux_set, int klinux_sig) {
  uint64_t sig = klinux_sig - 1;
  klinux_set->klinux_val[0] |= 1UL << sig;
}

// Copies the C string |source_buf| into |dest_buf|. Only copies up to size-1
// non-null characters. Always terminates the copied string with a null byte on
// a successful write.
//
// Fails if |source_buf| contains more than |size| bytes (including the
// terminating null byte).
bool CStringCopy(const char *source_buf, char *dest_buf, size_t size) {
  int ret = snprintf(dest_buf, size, "%s", source_buf);
  return ret >= 0 && static_cast<size_t>(ret) < size;
}

}  // namespace

int FromkLinuxErrno(int klinux_errno) {
  absl::optional<int> error_number = FromkLinuxErrorNumber(klinux_errno);
  return error_number ? *error_number : 0x8000 | klinux_errno;
}

absl::optional<int> TokLinuxSocketType(int input) {
  int sock_type = input;
  int output = 0;

  if (sock_type & SOCK_NONBLOCK) {
    output |= kLinux_SOCK_NONBLOCK;
    sock_type &= ~SOCK_NONBLOCK;
  }

  if (sock_type & SOCK_CLOEXEC) {
    output |= kLinux_SOCK_CLOEXEC;
    sock_type &= ~SOCK_CLOEXEC;
  }

  if (!sock_type) {  // Only SOCK_CLOEXEC or SOCK_NONBLOCK are present.
    return output;
  }

  switch (sock_type) {
    case SOCK_STREAM:
      output |= kLinux_SOCK_STREAM;
      break;
    case SOCK_DGRAM:
      output |= kLinux_SOCK_DGRAM;
      break;
    case SOCK_SEQPACKET:
      output |= kLinux_SOCK_SEQPACKET;
      break;
    case SOCK_RAW:
      output |= kLinux_SOCK_RAW;
      break;
    case SOCK_RDM:
      output |= kLinux_SOCK_RDM;
      break;
    case SOCK_PACKET:
      output |= kLinux_SOCK_PACKET;
      break;
    default:
      return absl::nullopt;
  }
  return output;
}

absl::optional<int> FromkLinuxSocketType(int input) {
  int kLinux_sock_type = input;
  int output = 0;

  if (kLinux_sock_type & kLinux_SOCK_NONBLOCK) {
    output |= SOCK_NONBLOCK;
    kLinux_sock_type &= ~kLinux_SOCK_NONBLOCK;
  }

  if (kLinux_sock_type & kLinux_SOCK_CLOEXEC) {
    output |= SOCK_CLOEXEC;
    kLinux_sock_type &= ~kLinux_SOCK_CLOEXEC;
  }

  if (!kLinux_sock_type) {  // Only kLinux_SOCK_CLOEXEC or kLinux_SOCK_NONBLOCK
                            // are present.
    return output;
  }

  switch (kLinux_sock_type) {
    case kLinux_SOCK_STREAM:
      output |= SOCK_STREAM;
      break;
    case kLinux_SOCK_DGRAM:
      output |= SOCK_DGRAM;
      break;
    case kLinux_SOCK_SEQPACKET:
      output |= SOCK_SEQPACKET;
      break;
    case kLinux_SOCK_RAW:
      output |= SOCK_RAW;
      break;
    case kLinux_SOCK_RDM:
      output |= SOCK_RDM;
      break;
    case kLinux_SOCK_PACKET:
      output |= SOCK_PACKET;
      break;
    default:
      return absl::nullopt;
  }
  return output;
}

absl::optional<int> TokLinuxOptionName(int level, int option_name) {
  if (level == IPPROTO_TCP) {
    return TokLinuxTcpOptionName(option_name);
  } else if (level == IPPROTO_IPV6) {
    return TokLinuxIpV6OptionName(option_name);
  } else if (level == SOL_SOCKET) {
    return TokLinuxSocketOptionName(option_name);
  }

  return absl::nullopt;
}

absl::optional<int> FromkLinuxOptionName(int level, int klinux_option_name) {
  if (level == IPPROTO_TCP) {
    return FromkLinuxTcpOptionName(klinux_option_name);
  } else if (level == IPPROTO_IPV6) {
    return FromkLinuxIpV6OptionName(klinux_option_name);
  } else if (level == SOL_SOCKET) {
    return FromkLinuxSocketOptionName(klinux_option_name);
  }

  return absl::nullopt;
}

bool FromkLinuxStat(const struct klinux_stat *input, struct stat *output) {
  if (!input || !output) return false;
  output->st_atime = input->klinux_st_atime;
  output->st_blksize = input->klinux_st_blksize;
  output->st_blocks = input->klinux_st_blocks;
  output->st_mtime = input->klinux_st_mtime;
  output->st_dev = input->klinux_st_dev;
  output->st_gid = input->klinux_st_gid;
  output->st_ino = input->klinux_st_ino;
  output->st_mode = input->klinux_st_mode;
  output->st_ctime = input->klinux_st_ctime;
  output->st_nlink = input->klinux_st_nlink;
  output->st_rdev = input->klinux_st_rdev;
  output->st_size = input->klinux_st_size;
  output->st_uid = input->klinux_st_uid;
  return true;
}

bool TokLinuxStat(const struct stat *input, struct klinux_stat *output) {
  if (!input || !output) return false;
  output->klinux_st_atime = input->st_atime;
  output->klinux_st_blksize = input->st_blksize;
  output->klinux_st_blocks = input->st_blocks;
  output->klinux_st_mtime = input->st_mtime;
  output->klinux_st_dev = input->st_dev;
  output->klinux_st_gid = input->st_gid;
  output->klinux_st_ino = input->st_ino;
  output->klinux_st_mode = input->st_mode;
  output->klinux_st_ctime = input->st_ctime;
  output->klinux_st_nlink = input->st_nlink;
  output->klinux_st_rdev = input->st_rdev;
  output->klinux_st_size = input->st_size;
  output->klinux_st_uid = input->st_uid;
  return true;
}

bool SockaddrTokLinuxSockaddrUn(const struct sockaddr *input,
                                socklen_t input_addrlen,
                                klinux_sockaddr_un *output) {
  if (!input || !output || input_addrlen == 0 || input->sa_family != AF_UNIX ||
      input_addrlen < sizeof(output->klinux_sun_family)) {
    output = nullptr;
    return false;
  }

  struct sockaddr_un *sock_un = const_cast<struct sockaddr_un *>(
      reinterpret_cast<const struct sockaddr_un *>(input));
  output->klinux_sun_family = kLinux_AF_UNIX;
  InitializeToZeroArray(output->klinux_sun_path);
  ReinterpretCopyArray(output->klinux_sun_path, sock_un->sun_path,
                       input_addrlen - sizeof(input->sa_family));
  return true;
}

bool SockaddrTokLinuxSockaddrIn(const struct sockaddr *input,
                                socklen_t input_addrlen,
                                klinux_sockaddr_in *output) {
  if (!input || !output || input_addrlen == 0 || input->sa_family != AF_INET ||
      input_addrlen < sizeof(struct sockaddr_in)) {
    output = nullptr;
    return false;
  }

  struct sockaddr_in *sockaddr_in_from = const_cast<struct sockaddr_in *>(
      reinterpret_cast<const struct sockaddr_in *>(input));

  output->klinux_sin_family = kLinux_AF_INET;
  output->klinux_sin_port = sockaddr_in_from->sin_port;
  InitializeToZeroSingle(&output->klinux_sin_addr);
  ReinterpretCopySingle(&output->klinux_sin_addr, &sockaddr_in_from->sin_addr);
  InitializeToZeroArray(output->klinux_sin_zero);
  ReinterpretCopyArray(output->klinux_sin_zero, sockaddr_in_from->sin_zero,
                       std::min(sizeof(output->klinux_sin_zero),
                                sizeof(sockaddr_in_from->sin_zero)));
  return true;
}

bool SockaddrTokLinuxSockaddrIn6(const struct sockaddr *input,
                                 socklen_t input_addrlen,
                                 klinux_sockaddr_in6 *output) {
  if (!input || !output || input_addrlen == 0 || input->sa_family != AF_INET6 ||
      input_addrlen < sizeof(struct sockaddr_in6)) {
    output = nullptr;
    return false;
  }

  struct sockaddr_in6 *sockaddr_in6_from = const_cast<struct sockaddr_in6 *>(
      reinterpret_cast<const struct sockaddr_in6 *>(input));

  output->klinux_sin6_family = kLinux_AF_INET6;
  output->klinux_sin6_flowinfo = sockaddr_in6_from->sin6_flowinfo;
  output->klinux_sin6_port = sockaddr_in6_from->sin6_port;
  output->klinux_sin6_scope_id = sockaddr_in6_from->sin6_scope_id;
  InitializeToZeroSingle(&output->klinux_sin6_addr);
  ReinterpretCopySingle(&output->klinux_sin6_addr,
                        &sockaddr_in6_from->sin6_addr);
  return true;
}

bool FromkLinuxSockAddrUn(const struct klinux_sockaddr_un *input,
                          struct sockaddr_un *output) {
  if (!input || !output) {
    return false;
  }
  output->sun_family = AF_UNIX;
  InitializeToZeroArray(output->sun_path);
  ReinterpretCopyArray(
      output->sun_path, input->klinux_sun_path,
      sizeof(struct klinux_sockaddr_un) - sizeof(input->klinux_sun_family));
  return true;
}

bool FromkLinuxSockAddrIn(const struct klinux_sockaddr_in *input,
                          struct sockaddr_in *output) {
  if (!input || !output) {
    return false;
  }
  output->sin_family = AF_INET;
  output->sin_port = input->klinux_sin_port;
  InitializeToZeroSingle(&output->sin_addr);
  ReinterpretCopySingle(&output->sin_addr, &input->klinux_sin_port);
  InitializeToZeroArray(output->sin_zero);
  ReinterpretCopyArray(
      output->sin_zero, input->klinux_sin_zero,
      std::min(sizeof(output->sin_zero), sizeof(input->klinux_sin_zero)));
  return true;
}

bool FromkLinuxSockAddrIn6(const struct klinux_sockaddr_in6 *input,
                           struct sockaddr_in6 *output) {
  if (!input || !output) {
    return false;
  }
  output->sin6_family = AF_INET;
  output->sin6_port = input->klinux_sin6_port;
  output->sin6_scope_id = input->klinux_sin6_scope_id;
  output->sin6_flowinfo = input->klinux_sin6_flowinfo;
  InitializeToZeroSingle(&output->sin6_addr);
  ReinterpretCopySingle(&output->sin6_addr, &input->klinux_sin6_port);
  return true;
}

bool FromkLinuxStatFs(const struct klinux_statfs *input,
                      struct statfs *output) {
  if (!input || !output) return false;
  output->f_type = input->klinux_f_type;
  output->f_bsize = input->klinux_f_bsize;
  output->f_blocks = input->klinux_f_blocks;
  output->f_bfree = input->klinux_f_bfree;
  output->f_bavail = input->klinux_f_bavail;
  output->f_files = input->klinux_f_files;
  output->f_ffree = input->klinux_f_ffree;
  output->f_fsid.__val[0] = input->klinux_f_fsid.__val[0];
  output->f_fsid.__val[1] = input->klinux_f_fsid.__val[1];
  output->f_namelen = input->klinux_f_namelen;
  output->f_frsize = input->klinux_f_frsize;
  output->f_flags = input->klinux_f_flags;
  memset(output->f_spare, 0, sizeof(output->f_spare));
  return true;
}

bool TokLinuxStatFs(const struct statfs *input, struct klinux_statfs *output) {
  if (!input || !output) return false;
  output->klinux_f_bsize = input->f_bsize;
  output->klinux_f_frsize = input->f_frsize;
  output->klinux_f_blocks = input->f_blocks;
  output->klinux_f_bfree = input->f_bfree;
  output->klinux_f_bavail = input->f_bavail;
  output->klinux_f_files = input->f_files;
  output->klinux_f_ffree = input->f_ffree;
  output->klinux_f_fsid.__val[0] = input->f_fsid.__val[0];
  output->klinux_f_fsid.__val[1] = input->f_fsid.__val[1];
  output->klinux_f_namelen = input->f_namelen;
  output->klinux_f_frsize = input->f_frsize;
  output->klinux_f_flags = input->f_flags;
  memset(output->klinux_f_spare, 0, sizeof(output->klinux_f_spare));
  return true;
}

int64_t FromkLinuxStatFsFlags(int64_t input) {
  int64_t result = 0;

  if (input & kLinux_ST_NOSUID) result |= ST_NOSUID;
  if (input & kLinux_ST_RDONLY) result |= ST_RDONLY;
#if (defined(__USE_GNU) && __USE_GNU) || \
    (defined(__GNU_VISIBLE) && __GNU_VISIBLE)
  if (input & kLinux_ST_MANDLOCK) result |= ST_MANDLOCK;
  if (input & kLinux_ST_NOATIME) result |= ST_NOATIME;
  if (input & kLinux_ST_NODEV) result |= ST_NODEV;
  if (input & kLinux_ST_NODIRATIME) result |= ST_NODIRATIME;
  if (input & kLinux_ST_NOEXEC) result |= ST_NOEXEC;
  if (input & kLinux_ST_RELATIME) result |= ST_RELATIME;
  if (input & kLinux_ST_SYNCHRONOUS) result |= ST_SYNCHRONOUS;
#endif
  return result;
}

int64_t TokLinuxStatFsFlags(int64_t input) {
  int64_t result = 0;

  if (input & ST_NOSUID) result |= kLinux_ST_NOSUID;
  if (input & ST_RDONLY) result |= kLinux_ST_RDONLY;
#if (defined(__USE_GNU) && __USE_GNU) || \
    (defined(__GNU_VISIBLE) && __GNU_VISIBLE)
  if (input & ST_MANDLOCK) result |= kLinux_ST_MANDLOCK;
  if (input & ST_NOATIME) result |= kLinux_ST_NOATIME;
  if (input & ST_NODEV) result |= kLinux_ST_NODEV;
  if (input & ST_NODIRATIME) result |= kLinux_ST_NODIRATIME;
  if (input & ST_NOEXEC) result |= kLinux_ST_NOEXEC;
  if (input & ST_RELATIME) result |= kLinux_ST_RELATIME;
  if (input & ST_SYNCHRONOUS) result |= kLinux_ST_SYNCHRONOUS;
#endif
  return result;
}

bool FromkLinuxSockAddr(const struct klinux_sockaddr *input,
                        socklen_t input_len, struct sockaddr *output,
                        socklen_t *output_len,
                        void (*abort_handler)(const char *)) {
  if (!input || !output || !output_len || input_len == 0) {
    output = nullptr;
    return false;
  }

  int16_t klinux_family = input->klinux_sa_family;
  if (klinux_family == kLinux_AF_UNIX) {
    if (input_len < sizeof(struct klinux_sockaddr_un)) {
      return false;
    }

    struct klinux_sockaddr_un *klinux_sockaddr_un_in =
        const_cast<struct klinux_sockaddr_un *>(
            reinterpret_cast<const struct klinux_sockaddr_un *>(input));

    struct sockaddr_un sockaddr_un_out;
    sockaddr_un_out.sun_family = AF_UNIX;
    InitializeToZeroArray(sockaddr_un_out.sun_path);
    ReinterpretCopyArray(
        sockaddr_un_out.sun_path, klinux_sockaddr_un_in->klinux_sun_path,
        std::min(sizeof(sockaddr_un_out.sun_path),
                 sizeof(klinux_sockaddr_un_in->klinux_sun_path)));
    CopySockaddr(&sockaddr_un_out, sizeof(sockaddr_un_out), output, output_len);
  } else if (klinux_family == kLinux_AF_INET) {
    if (input_len < sizeof(struct klinux_sockaddr_in)) {
      return false;
    }
    struct klinux_sockaddr_in *klinux_sockaddr_in_in =
        const_cast<struct klinux_sockaddr_in *>(
            reinterpret_cast<const struct klinux_sockaddr_in *>(input));

    struct sockaddr_in sockaddr_in_out;
    sockaddr_in_out.sin_family = AF_INET;
    sockaddr_in_out.sin_port = klinux_sockaddr_in_in->klinux_sin_port;
    InitializeToZeroSingle(&sockaddr_in_out.sin_addr);
    ReinterpretCopySingle(&sockaddr_in_out.sin_addr,
                          &klinux_sockaddr_in_in->klinux_sin_addr);
    InitializeToZeroArray(sockaddr_in_out.sin_zero);
    ReinterpretCopyArray(sockaddr_in_out.sin_zero,
                         klinux_sockaddr_in_in->klinux_sin_zero);
    CopySockaddr(&sockaddr_in_out, sizeof(sockaddr_in_out), output, output_len);
  } else if (klinux_family == kLinux_AF_INET6) {
    if (input_len < sizeof(struct klinux_sockaddr_in6)) {
      return false;
    }

    struct klinux_sockaddr_in6 *klinux_sockaddr_in6_in =
        const_cast<struct klinux_sockaddr_in6 *>(
            reinterpret_cast<const struct klinux_sockaddr_in6 *>(input));

    struct sockaddr_in6 sockaddr_in6_out;
    sockaddr_in6_out.sin6_family = AF_INET6;
    sockaddr_in6_out.sin6_port = klinux_sockaddr_in6_in->klinux_sin6_port;
    sockaddr_in6_out.sin6_flowinfo =
        klinux_sockaddr_in6_in->klinux_sin6_flowinfo;
    sockaddr_in6_out.sin6_scope_id =
        klinux_sockaddr_in6_in->klinux_sin6_scope_id;
    InitializeToZeroSingle(&sockaddr_in6_out.sin6_addr);
    ReinterpretCopySingle(&sockaddr_in6_out.sin6_addr,
                          &klinux_sockaddr_in6_in->klinux_sin6_addr);
    CopySockaddr(&sockaddr_in6_out, sizeof(sockaddr_in6_out), output,
                 output_len);
  } else if (klinux_family == kLinux_AF_UNSPEC) {
    output = nullptr;
    *output_len = 0;
  } else {
    if (abort_handler != nullptr) {
      std::string message = absl::StrCat(
          "Type conversion error - Unsupported AF family: ", klinux_family);
      abort_handler(message.c_str());
    } else {
      abort();
    }
  }
  return true;
}

bool TokLinuxSockAddr(const struct sockaddr *input, socklen_t input_len,
                      struct klinux_sockaddr *output, socklen_t *output_len,
                      void (*abort_handler)(const char *)) {
  if (!input || input_len == 0 || !output || !output_len) {
    return false;
  }

  if (input->sa_family == AF_UNIX) {
    struct klinux_sockaddr_un klinux_sock_un;
    if (!SockaddrTokLinuxSockaddrUn(input, input_len, &klinux_sock_un)) {
      return false;
    }
    CopySockaddr(&klinux_sock_un, sizeof(klinux_sock_un), output, output_len);
  } else if (input->sa_family == AF_INET) {
    struct klinux_sockaddr_in klinux_sock_in;
    if (!SockaddrTokLinuxSockaddrIn(input, input_len, &klinux_sock_in)) {
      return false;
    }
    CopySockaddr(&klinux_sock_in, sizeof(klinux_sock_in), output, output_len);
  } else if (input->sa_family == AF_INET6) {
    struct klinux_sockaddr_in6 klinux_sock_in6;
    if (!SockaddrTokLinuxSockaddrIn6(input, input_len, &klinux_sock_in6)) {
      return false;
    }
    CopySockaddr(&klinux_sock_in6, sizeof(klinux_sock_in6), output, output_len);
  } else if (input->sa_family == AF_UNSPEC) {
    output = nullptr;
    *output_len = 0;
  } else {
    if (abort_handler != nullptr) {
      std::string message =
          absl::StrCat("Unsupported AF family encountered: ", input->sa_family);
      abort_handler(message.c_str());
    } else {
      abort();
    }
  }
  return true;
}

bool FromkLinuxFdSet(const struct klinux_fd_set *input, fd_set *output) {
  if (!input || !output) {
    output = nullptr;
    return false;
  }
  FD_ZERO(output);
  for (int fd = 0; fd < std::min(KLINUX_FD_SETSIZE, FD_SETSIZE); ++fd) {
    if (KLINUX_FD_ISSET(fd, input)) {
      FD_SET(fd, output);
    }
  }
  return true;
}

bool TokLinuxFdSet(const fd_set *input, struct klinux_fd_set *output) {
  if (!input || !output) {
    output = nullptr;
    return false;
  }
  KLINUX_FD_ZERO(output);
  for (int fd = 0; fd < std::min(FD_SETSIZE, KLINUX_FD_SETSIZE); ++fd) {
    if (FD_ISSET(fd, input)) {
      KLINUX_FD_SET(fd, output);
    }
  }
  return true;
}

absl::optional<int> FromkLinuxSignalNumber(int input) {
#if defined(SIGRTMIN) && defined(SIGRTMAX)
  if (input >= kLinux_SIGRTMIN && input <= kLinux_SIGRTMAX) {
    return SIGRTMIN + input - kLinux_SIGRTMIN;
  }
#endif
  return FromkLinuxBaseSignalNumber(input);
}

absl::optional<int> TokLinuxSignalNumber(int input) {
#if defined(SIGRTMIN) && defined(SIGRTMAX)
  if (input >= SIGRTMIN && input <= SIGRTMAX) {
    return kLinux_SIGRTMIN + input - SIGRTMIN;
  }
#endif
  return TokLinuxBaseSignalNumber(input);
}

bool TokLinuxSigset(const sigset_t *input, klinux_sigset_t *output) {
  if (!input || !output) {
    output = nullptr;
    return false;
  }
  klinux_sigemptyset(output);
  for (int sig = 1; sig < NSIG; sig++) {
    if (sigismember(input, sig)) {
      absl::optional<int> klinux_sig = TokLinuxSignalNumber(sig);
      if (klinux_sig) {
        klinux_sigaddset(output, *klinux_sig);
      }
    }
  }
  return true;
}

bool FromkLinuxSigset(const klinux_sigset_t *input, sigset_t *output) {
  if (!input || !output) {
    output = nullptr;
    return false;
  }
  sigemptyset(output);
  for (int klinux_sig = 1; klinux_sig < kLinux_NSIG; klinux_sig++) {
    absl::optional<int> sig = FromkLinuxSignalNumber(klinux_sig);
    if (klinux_sigismember(input, klinux_sig) && sig) {
      sigaddset(output, *sig);
    }
  }
  return true;
}

inline uint64_t kLinuxCpuWordNum(int cpu) {
  return cpu / (8 * sizeof(klinux_cpu_set_word));
}

inline klinux_cpu_set_word kLinuxCpuBitNum(int cpu) {
  return cpu % (8 * sizeof(klinux_cpu_set_word));
}

int kLinuxCpuSetCheckBit(int cpu, klinux_cpu_set_t *set) {
  return (set->words[kLinuxCpuWordNum(cpu)] &
          (static_cast<klinux_cpu_set_word>(1) << kLinuxCpuBitNum(cpu))) != 0;
}

bool FromkLinuxCpuSet(klinux_cpu_set_t *input, cpu_set_t *output) {
  if (!input || !output) {
    return false;
  }

  CPU_ZERO(output);

  for (int cpu = 0; cpu < KLINUX_CPU_SET_MAX_CPUS; cpu++) {
    if (kLinuxCpuSetCheckBit(cpu, input)) {
      CPU_SET(cpu, output);
    }
  }
  return true;
}

bool TokLinuxItimerval(const struct itimerval *input,
                       struct klinux_itimerval *output) {
  if (!input || !output) {
    return false;
  }
  if (!TokLinuxtimeval(&input->it_interval, &output->klinux_it_interval) ||
      !TokLinuxtimeval(&input->it_value, &output->klinux_it_value)) {
    return false;
  }
  return true;
}

bool FromkLinuxItimerval(const struct klinux_itimerval *input,
                         struct itimerval *output) {
  if (!input || !output) {
    return false;
  }
  if (!FromkLinuxtimeval(&input->klinux_it_interval, &output->it_interval) ||
      !FromkLinuxtimeval(&input->klinux_it_value, &output->it_value)) {
    return false;
  }
  return true;
}

bool TokLinuxPollfd(const struct pollfd *input, struct klinux_pollfd *output) {
  if (!input || !output) return false;

  absl::optional<int> klinux_events =
      input->events ? TokLinuxPollEvent(input->events) : 0;
  absl::optional<int> klinux_revents =
      input->revents ? TokLinuxPollEvent(input->revents) : 0;
  if (!klinux_events || !klinux_revents) {
    return false;
  }

  output->klinux_fd = input->fd;
  output->klinux_events = *klinux_events;
  output->klinux_revents = *klinux_revents;
  return true;
}

bool FromkLinuxPollfd(const struct klinux_pollfd *input,
                      struct pollfd *output) {
  if (!input || !output) return false;

  absl::optional<int> events =
      input->klinux_events ? FromkLinuxPollEvent(input->klinux_events) : 0;
  absl::optional<int> revents =
      input->klinux_revents ? FromkLinuxPollEvent(input->klinux_revents) : 0;
  if (!events || !revents) {
    return false;
  }

  output->fd = input->klinux_fd;
  output->events = *events;
  output->revents = *revents;
  return true;
}

bool TokLinuxEpollEvent(const struct epoll_event *input,
                        struct klinux_epoll_event *output) {
  if (!input || !output) return false;
  output->events = TokLinuxEpollEvents(input->events).value_or(0);
  if (input->events != 0 && output->events == 0) {
    return false;
  }
  output->data.u64 = input->data.u64;
  return true;
}

bool FromkLinuxEpollEvent(const struct klinux_epoll_event *input,
                          struct epoll_event *output) {
  if (!input || !output) return false;
  output->events = FromkLinuxEpollEvents(input->events).value_or(0);
  if (input->events != 0 && output->events == 0) {
    return false;
  }
  output->data.u64 = input->data.u64;
  return true;
}

bool FromkLinuxRusage(const struct klinux_rusage *input,
                      struct rusage *output) {
  if (!input || !output) {
    return false;
  }
  if (!FromkLinuxtimeval(&input->ru_stime, &output->ru_stime) ||
      !FromkLinuxtimeval(&input->ru_utime, &output->ru_utime)) {
    return false;
  }
  return true;
}

bool TokLinuxRusage(const struct rusage *input, struct klinux_rusage *output) {
  if (!input || !output) {
    return false;
  }
  if (!TokLinuxtimeval(&input->ru_stime, &output->ru_stime) ||
      !TokLinuxtimeval(&input->ru_utime, &output->ru_utime)) {
    return false;
  }
  return true;
}

int FromkLinuxToNewlibWstatus(int input) {
  int info = static_cast<int>(input >> 8 & 0xff) << 8;
  int code = input & 0x7f;

  if (KLINUX_WIFEXITED(input)) {
    code = 0;
  } else if (KLINUX_WIFSTOPPED(input)) {
    code = 0x7f;
  }

  return info + code;
}

bool FromkLinuxUtsName(const struct klinux_utsname *input,
                       struct utsname *output) {
  if (!input || !output) {
    return false;
  }

  if (!CStringCopy(input->sysname, output->sysname, sizeof(output->sysname)) ||
      !CStringCopy(input->nodename, output->nodename,
                   sizeof(output->nodename)) ||
      !CStringCopy(input->release, output->release, sizeof(output->release)) ||
      !CStringCopy(input->version, output->version, sizeof(output->version)) ||
      !CStringCopy(input->machine, output->machine, sizeof(output->machine))) {
    return false;
  }

#if (defined(__USE_GNU) && __USE_GNU) || \
    (defined(__GNU_VISIBLE) && __GNU_VISIBLE)
  if (!CStringCopy(input->domainname, output->domainname,
                   sizeof(output->domainname))) {
    return false;
  }
#else
  if (!CStringCopy(input->__domainname, output->domainname,
                   sizeof(output->domainname))) {
    return false;
  }
#endif
  return true;
}

// Priorities are encoded into a single 32-bit integer. The bottom 3 bits are
// the level and the rest are the facility.
absl::optional<int> TokLinuxSyslogPriority(int input) {
  absl::optional<int> syslog_level = TokLinuxSyslogLevel(input & 0x07);
  absl::optional<int> syslog_facility = TokLinuxSyslogFacility(input & ~0x07);
  if (!syslog_level || !syslog_facility) {
    return absl::nullopt;
  }
  return *syslog_level | *syslog_facility;
}

bool FromkLinuxSiginfo(const klinux_siginfo_t *input, siginfo_t *output) {
  if (!input || !output) {
    return false;
  }
  absl::optional<int> si_signo = FromkLinuxSignalNumber(input->si_signo);
  if (!si_signo) {
    return false;
  }
  output->si_signo = *si_signo;
  output->si_code =
      FromkLinuxSignalCode(input->si_code).value_or(kLinux_SI_USER);
  return true;
}
