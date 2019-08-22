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

#include <algorithm>
#include <cstring>

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

}  // namespace

void TokLinuxSocketType(const int *input, int *output) {
  int sock_type = *input;
  *output = 0;

  if (sock_type & SOCK_NONBLOCK) {
    *output |= kLinux_SOCK_NONBLOCK;
    sock_type &= ~SOCK_NONBLOCK;
  }

  if (sock_type & SOCK_CLOEXEC) {
    *output |= kLinux_SOCK_CLOEXEC;
    sock_type &= ~SOCK_CLOEXEC;
  }

  if (!sock_type) {  // Only SOCK_CLOEXEC or SOCK_NONBLOCK are present.
    return;
  }

  switch (sock_type) {
    case SOCK_STREAM:
      *output |= kLinux_SOCK_STREAM;
      break;
    case SOCK_DGRAM:
      *output |= kLinux_SOCK_DGRAM;
      break;
    case SOCK_SEQPACKET:
      *output |= kLinux_SOCK_SEQPACKET;
      break;
    case SOCK_RAW:
      *output |= kLinux_SOCK_RAW;
      break;
    case SOCK_RDM:
      *output |= kLinux_SOCK_RDM;
      break;
    case SOCK_PACKET:
      *output |= kLinux_SOCK_PACKET;
      break;
    default:
      *output = -1;  // Unsupported
  }
}

void FromkLinuxSocketType(const int *input, int *output) {
  int kLinux_sock_type = *input;
  *output = 0;

  if (kLinux_sock_type & kLinux_SOCK_NONBLOCK) {
    *output |= SOCK_NONBLOCK;
    kLinux_sock_type &= ~kLinux_SOCK_NONBLOCK;
  }

  if (kLinux_sock_type & kLinux_SOCK_CLOEXEC) {
    *output |= SOCK_CLOEXEC;
    kLinux_sock_type &= ~kLinux_SOCK_CLOEXEC;
  }

  if (!kLinux_sock_type) {  // Only kLinux_SOCK_CLOEXEC or kLinux_SOCK_NONBLOCK
                            // are present.
    return;
  }

  switch (kLinux_sock_type) {
    case kLinux_SOCK_STREAM:
      *output |= SOCK_STREAM;
      break;
    case kLinux_SOCK_DGRAM:
      *output |= SOCK_DGRAM;
      break;
    case kLinux_SOCK_SEQPACKET:
      *output |= SOCK_SEQPACKET;
      break;
    case kLinux_SOCK_RAW:
      *output |= SOCK_RAW;
      break;
    case kLinux_SOCK_RDM:
      *output |= SOCK_RDM;
      break;
    case kLinux_SOCK_PACKET:
      *output |= SOCK_PACKET;
      break;
    default:
      *output = -1;  // Unsupported
  }
}

void TokLinuxOptionName(const int *level, const int *option_name, int *output) {
  if (*level == IPPROTO_TCP) {
    TokLinuxTcpOptionName(option_name, output);
  } else if (*level == IPPROTO_IPV6) {
    TokLinuxIpV6OptionName(option_name, output);
  } else if (*level == SOL_SOCKET) {
    TokLinuxSocketOptionName(option_name, output);
  } else {
    *output = -1;
  }
}

void FromkLinuxOptionName(const int *level, const int *klinux_option_name,
                          int *output) {
  if (*level == IPPROTO_TCP) {
    FromkLinuxTcpOptionName(klinux_option_name, output);
  } else if (*level == IPPROTO_IPV6) {
    TokLinuxIpV6OptionName(klinux_option_name, output);
  } else if (*level == SOL_SOCKET) {
    FromkLinuxSocketOptionName(klinux_option_name, output);
  } else {
    *output = -1;
  }
}

void FromkLinuxStat(const struct klinux_stat *input, struct stat *output) {
  if (!input || !output) return;
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
}

void TokLinuxStat(const struct stat *input, struct klinux_stat *output) {
  if (!input || !output) return;
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
}

void SockaddrTokLinuxSockaddrUn(const struct sockaddr *input,
                                socklen_t input_addrlen,
                                klinux_sockaddr_un *output) {
  if (!input || !output || input_addrlen == 0 || input->sa_family != AF_UNIX ||
      input_addrlen < sizeof(output->klinux_sun_family)) {
    output = nullptr;
    return;
  }

  struct sockaddr_un *sock_un = const_cast<struct sockaddr_un *>(
      reinterpret_cast<const struct sockaddr_un *>(input));
  output->klinux_sun_family = kLinux_AF_UNIX;
  InitializeToZeroArray(output->klinux_sun_path);
  ReinterpretCopyArray(output->klinux_sun_path, sock_un->sun_path,
                       input_addrlen - sizeof(input->sa_family));
}

void SockaddrTokLinuxSockaddrIn(const struct sockaddr *input,
                                socklen_t input_addrlen,
                                klinux_sockaddr_in *output) {
  if (!input || !output || input_addrlen == 0 || input->sa_family != AF_INET ||
      input_addrlen < sizeof(struct sockaddr_in)) {
    output = nullptr;
    return;
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
}

void SockaddrTokLinuxSockaddrIn6(const struct sockaddr *input,
                                 socklen_t input_addrlen,
                                 klinux_sockaddr_in6 *output) {
  if (!input || !output || input_addrlen == 0 || input->sa_family != AF_INET6 ||
      input_addrlen < sizeof(struct sockaddr_in6)) {
    output = nullptr;
    return;
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
}

void FromkLinuxSockAddrUn(const struct klinux_sockaddr_un *input,
                          struct sockaddr_un *output) {
  if (!input || !output) {
    return;
  }
  output->sun_family = AF_UNIX;
  InitializeToZeroArray(output->sun_path);
  ReinterpretCopyArray(
      output->sun_path, input->klinux_sun_path,
      sizeof(struct klinux_sockaddr_un) - sizeof(input->klinux_sun_family));
}

void FromkLinuxSockAddrIn(const struct klinux_sockaddr_in *input,
                          struct sockaddr_in *output) {
  if (!input || !output) {
    return;
  }
  output->sin_family = AF_INET;
  output->sin_port = input->klinux_sin_port;
  InitializeToZeroSingle(&output->sin_addr);
  ReinterpretCopySingle(&output->sin_addr, &input->klinux_sin_port);
  InitializeToZeroArray(output->sin_zero);
  ReinterpretCopyArray(
      output->sin_zero, input->klinux_sin_zero,
      std::min(sizeof(output->sin_zero), sizeof(input->klinux_sin_zero)));
}

void FromkLinuxSockAddrIn6(const struct klinux_sockaddr_in6 *input,
                           struct sockaddr_in6 *output) {
  if (!input || !output) {
    return;
  }
  output->sin6_family = AF_INET;
  output->sin6_port = input->klinux_sin6_port;
  output->sin6_scope_id = input->klinux_sin6_scope_id;
  output->sin6_flowinfo = input->klinux_sin6_flowinfo;
  InitializeToZeroSingle(&output->sin6_addr);
  ReinterpretCopySingle(&output->sin6_addr, &input->klinux_sin6_port);
}
