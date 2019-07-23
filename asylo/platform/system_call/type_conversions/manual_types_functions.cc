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

#include "asylo/platform/system_call/type_conversions/generated_types_functions.h"

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

void FromKernelStat(const struct kernel_stat *from, struct stat *to) {
  if (!from || !to) return;
  to->st_atime = from->kernel_st_atime;
  to->st_blksize = from->kernel_st_blksize;
  to->st_blocks = from->kernel_st_blocks;
  to->st_mtime = from->kernel_st_mtime;
  to->st_dev = from->kernel_st_dev;
  to->st_gid = from->kernel_st_gid;
  to->st_ino = from->kernel_st_ino;
  to->st_mode = from->kernel_st_mode;
  to->st_ctime = from->kernel_st_ctime;
  to->st_nlink = from->kernel_st_nlink;
  to->st_rdev = from->kernel_st_rdev;
  to->st_size = from->kernel_st_size;
  to->st_uid = from->kernel_st_uid;
}

void ToKernelStat(const struct stat *from, struct kernel_stat *to) {
  if (!from || !to) return;
  to->kernel_st_atime = from->st_atime;
  to->kernel_st_blksize = from->st_blksize;
  to->kernel_st_blocks = from->st_blocks;
  to->kernel_st_mtime = from->st_mtime;
  to->kernel_st_dev = from->st_dev;
  to->kernel_st_gid = from->st_gid;
  to->kernel_st_ino = from->st_ino;
  to->kernel_st_mode = from->st_mode;
  to->kernel_st_ctime = from->st_ctime;
  to->kernel_st_nlink = from->st_nlink;
  to->kernel_st_rdev = from->st_rdev;
  to->kernel_st_size = from->st_size;
  to->kernel_st_uid = from->st_uid;
}
