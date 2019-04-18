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

int TokLinuxSocketType(int sock_type) {
  int kLinux_sock_type = 0;

  if (sock_type & SOCK_NONBLOCK) {
    kLinux_sock_type |= kLinux_SOCK_NONBLOCK;
    sock_type &= ~SOCK_NONBLOCK;
  }

  if (sock_type & SOCK_CLOEXEC) {
    kLinux_sock_type |= kLinux_SOCK_CLOEXEC;
    sock_type &= ~SOCK_CLOEXEC;
  }

  if (!sock_type) {  // Only SOCK_CLOEXEC or SOCK_NONBLOCK are present.
    return kLinux_sock_type;
  }

  switch (sock_type) {
    case SOCK_STREAM:
      kLinux_sock_type |= kLinux_SOCK_STREAM;
      break;
    case SOCK_DGRAM:
      kLinux_sock_type |= kLinux_SOCK_DGRAM;
      break;
    case SOCK_SEQPACKET:
      kLinux_sock_type |= kLinux_SOCK_SEQPACKET;
      break;
    case SOCK_RAW:
      kLinux_sock_type |= kLinux_SOCK_RAW;
      break;
    case SOCK_RDM:
      kLinux_sock_type |= kLinux_SOCK_RDM;
      break;
    case SOCK_PACKET:
      kLinux_sock_type |= kLinux_SOCK_PACKET;
      break;
    default:
      return -1;  // Unsupported
  }

  return kLinux_sock_type;
}

int FromkLinuxSocketType(int kLinux_sock_type) {
  int sock_type = 0;

  if (kLinux_sock_type & kLinux_SOCK_NONBLOCK) {
    sock_type |= SOCK_NONBLOCK;
    kLinux_sock_type &= ~kLinux_SOCK_NONBLOCK;
  }

  if (kLinux_sock_type & kLinux_SOCK_CLOEXEC) {
    sock_type |= SOCK_CLOEXEC;
    kLinux_sock_type &= ~kLinux_SOCK_CLOEXEC;
  }

  if (!kLinux_sock_type) {  // Only kLinux_SOCK_CLOEXEC or kLinux_SOCK_NONBLOCK
                            // are present.
    return sock_type;
  }

  switch (kLinux_sock_type) {
    case kLinux_SOCK_STREAM:
      sock_type |= SOCK_STREAM;
      break;
    case kLinux_SOCK_DGRAM:
      sock_type |= SOCK_DGRAM;
      break;
    case kLinux_SOCK_SEQPACKET:
      sock_type |= SOCK_SEQPACKET;
      break;
    case kLinux_SOCK_RAW:
      sock_type |= SOCK_RAW;
      break;
    case kLinux_SOCK_RDM:
      sock_type |= SOCK_RDM;
      break;
    case kLinux_SOCK_PACKET:
      sock_type |= SOCK_PACKET;
      break;
    default:
      return -1;  // Unsupported
  }

  return sock_type;
}

int TokLinuxOptionName(int level, int option_name) {
  if (level == IPPROTO_TCP) {
    return TokLinuxTcpOptionName(option_name);
  }
  if (level == IPPROTO_IPV6) {
    return TokLinuxIpV6OptionName(option_name);
  }
  if (level == SOL_SOCKET) {
    return TokLinuxSocketOptionName(option_name);
  }
  return -1;
}

int FromkLinuxOptionName(int level, int klinux_option_name) {
  if (level == IPPROTO_TCP) {
    return FromkLinuxTcpOptionName(klinux_option_name);
  }
  if (level == IPPROTO_IPV6) {
    return TokLinuxIpV6OptionName(klinux_option_name);
  }
  if (level == SOL_SOCKET) {
    return FromkLinuxSocketOptionName(klinux_option_name);
  }
  return -1;
}
