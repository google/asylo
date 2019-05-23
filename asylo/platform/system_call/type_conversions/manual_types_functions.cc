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
