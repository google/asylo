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

#ifndef ASYLO_PLATFORM_POSIX_INCLUDE_IFADDRS_H_
#define ASYLO_PLATFORM_POSIX_INCLUDE_IFADDRS_H_

#include <sys/socket.h>

#ifdef __cplusplus
extern "C" {
#endif

struct ifaddrs {
  struct ifaddrs *ifa_next;     /* Next item in list */
  char *ifa_name;               /* Name of interface */
  unsigned int ifa_flags;       /* Flags from SIOCGIFFLAGS */
  struct sockaddr *ifa_addr;    /* Address of interface */
  struct sockaddr *ifa_netmask; /* Netmask of interface */
  union {
    struct sockaddr *ifu_broadaddr; /* Broadcast address of interface */
    struct sockaddr *ifu_dstaddr;   /* Point-to-point destination address */
  } ifa_ifu;
#define ifa_broadaddr ifa_ifu.ifu_broadaddr
#define ifa_dstaddr ifa_ifu.ifu_dstaddr
  void *ifa_data; /* Address-specific data */
};

int getifaddrs(struct ifaddrs **ifap);

void freeifaddrs(struct ifaddrs *ifa);

#ifdef __cplusplus
}
#endif

#endif  // ASYLO_PLATFORM_POSIX_INCLUDE_IFADDRS_H_
