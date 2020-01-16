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

#ifndef ASYLO_PLATFORM_POSIX_INCLUDE_NET_IF_H_
#define ASYLO_PLATFORM_POSIX_INCLUDE_NET_IF_H_

#ifdef __cplusplus
extern "C" {
#endif

// Macros from newlib/src/newlib/libc/sys/linux/include/net/if.h
// This is the subset of macros which Asylo supports.
#define IFF_UP 0x1           /* interface is up */
#define IFF_BROADCAST 0x2    /* broadcast address valid */
#define IFF_DEBUG 0x4        /* turn on debugging */
#define IFF_LOOPBACK 0x8     /* is a loopback net */
#define IFF_POINTOPOINT 0x10 /* interface is point-to-point link */
#define IFF_NOTRAILERS 0x20  /* avoid use of trailers */
#define IFF_RUNNING 0x40     /* resources allocated */
#define IFF_NOARP 0x80       /* no address resolution protocol */
#define IFF_PROMISC 0x100    /* receive all packets */
#define IFF_ALLMULTI 0x200   /* receive all multicast packets */
#define IFF_MULTICAST 0x400  /* supports multicast */

#define IF_NAMESIZE 16

unsigned int if_nametoindex(const char *ifname);
char *if_indextoname(unsigned int ifindex, char *ifname);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // ASYLO_PLATFORM_POSIX_INCLUDE_NET_IF_H_
