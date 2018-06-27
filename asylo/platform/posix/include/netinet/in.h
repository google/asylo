/*
 *
 * Copyright 2017 Asylo authors
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

#ifndef ASYLO_PLATFORM_POSIX_INCLUDE_NETINET_IN_H_
#define ASYLO_PLATFORM_POSIX_INCLUDE_NETINET_IN_H_

#include <arpa/inet.h>
#include <stdint.h>
#include <sys/socket.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint16_t in_port_t;

// Internet address.
typedef uint32_t in_addr_t;
struct in_addr {
  in_addr_t s_addr;
};

struct in6_addr {
  union {
    uint8_t s6_addr[16];
    uint16_t s6_addr16[8];
    uint32_t s6_addr32[4];
  };
};

struct sockaddr_in {
  sa_family_t sin_family;
  in_port_t sin_port;
  struct in_addr sin_addr;
  char sin_zero[8];
} __attribute__((packed));

struct sockaddr_in6 {
  sa_family_t sin6_family;
  in_port_t sin6_port;
  uint32_t sin6_flowinfo;
  struct in6_addr sin6_addr;
  uint32_t sin6_scope_id;
} __attribute__((packed));

// Global address variables to support IPv6
extern const struct in6_addr in6addr_any;       // Inet6 "::"
extern const struct in6_addr in6addr_loopback;  // Inet6 "::1"

#define IN6ADDR_ANY_INIT                               \
  {                                                    \
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 } \
  }
#define IN6ADDR_LOOPBACK_INIT                          \
  {                                                    \
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } \
  }

/* Standard well-defined IP protocols.  */
#define IPPROTO_IP 0         // Dummy protocol for TCP.
#define IPPROTO_ICMP 1       // Internet Control Message Protocol.
#define IPPROTO_IGMP 2       // Internet Group Management Protocol
#define IPPROTO_IPIP 4       // IPIP tunnels (older KA9Q tunnels use 94).
#define IPPROTO_TCP 6        // Transmission Control Protocol.
#define IPPROTO_EGP 8        // Exterior Gateway Protocol.
#define IPPROTO_PUP 12       // PUP protocol.
#define IPPROTO_UDP 17       // User Datagram Protocol.
#define IPPROTO_IDP 22       // XNS IDP protocol.
#define IPPROTO_TP 29        // SO Transport Protocol Class 4.
#define IPPROTO_DCCP 33      // Datagram Congestion Control Protocol.
#define IPPROTO_IPV6 41      // IPv6 header.
#define IPPROTO_RSVP 46      // Reservation Protocol.
#define IPPROTO_GRE 47       // General Routing Encapsulation.
#define IPPROTO_ESP 50       // encapsulating security payload.
#define IPPROTO_AH 51        // authentication header.
#define IPPROTO_MTP 92       // Multicast Transport Protocol.
#define IPPROTO_BEETPH 94    // IP option pseudo header for BEET.
#define IPPROTO_ENCAP 98     // Encapsulation Header.
#define IPPROTO_PIM 103      // Protocol Independent Multicast.
#define IPPROTO_COMP 108     // Compression Header Protocol.
#define IPPROTO_SCTP 132     // Stream Control Transmission Protocol.
#define IPPROTO_UDPLITE 136  // UDP-Lite protocol.
#define IPPROTO_RAW 255      // Raw IP packets.
#define IPPROTO_MAX

#define AI_PASSIVE 0x0001  // Socket address is intended for `bind'.

#define IPV6_V6ONLY 26

#define INET_ADDRSTRLEN 16
#define INET6_ADDRSTRLEN 46

#define IN_CLASSA(a) ((((in_addr_t)(a)) & 0x80000000) == 0)
#define IN_CLASSA_NET 0xff000000
#define IN_CLASSB(a) ((((in_addr_t)(a)) & 0xc0000000) == 0x80000000)
#define IN_CLASSB_NET 0xffff0000
#define IN_CLASSC(a) ((((in_addr_t)(a)) & 0xe0000000) == 0xc0000000)
#define IN_CLASSC_NET 0xffffff00
#define IN_CLASSD(a) ((((in_addr_t)(a)) & 0xf0000000) == 0xe0000000)

#define INADDR_ANY UINT32_C(0x00000000)  // Inet 0.0.0.0

// Address to loopback in software to local host.
#ifndef INADDR_LOOPBACK
#define INADDR_LOOPBACK ((in_addr_t)0x7f000001)  // Inet 127.0.0.1.
#endif

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // ASYLO_PLATFORM_POSIX_INCLUDE_NETINET_IN_H_
