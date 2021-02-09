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

#include <stdint.h>
#include <sys/socket.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint16_t in_port_t;

uint32_t htonl(uint32_t hostlong);
uint16_t htons(uint16_t hostshort);
uint32_t ntohl(uint32_t netlong);
uint16_t ntohs(uint16_t netshort);

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
  {{                                                   \
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 } \
  }}
#define IN6ADDR_LOOPBACK_INIT                          \
  {{                                                   \
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } \
  }}

// Macros that test for special IPv6 addresses.
// https://www.iana.org/assignments/ipv6-address-space/ipv6-address-space.xhtml
// https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml
// https://www.iana.org/assignments/ipv6-multicast-addresses/ipv6-multicast-addresses.xhtml
#define __IN6_ADDR_CAST_8(a) (((const struct in6_addr*)(a))->s6_addr)
#define __IN6_ADDR_CAST_16(a) (((const struct in6_addr*)(a))->s6_addr16)
#define __IN6_ADDR_CAST_32(a) (((const struct in6_addr*)(a))->s6_addr32)
#define IN6_IS_ADDR_UNSPECIFIED(a)             \
  ((__IN6_ADDR_CAST_32(a)[0] == 0x00000000) && \
   (__IN6_ADDR_CAST_32(a)[1] == 0x00000000) && \
   (__IN6_ADDR_CAST_32(a)[2] == 0x00000000) && \
   (__IN6_ADDR_CAST_32(a)[3] == 0x00000000))
#define IN6_IS_ADDR_LOOPBACK(a)                \
  ((__IN6_ADDR_CAST_32(a)[0] == 0x00000000) && \
   (__IN6_ADDR_CAST_32(a)[1] == 0x00000000) && \
   (__IN6_ADDR_CAST_32(a)[2] == 0x00000000) && \
   (__IN6_ADDR_CAST_16(a)[6] == 0x0000) &&     \
   (__IN6_ADDR_CAST_8(a)[14] == 0x00) &&       \
   (__IN6_ADDR_CAST_8(a)[15] == 0x01))
#define IN6_IS_ADDR_MULTICAST(a) \
  (__IN6_ADDR_CAST_8(a)[0] == 0xff)
#define IN6_IS_ADDR_LINKLOCAL(a)        \
  ((__IN6_ADDR_CAST_8(a)[0] == 0xfe) && \
   ((__IN6_ADDR_CAST_8(a)[1] & 0xc0) == 0x80))
#define IN6_IS_ADDR_SITELOCAL(a)        \
  ((__IN6_ADDR_CAST_8(a)[0] == 0xfe) && \
   ((__IN6_ADDR_CAST_8(a)[1] & 0xc0) == 0xc0))
#define IN6_IS_ADDR_V4MAPPED(a)                \
  ((__IN6_ADDR_CAST_32(a)[0] == 0x00000000) && \
   (__IN6_ADDR_CAST_32(a)[1] == 0x00000000) && \
   (__IN6_ADDR_CAST_16(a)[4] == 0x0000) &&     \
   (__IN6_ADDR_CAST_16(a)[5] == 0xffff))
#define IN6_IS_ADDR_V4COMPAT(a)                \
  ((__IN6_ADDR_CAST_32(a)[0] == 0x00000000) && \
   (__IN6_ADDR_CAST_32(a)[1] == 0x00000000) && \
   (__IN6_ADDR_CAST_32(a)[2] == 0x00000000) && \
   !IN6_IS_ADDR_UNSPECIFIED(a) &&              \
   !IN6_IS_ADDR_LOOPBACK(a))
#define IN6_IS_ADDR_MC_NODELOCAL(a) \
  (IN6_IS_ADDR_MULTICAST(a) &&      \
   ((__IN6_ADDR_CAST_8(a)[1] & 0x0f) == 0x01))
#define IN6_IS_ADDR_MC_LINKLOCAL(a) \
  (IN6_IS_ADDR_MULTICAST(a) &&      \
   ((__IN6_ADDR_CAST_8(a)[1] & 0x0f) == 0x02))
#define IN6_IS_ADDR_MC_SITELOCAL(a) \
  (IN6_IS_ADDR_MULTICAST(a) &&      \
   ((__IN6_ADDR_CAST_8(a)[1] & 0x0f) == 0x05))
#define IN6_IS_ADDR_MC_ORGLOCAL(a) \
  (IN6_IS_ADDR_MULTICAST(a) &&     \
   ((__IN6_ADDR_CAST_8(a)[1] & 0x0f) == 0x08))
#define IN6_IS_ADDR_MC_GLOBAL(a) \
  (IN6_IS_ADDR_MULTICAST(a) &&   \
   ((__IN6_ADDR_CAST_8(a)[1] & 0x0f) == 0x0e))

/* Standard well-known IP protocols.  */
#define IPPROTO_IP 0         // Base protocol for TCP.
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
#define IPPROTO_ICMPV6 58    // ICMPv6.
#define IPPROTO_MTP 92       // Multicast Transport Protocol.
#define IPPROTO_BEETPH 94    // IP option pseudo header for BEET.
#define IPPROTO_ENCAP 98     // Encapsulation Header.
#define IPPROTO_PIM 103      // Protocol Independent Multicast.
#define IPPROTO_COMP 108     // Compression Header Protocol.
#define IPPROTO_SCTP 132     // Stream Control Transmission Protocol.
#define IPPROTO_UDPLITE 136  // UDP-Lite protocol.
#define IPPROTO_RAW 255      // Raw IP packets.
#define IPPROTO_MAX

#define IPV6_V6ONLY 26

#define INET_ADDRSTRLEN 16
#define INET6_ADDRSTRLEN 46

struct in_pktinfo {
  int ipi_ifindex;
  struct in_addr ipi_spec_dst;
  struct in_addr ipi_addr;
};

/* IPv6 packet information.  */
struct in6_pktinfo {
  struct in6_addr ipi6_addr; /* src/dst IPv6 address */
  unsigned int ipi6_ifindex; /* send/recv interface index */
};

/* IPv6 MTU information.  */
struct ip6_mtuinfo {
  struct sockaddr_in6 ip6m_addr; /* dst address including zone ID */
  uint32_t ip6m_mtu;             /* path MTU in host byte order */
};

#define IN_CLASSA(a) ((((in_addr_t)(a)) & 0x80000000) == 0)
#define IN_CLASSA_NET 0xff000000
#define IN_CLASSB(a) ((((in_addr_t)(a)) & 0xc0000000) == 0x80000000)
#define IN_CLASSB_NET 0xffff0000
#define IN_CLASSC(a) ((((in_addr_t)(a)) & 0xe0000000) == 0xc0000000)
#define IN_CLASSC_NET 0xffffff00
#define IN_CLASSD(a) ((((in_addr_t)(a)) & 0xf0000000) == 0xe0000000)

#define INADDR_ANY UINT32_C(0x00000000)  // Inet 0.0.0.0
#define INADDR_NONE UINT32_C(0xffffffff)  // Inet 255.255.255.255

// Address to loopback in software to local host.
#ifndef INADDR_LOOPBACK
#define INADDR_LOOPBACK ((in_addr_t)0x7f000001)  // Inet 127.0.0.1.
#endif

#define IP_TOS 1
#define IP_TTL 2
#define IP_HDRINCL 3
#define IP_OPTIONS 4
#define IP_ROUTER_ALERT 5 /* bool */
#define IP_PKTINFO 8      /* bool */
#define IP_PKTOPTIONS 9
#define IP_PMTUDISC 10     /* obsolete name? */
#define IP_MTU_DISCOVER 10 /* int; see below */
#define IP_RECVERR 11      /* bool */
#define IP_RECVTTL 12      /* bool */
#define IP_RECVTOS 13      /* bool */
#define IP_MTU 14          /* int */
#define IP_FREEBIND 15
#define IP_IPSEC_POLICY 16
#define IP_XFRM_POLICY 17
#define IP_PASSSEC 18
#define IP_TRANSPARENT 19

#define IP_MULTICAST_IF 32
#define IP_MULTICAST_TTL 33
#define IP_MULTICAST_LOOP 34
#define IP_ADD_MEMBERSHIP 35
#define IP_DROP_MEMBERSHIP 36
#define IP_UNBLOCK_SOURCE 37
#define IP_BLOCK_SOURCE 38
#define IP_ADD_SOURCE_MEMBERSHIP 39
#define IP_DROP_SOURCE_MEMBERSHIP 40
#define IP_MSFILTER 41
#define MCAST_JOIN_GROUP 42
#define MCAST_BLOCK_SOURCE 43
#define MCAST_UNBLOCK_SOURCE 44
#define MCAST_LEAVE_GROUP 45
#define MCAST_JOIN_SOURCE_GROUP 46
#define MCAST_LEAVE_SOURCE_GROUP 47
#define MCAST_MSFILTER 48
#define IP_MULTICAST_ALL 49
#define IP_UNICAST_IF 50

#define IPV6_RECVPKTINFO 49
#define IPV6_PKTINFO 50
#define IPV6_RECVHOPLIMIT 51
#define IPV6_HOPLIMIT 52
#define IPV6_RECVHOPOPTS 53
#define IPV6_HOPOPTS 54
#define IPV6_RTHDRDSTOPTS 55
#define IPV6_RECVRTHDR 56
#define IPV6_RTHDR 57
#define IPV6_RECVDSTOPTS 58
#define IPV6_DSTOPTS 59
#define IPV6_RECVPATHMTU 60
#define IPV6_PATHMTU 61
#define IPV6_DONTFRAG 62

struct ip_mreq {
  struct in_addr imr_multiaddr; /* IP multicast address of group */
  struct in_addr imr_interface; /* local IP address of interface */
};

struct ip_mreqn {
  struct in_addr imr_multiaddr; /* IP multicast address of group */
  struct in_addr imr_address;   /* local IP address of interface */
  int imr_ifindex;              /* Interface index */
};

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // ASYLO_PLATFORM_POSIX_INCLUDE_NETINET_IN_H_
