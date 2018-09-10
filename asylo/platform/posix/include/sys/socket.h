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

#ifndef ASYLO_PLATFORM_POSIX_INCLUDE_SYS_SOCKET_H_
#define ASYLO_PLATFORM_POSIX_INCLUDE_SYS_SOCKET_H_

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/uio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t __socklen_t;
typedef __socklen_t socklen_t;
typedef __sa_family_t sa_family_t;

struct sockaddr {
  sa_family_t sa_family;
  char sa_data[14];
} __attribute__((packed));

struct sockaddr_storage {
  sa_family_t ss_family;
  uint64_t __padding[4];
} __attribute__((packed));

typedef struct addrinfo {
  int ai_flags;
  int ai_family;
  int ai_socktype;
  int ai_protocol;
  socklen_t ai_addrlen;
  struct sockaddr *ai_addr;
  char *ai_canonname;
  struct addrinfo *ai_next;
} addrinfo;

struct msghdr {
  void *msg_name;
  socklen_t msg_namelen;
  struct iovec *msg_iov;
  size_t msg_iovlen;
  void *msg_control;
  socklen_t msg_controllen;
  int msg_flags;
};

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

void freeaddrinfo(struct addrinfo *res);

int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints, struct addrinfo **res);

int getsockopt(int sockfd, int level, int optname, void *optval,
               socklen_t *optlen);

int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen);

int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen);

int listen(int sockfd, int backlog);

ssize_t recv(int sockfd, void *buf, size_t len, int flags);

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
                 struct sockaddr *src_addr, socklen_t *addrlen);

// No implementation provided.
ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags);

ssize_t send(int sockfd, const void *buf, size_t len, int flags);
ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags);

int setsockopt(int socket, int level, int option_name, const void *option_value,
               socklen_t option_len);

// No implementation provided.
int shutdown(int sockfd, int how);

int socket(int domain, int type, int protocol);

// No implementation provided.
int socketpair(int domain, int type, int protocol, int sv[2]);

// For setsockopt(2)
#define SOL_SOCKET 1

#define SO_DEBUG 1
#define SO_REUSEADDR 2
#define SO_TYPE 3
#define SO_ERROR 4
#define SO_DONTROUTE 5
#define SO_BROADCAST 6
#define SO_SNDBUF 7
#define SO_RCVBUF 8
#define SO_KEEPALIVE 9
#define SO_OOBINLINE 10
#define SO_NO_CHECK 11
#define SO_PRIORITY 12
#define SO_LINGER 13
#define SO_BSDCOMPAT 14
#define SO_REUSEPORT 15
#define SO_RCVTIMEO 20
#define SO_SNDTIMEO 21
#define SO_SNDBUFFORCE 32
#define SO_RCVBUFFORCE 33

// Protocol families.
#define PF_UNSPEC 0       // Unspecified.
#define PF_LOCAL 1        // Local to host (pipes and file-domain).
#define PF_UNIX PF_LOCAL  // POSIX name for PF_LOCAL.
#define PF_FILE PF_LOCAL  // Another non-standard name for PF_LOCAL.
#define PF_INET 2         // IP protocol family.
#define PF_AX25 3         // Amateur Radio AX.25.
#define PF_IPX 4          // Novell Internet Protocol.
#define PF_APPLETALK 5    // Appletalk DDP.
#define PF_NETROM 6       // Amateur radio NetROM.
#define PF_BRIDGE 7       // Multiprotocol bridge.
#define PF_ATMPVC 8       // ATM PVCs.
#define PF_X25 9          // Reserved for X.25 project.
#define PF_INET6 10       // IP version 6.
#define PF_ROSE 11        // Amateur Radio X.25 PLP.
#define PF_DECnet 12      // Reserved for DECnet project.
#define PF_NETBEUI 13     // Reserved for 802.2LLC project.
#define PF_SECURITY 14    // Security callback pseudo AF.
#define PF_KEY 15         // PF_KEY key management API.
#define PF_NETLINK 16
#define PF_ROUTE PF_NETLINK  // Alias to emulate 4.4BSD.
#define PF_PACKET 17         // Packet family.
#define PF_ASH 18            // Ash.
#define PF_ECONET 19         // Acorn Econet.
#define PF_ATMSVC 20         // ATM SVCs.
#define PF_RDS 21            // RDS sockets.
#define PF_SNA 22            // Linux SNA Projec
#define PF_IRDA 23           // IRDA sockets.
#define PF_PPPOX 24          // PPPoX sockets.
#define PF_WANPIPE 25        // Wanpipe API sockets.
#define PF_LLC 26            // Linux LLC.
#define PF_CAN 29            // Controller Area Network.
#define PF_TIPC 30           // TIPC sockets.
#define PF_BLUETOOTH 31      // Bluetooth sockets.
#define PF_IUCV 32           // IUCV sockets.
#define PF_RXRPC 33          // RxRPC sockets.
#define PF_ISDN 34           // mISDN sockets.
#define PF_PHONET 35         // Phonet sockets.
#define PF_IEEE802154 36     // IEEE 802.15.4 sockets.
#define PF_CAIF 37           // CAIF sockets.
#define PF_ALG 38            // Algorithm sockets.
#define PF_NFC 39            // NFC sockets.
#define PF_VSOCK 40          // vSockets.
#define PF_MAX 41            // For now..

// Address families.
#define AF_UNSPEC PF_UNSPEC
#define AF_LOCAL PF_LOCAL
#define AF_UNIX PF_UNIX
#define AF_FILE PF_FILE
#define AF_INET PF_INET
#define AF_AX25 PF_AX25
#define AF_IPX PF_IPX
#define AF_APPLETALK PF_APPLETALK
#define AF_NETROM PF_NETROM
#define AF_BRIDGE PF_BRIDGE
#define AF_ATMPVC PF_ATMPVC
#define AF_X25 PF_X25
#define AF_INET6 PF_INET6
#define AF_ROSE PF_ROSE
#define AF_DECnet PF_DECnet
#define AF_NETBEUI PF_NETBEUI
#define AF_SECURITY PF_SECURITY
#define AF_KEY PF_KEY
#define AF_NETLINK PF_NETLINK
#define AF_ROUTE PF_ROUTE
#define AF_PACKET PF_PACKET
#define AF_ASH PF_ASH
#define AF_ECONET PF_ECONET
#define AF_ATMSVC PF_ATMSVC
#define AF_RDS PF_RDS
#define AF_SNA PF_SNA
#define AF_IRDA PF_IRDA
#define AF_PPPOX PF_PPPOX
#define AF_WANPIPE PF_WANPIPE
#define AF_LLC PF_LLC
#define AF_CAN PF_CAN
#define AF_TIPC PF_TIPC
#define AF_BLUETOOTH PF_BLUETOOTH
#define AF_IUCV PF_IUCV
#define AF_RXRPC PF_RXRPC
#define AF_ISDN PF_ISDN
#define AF_PHONET PF_PHONET
#define AF_IEEE802154 PF_IEEE802154
#define AF_CAIF PF_CAIF
#define AF_ALG PF_ALG
#define AF_NFC PF_NFC
#define AF_VSOCK PF_VSOCK
#define AF_MAX PF_MAX

#define SOL_RAW 255
#define SOL_DECNET 261
#define SOL_X25 262
#define SOL_PACKET 263
#define SOL_ATM 264  // ATM layer (cell level).
#define SOL_AAL 265  // ATM Adaption Layer (packet level).
#define SOL_IRDA 266

// Bits in the flags argument to send and recv methods.
enum {
  MSG_OOB = 0x01,
#define MSG_OOB MSG_OOB
  MSG_PEEK = 0x02,
#define MSG_PEEK MSG_PEEK
  MSG_DONTROUTE = 0x04,
#define MSG_DONTROUTE MSG_DONTROUTE
  MSG_CTRUNC = 0x08,
#define MSG_CTRUNC MSG_CTRUNC
  MSG_PROXY = 0x10,
#define MSG_PROXY MSG_PROXY
  MSG_TRUNC = 0x20,
#define MSG_TRUNC MSG_TRUNC
  MSG_DONTWAIT = 0x40,
#define MSG_DONTWAIT MSG_DONTWAIT
  MSG_EOR = 0x80,
#define MSG_EOR MSG_EOR
  MSG_WAITALL = 0x100,
#define MSG_WAITALL MSG_WAITALL
  MSG_FIN = 0x200,
#define MSG_FIN MSG_FIN
  MSG_SYN = 0x400,
#define MSG_SYN MSG_SYN
  MSG_CONFIRM = 0x800,
#define MSG_CONFIRM MSG_CONFIRM
  MSG_RST = 0x1000,
#define MSG_RST MSG_RST
  MSG_ERRQUEUE = 0x2000,
#define MSG_ERRQUEUE MSG_ERRQUEUE
  MSG_NOSIGNAL = 0x4000,
#define MSG_NOSIGNAL MSG_NOSIGNAL
  MSG_MORE = 0x8000,
#define MSG_MORE MSG_MORE
  MSG_WAITFORONE = 0x10000,
#define MSG_WAITFORONE MSG_WAITFORONE
  MSG_FASTOPEN = 0x20000000,
#define MSG_FASTOPEN MSG_FASTOPEN
  MSG_CMSG_CLOEXEC = 0x40000000,
#define MSG_CMSG_CLOEXEC MSG_CMSG_CLOEXEC
};

// Maximum queue length specifiable by listen.
#define SOMAXCONN 128

#define SHUT_RD 0
#define SHUT_WR 1
#define SHUT_RDWR 2

// Types of sockets.
// Sequenced, reliable, connection-based byte streams.
#define SOCK_STREAM 1
// Connectionless, unreliable datagrams of fixed maximum length.
#define SOCK_DGRAM 2
// Raw protocol interface.
#define SOCK_RAW 3
// Reliably-delivered messages.
#define SOCK_RDM 4
// Sequenced, reliable, connection-based, datagrams of fixed maximum length.
#define SOCK_SEQPACKET 5
// Datagram Congestion Control Protocol.
#define SOCK_DCCP 6
// Linux specific way of getting packets at the dev level.  For writing rarp and
// other similar things on the user level
#define SOCK_PACKET 10

// Flags to be ORed into the type parameter of socket and socketpair and used
// for the flags parameter of paccept.

// Atomically set close-on-exec flag for the new descriptor(s).
#define SOCK_CLOEXEC 02000000
// Atomically mark descriptor(s) as non-blocking.
#define SOCK_NONBLOCK 00004000

#define SOL_SOCKET 1
#define SO_REUSEADDR 2

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // ASYLO_PLATFORM_POSIX_INCLUDE_SYS_SOCKET_H_
