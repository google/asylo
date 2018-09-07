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
#include <arpa/inet.h>
#include <sys/socket.h>

#include <stdlib.h>
#include <cstring>
#include <string>

#include "asylo/platform/arch/include/trusted/host_calls.h"
#include "asylo/platform/common/memory.h"
#include "asylo/platform/posix/io/io_manager.h"

using asylo::io::IOManager;

extern "C" {

int setsockopt(int sockfd, int level, int option_name, const void *option_value,
               socklen_t option_len) {
  return IOManager::GetInstance().SetSockOpt(sockfd, level, option_name,
                                             option_value, option_len);
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
  return IOManager::GetInstance().Connect(sockfd, addr, addrlen);
}

int shutdown(int sockfd, int how) {
  return IOManager::GetInstance().Shutdown(sockfd, how);
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
  return IOManager::GetInstance().Send(sockfd, buf, len, flags);
}

int socket(int domain, int type, int protocol) {
  return IOManager::GetInstance().Socket(domain, type, protocol);
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags) {
  return recvfrom(sockfd, buf, len, flags, nullptr, nullptr);
}

int getsockopt(int sockfd, int level, int optname, void *optval,
               socklen_t *optlen) {
  return IOManager::GetInstance().GetSockOpt(sockfd, level, optname, optval,
                                             optlen);
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
  return IOManager::GetInstance().Accept(sockfd, addr, addrlen);
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
  return IOManager::GetInstance().Bind(sockfd, addr, addrlen);
}

int listen(int sockfd, int backlog) {
  return IOManager::GetInstance().Listen(sockfd, backlog);
}

ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags) {
  return IOManager::GetInstance().SendMsg(sockfd, msg, flags);
}

ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags) {
  return IOManager::GetInstance().RecvMsg(sockfd, msg, flags);
}

int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
  return IOManager::GetInstance().GetSockName(sockfd, addr, addrlen);
}

int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
  return IOManager::GetInstance().GetPeerName(sockfd, addr, addrlen);
}

in_addr_t inet_addr(const char *cp) {
  struct in_addr addr;
  int ret = inet_aton(cp, &addr);
  if (ret == 0) {
    return INADDR_NONE;
  }
  return addr.s_addr;
}

int inet_aton(const char *cp, struct in_addr *inp) {
  if (!cp || !inp) {
    return 0;
  }
  char *cp_copy = strdup(cp);
  asylo::MallocUniquePtr<char[]> cp_copy_ptr(cp_copy);
  char *save_ptr = nullptr;
  uint8_t result[sizeof(uint32_t)];
  char *token1 = strtok_r(cp_copy, ".", &save_ptr);
  if (token1 == nullptr) {
    // Upon failure, inet_aton simply returns 0 and does not set errno.
    return 0;
  }
  char *token2 = strtok_r(nullptr, ".", &save_ptr);
  // Case: "a" (one chunk)
  if (token2 == nullptr) {
    uint64_t addr = strtoull(token1, nullptr, 0);
    if (addr > 0xffffffff) {
      // Upon failure, inet_aton simply returns 0 and does not set errno.
      return 0;
    }
    inp->s_addr = htonl(static_cast<in_addr_t>(addr));
    return 1;
  }
  char *token3 = strtok_r(nullptr, ".", &save_ptr);
  // Case: "a.b"
  if (token3 == nullptr) {
    uint64_t byte1 = strtoull(token1, nullptr, 0);
    uint64_t rest = strtoull(token2, nullptr, 0);
    if (byte1 > 0xff || rest > 0xffffff) {
      // Upon failure, inet_aton simply returns 0 and does not set errno.
      return 0;
    }
    uint32_t rest_int = htonl(static_cast<uint32_t>(rest));
    uint8_t *rest_arr = reinterpret_cast<uint8_t *>(&rest_int);
    result[0] = static_cast<uint8_t>(byte1);
    result[1] = rest_arr[1];
    result[2] = rest_arr[2];
    result[3] = rest_arr[3];
    inp->s_addr = *reinterpret_cast<in_addr_t *>(&result);
    return 1;
  }
  char *token4 = strtok_r(nullptr, ".", &save_ptr);
  // Case: "a.b.c"
  if (token4 == nullptr) {
    uint64_t byte1 = strtoull(token1, nullptr, 0);
    uint64_t byte2 = strtoull(token2, nullptr, 0);
    uint64_t rest = strtoull(token3, nullptr, 0);
    if (byte1 > 0xff || byte2 > 0xff || rest > 0xffff) {
      // Upon failure, inet_aton simply returns 0 and does not set errno.
      return 0;
    }
    uint16_t rest_int = htons(static_cast<uint16_t>(rest));
    uint8_t *rest_arr = reinterpret_cast<uint8_t *>(&rest_int);
    result[0] = static_cast<uint8_t>(byte1);
    result[1] = static_cast<uint8_t>(byte2);
    result[2] = rest_arr[0];
    result[3] = rest_arr[1];
    inp->s_addr = *reinterpret_cast<in_addr_t *>(&result);
    return 1;
  }
  char *token5 = strtok_r(nullptr, ".", &save_ptr);
  // Case: too many "." => error.
  if (token5 != nullptr) {
    // Upon failure, inet_aton simply returns 0 and does not set errno.
    return 0;
  }
  // Case: "a.b.c.d"
  uint64_t byte1 = strtoull(token1, nullptr, 0);
  uint64_t byte2 = strtoull(token2, nullptr, 0);
  uint64_t byte3 = strtoull(token3, nullptr, 0);
  uint64_t byte4 = strtoull(token4, nullptr, 0);
  if (byte1 > 0xff || byte2 > 0xff || byte3 > 0xff || byte4 > 0xff) {
    // Upon failure, inet_aton simply returns 0 and does not set errno.
    return 0;
  }
  result[0] = static_cast<uint8_t>(byte1);
  result[1] = static_cast<uint8_t>(byte2);
  result[2] = static_cast<uint8_t>(byte3);
  result[3] = static_cast<uint8_t>(byte4);
  inp->s_addr = *reinterpret_cast<in_addr_t *>(&result);
  return 1;
}

ssize_t recvfrom(int socket, void *buffer, size_t length, int flags,
                 struct sockaddr *address, socklen_t *address_len) {
  return IOManager::GetInstance().RecvFrom(socket, buffer, length, flags,
                                           address, address_len);
}

struct servent *getservbyport(int port, const char *proto) {
  abort();
}

int socketpair(int domain, int type, int protocol, int sv[2]) {
  abort();
}

}  // extern "C"
