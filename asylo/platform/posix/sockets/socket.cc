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
#include <stdlib.h>
#include <sys/socket.h>

#include <cstring>
#include <string>

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
  if (!cp || *cp == '\0' || !inp) {
    return 0;
  }

  uint64_t tokens[4];
  int accepted = 0;
  const char *ci = cp;
  do {
    // Parse a number.

    // Valid prefixes include "0x" for hex and "0", but not "+" or "-", so
    // expect the next character is a digit.
    if (!isdigit(*ci)) {
      return 0;
    }

    char *next;
    tokens[accepted] = strtoll(ci, &next, 0);
    if (tokens[accepted] > UINT32_MAX) return 0;

    // Fail if we could not parse a number.
    if (ci == next) {
      return 0;
    }
    ci = next;
    accepted++;

    // If we aren't at the end of the string, advance past the next '.' or fail.
    if (*ci) {
      if (*ci == '.') {
        ci++;
      } else {
        return 0;
      }
    }

    // If we have accepted four tokens and we are not at the end of the string,
    // fail.
    if (accepted == 4 && *ci) {
      return 0;
    }
  } while (*ci);

  if (accepted == 4) {
    // Case 1: "a.b.c.d" where each of the four parts is a byte.
    if (inp) {
      inp->s_addr = 0;
    }
    for (int i = 3; i >= 0; i--) {
      if (tokens[i] > UINT8_MAX) {
        return 0;
      }
      if (inp) {
        inp->s_addr = inp->s_addr << 8 | tokens[i];
      }
    }
  } else if (accepted == 3) {
    // Case 2: "a.b.c" where a and b are 8-bit values and c is 16-bits.
    if (tokens[0] > UINT8_MAX || tokens[1] > UINT8_MAX ||
        tokens[2] > UINT16_MAX) {
      return 0;
    }

    if (inp) {
      inp->s_addr = htonl(tokens[0] << 24 | tokens[1] << 16 | tokens[2]);
    }
  } else if (accepted == 2) {
    // Case 3: "a.b" where a is 8-bit and b is 24-bits.
    if (tokens[0] > UINT8_MAX || tokens[1] > 0x00FFFFFF) {
      return 0;
    }
    if (inp) {
      inp->s_addr = htonl(tokens[0] << 24 | tokens[1]);
    }
  } else if (accepted == 1) {
    // Case 4: "a" where a is a 32-bits value.
    if (inp) {
      inp->s_addr = htonl(tokens[0]);
    }
  } else {
    return 0;
  }
  return 1;
}

ssize_t recvfrom(int socket, void *buffer, size_t length, int flags,
                 struct sockaddr *address, socklen_t *address_len) {
  return IOManager::GetInstance().RecvFrom(socket, buffer, length, flags,
                                           address, address_len);
}

int socketpair(int domain, int type, int protocol, int sv[2]) { abort(); }

}  // extern "C"
