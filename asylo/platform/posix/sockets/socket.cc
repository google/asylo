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

#include <sys/socket.h>

#include <stdlib.h>

#include "asylo/platform/arch/include/trusted/host_calls.h"
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

ssize_t recv(int sockfd, void *buf, size_t len, int flags) { abort(); }

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

in_addr_t inet_addr(const char *cp) { abort(); }

ssize_t recvfrom(int socket, void *buffer, size_t length, int flags,
                 struct sockaddr *address, socklen_t *address_len) {
  abort();
}

struct servent *getservbyport(int port, const char *proto) {
  abort();
}

}  // extern "C"
