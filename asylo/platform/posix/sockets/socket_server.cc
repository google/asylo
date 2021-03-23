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

#include "asylo/platform/posix/sockets/socket_server.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "absl/status/status.h"
#include "asylo/util/logging.h"
#include "asylo/util/posix_errors.h"

namespace asylo {
namespace {

#ifdef __ASYLO__
constexpr const char kLogOrigin[] = "WITHIN ENCLAVE: ";
#else
constexpr const char kLogOrigin[] = "OUTSIDE ENCLAVE: ";
#endif

constexpr int kEnableAddrReuse = 1;

int MakeSockaddrReusable(int fd) {
  int addr_reuse = kEnableAddrReuse;
  return setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &addr_reuse,
                    sizeof(addr_reuse));
}

}  // namespace

SocketServer::SocketServer() : connection_fd_(-1) {}

Status SocketServer::Read(void *buf, size_t read_len) {
  return sock_transmit_.Read(connection_fd_, buf, read_len);
}

Status SocketServer::Write(const void *buf, size_t write_len) {
  return sock_transmit_.Write(connection_fd_, buf, write_len);
}

Status SocketServer::RecvMsg(struct msghdr *msg, int flags) {
  return sock_transmit_.RecvMsg(connection_fd_, msg, flags);
}

Status SocketServer::SendMsg(const struct msghdr *msg, int flags) {
  return sock_transmit_.SendMsg(connection_fd_, msg, flags);
}

Status SocketServer::RecvFrom(void *buffer, size_t length, int flags,
                              struct sockaddr *address,
                              socklen_t *address_len) {
  return sock_transmit_.RecvFrom(connection_fd_, buffer, length, flags, address,
                                 address_len);
}

Status SocketServer::ServerSetup(int server_port) {
  int fd = socket(AF_INET6, SOCK_STREAM, 0);
  if (fd < 0) {
    LOG(ERROR) << kLogOrigin << "server socket error";
    return LastPosixError("socket error");
  }

  socket_fd_.reset(fd);

  if (MakeSockaddrReusable(fd)) {
    LOG(ERROR) << kLogOrigin << "server setsockopt error";
    return LastPosixError("setsockopt error");
  }

  struct sockaddr_in6 serv_addr;
  memset(&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin6_family = AF_INET6;
  serv_addr.sin6_flowinfo = 0;
  serv_addr.sin6_addr = in6addr_any;
  serv_addr.sin6_port = htons(server_port);

  Status status = ServerConnection(
      fd, reinterpret_cast<struct sockaddr *>(&serv_addr), sizeof(serv_addr));
  return status;
}

Status SocketServer::ServerSetup(const std::string &socket_name,
                                 bool use_path_len) {
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) {
    LOG(ERROR) << kLogOrigin << "server socket error";
    return LastPosixError("socket error");
  }

  socket_fd_.reset(fd);

  struct sockaddr_un serv_addr;
  memset(&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sun_family = AF_UNIX;
  strncpy(serv_addr.sun_path, socket_name.c_str(),
          sizeof(serv_addr.sun_path) - 1);
  if (use_path_len) {
    return ServerConnection(
        fd, reinterpret_cast<struct sockaddr *>(&serv_addr),
        sizeof(serv_addr.sun_family) + strlen(serv_addr.sun_path) + 1);
  } else {
    return ServerConnection(fd, reinterpret_cast<struct sockaddr *>(&serv_addr),
                            sizeof(serv_addr));
  }
}

Status SocketServer::ServerAccept() {
  connection_fd_ = accept(socket_fd_.get(), nullptr, nullptr);
  if (connection_fd_ < 0) {
    LOG(ERROR) << kLogOrigin << "server accept error";
    return LastPosixError("accept error");
  }
  return absl::OkStatus();
}

Status SocketServer::ServerRoundtripTransmit(int buf_len, int round_trip) {
  Status status = absl::OkStatus();
  std::unique_ptr<char[]> transmit_buf(new char[buf_len]);
  char *buf = transmit_buf.get();

  // In all roundtrips, the server keeps writing and reading garbage data.
  // It is intentional here because in our perf test what is stored in buf
  // does not matter.
  while (round_trip--) {
    if (!(status = Write(buf, buf_len)).ok()) {
      break;
    }
    if (!(status = Read(buf, buf_len)).ok()) {
      break;
    }
  }
  return status;
}

int SocketServer::GetPort() {
  sockaddr_in6 serv_addr6;
  sockaddr *serv_addr = reinterpret_cast<sockaddr *>(&serv_addr6);
  socklen_t serv_addr_size = sizeof(sockaddr_in6);
  if (getsockname(socket_fd_.get(), serv_addr, &serv_addr_size) != 0) {
    LOG(ERROR) << kLogOrigin << "getsockname error: " << strerror(errno);
    return -1;
  }

  // If called on a domain socket, there is no port.
  if (serv_addr->sa_family != AF_INET6) {
    LOG(ERROR) << kLogOrigin << "getsockname not IPv6";
    return -1;
  }

  return ntohs(serv_addr6.sin6_port);
}

void SocketServer::LogServerIOStats() {
  LOG(INFO) << kLogOrigin << "server made " << sock_transmit_.GetWrite()
            << " calls to write";
  LOG(INFO) << kLogOrigin << "server made " << sock_transmit_.GetRead()
            << " calls to read";
}

Status SocketServer::ServerConnection(int fd, struct sockaddr *serv_addr,
                                      socklen_t addrlen) {
  if (bind(fd, serv_addr, addrlen)) {
    LOG(ERROR) << kLogOrigin << "server bind error";
    return LastPosixError("bind error");
  }
  if (listen(fd, 1)) {
    LOG(ERROR) << kLogOrigin << "server listen error";
    return LastPosixError("listen error");
  }
  return absl::OkStatus();
}

}  // namespace asylo
