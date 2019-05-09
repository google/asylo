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

#ifndef ASYLO_PLATFORM_POSIX_SOCKETS_SOCKET_SERVER_H_
#define ASYLO_PLATFORM_POSIX_SOCKETS_SOCKET_SERVER_H_

#include <sys/socket.h>

#include <string>

#include "asylo/platform/posix/sockets/socket_transmit.h"
#include "asylo/platform/storage/utils/fd_closer.h"

namespace asylo {

// SocketServer sets up a local IPv4 server on a given port number at IP
// 0.0.0.0 or a UNIX domain server on a given socket name. A SocketServer
// object provides the interface that binds and listens on a local socket,
// and then accepts the first incoming connection request.
class SocketServer {
 public:
  // Constructs a SocketServer object and sets |connection_fd| to an invalid
  // descriptor (-1).
  SocketServer();

  // Sets up a local Internet IPv4 server on |server_port| at 0.0.0.0. Calls
  // ServerConncection to fulfill server binding and listening.
  // Returns an OK Status on success or a Status with corresponding error code
  // on failure.
  Status ServerSetup(int server_port = 0);

  // Sets up a UNIX domain server on |socket_name|. Calls Serverconnection to
  // fulfill server binding and listening. If |use_path_len| is true, then
  // instead of size of sockaddr_un struct, the len of sun_path plus size of
  // sun_family is used as the value of addrlen.
  // Returns an OK Status on success or a Status with corresponding error code
  // on failure.
  Status ServerSetup(const std::string &socket_name, bool use_path_len);

  // Accepts a single connection at the socket bound by ServerSetup and
  // directs the first incoming connection request to |connection_fd_|.
  Status ServerAccept();

  // Calls Read method of |sock_transmit_| to read |read_len| bytes from
  // |connection_fd_| into |buf| and propagates the return value.
  Status Read(void *buf, size_t read_len);

  // Calls Write method of |sock_transmit_| to write |write_len| bytes from
  // |buf| into |connection_fd_| and propagates the return value.
  Status Write(const void *buf, size_t write_len);

  // Calls RecvMsg method of |sock_transmit_| to receive message from
  // |connection_fd_| into |msg| and propagates the return value.
  Status RecvMsg(struct msghdr *msg, int flags);

  // Calls SendMsg method of |sock_transmit_| to send message from |msg| into
  // |connection_fd_| and propagates the return value.
  Status SendMsg(const struct msghdr *msg, int flags);

  // Calls RecvFrom method of |sock_transmit| to receive data from
  // |connection_fd_| and propagates the return value.
  Status RecvFrom(void *buffer, size_t length, int flags,
                  struct sockaddr *address, socklen_t *address_len);

  // Performs |round_trip| rounds of data transmission with client. In each
  // round, server writes |buf_len| bytes to client and reads |buf_len| bytes
  // from client.
  Status ServerRoundtripTransmit(int buf_len, int round_trip);

  // Logs socket write/read statistics of server.
  void LogServerIOStats();

  // Returns the port on which the server is listening, or -1 if not listening
  // on a port.
  int GetPort();

 private:
  int connection_fd_;
  SocketTransmit sock_transmit_;
  platform::storage::FdCloser socket_fd_;

  // Binds |fd| on |serv_addr| whose size is |addrlen|. Listens to connection
  // requests on |fd|.
  // Returns an OK Status on success or a Status with corresponding error code
  // on failure.
  Status ServerConnection(int fd, struct sockaddr *serv_addr,
                          socklen_t addrlen);
};

}  // namespace asylo

#endif  // ASYLO_PLATFORM_POSIX_SOCKETS_SOCKET_SERVER_H_
