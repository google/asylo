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

#ifndef ASYLO_PLATFORM_POSIX_SOCKETS_SOCKET_CLIENT_H_
#define ASYLO_PLATFORM_POSIX_SOCKETS_SOCKET_CLIENT_H_

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <string>

#include "asylo/platform/posix/sockets/socket_transmit.h"
#include "asylo/platform/storage/utils/fd_closer.h"

namespace asylo {

// SocketClient sets up a IPv4 client that connects to a given pair of IP and
// port or to local UNIX domain server on a given socket name.
class SocketClient {
 public:
  // Constructs a SocketClient object. Sets |connection_fd_| to an invalid
  // descriptor (-1).
  SocketClient();

  // Sets up a IPv6 client connecting to |server_ip| on |server_port|.
  // Connection is fulfilled on |connection_fd_|.
  // If |out_addr| is not null, and the OK status is returned, the sockaddr
  // of the made connection is written to |out_addr|.
  // Returns an OK Status on success or a Status with corresponding error code
  // on failure.
  Status ClientSetup(const std::string &server_ip, int server_port,
                     sockaddr_in6 *out_addr);

  // Sets up a UNIX domain client connecting to local UNIX domain server on
  // |socket_name|. Connection is fulfilled on |connection_fd_|.
  // If |out_addr| is not null, and the OK status is returned, the sockaddr
  // of the made connection is written to |out_addr|. If |use_path_len| is true,
  // then instead of size of sockaddr_un struct, the len of sun_path plus size
  // of sun_family is used as the value of addrlen.
  // Returns an OK Status on success or a Status with corresponding error code
  // on failure.
  Status ClientSetup(const std::string &socket_name, sockaddr_un *out_addr,
                     bool use_path_len);

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

  // Calls RecvFrom method of |sock_transmit_| to receive data from
  // |connection_fd_| and propagates the return value.
  Status RecvFrom(void *buffer, size_t length, int flags,
                  struct sockaddr *address, socklen_t *address_len);

  // Performs |round_trip| rounds of data transmission with server. In each
  // round, client reads |buf_len| bytes from server and writes |buf_len| bytes
  // to server.
  Status ClientRoundtripTransmit(int buf_len, int round_trip);

  // Calls getpeername() on the underlying connection. If retval is OkStatus(),
  // the peer sockaddr and its length are returned in the caller-provided
  // buffers in |peeraddr_out| and |peeraddr_len_out|.
  Status GetPeername(struct sockaddr *peeraddr_out,
                     socklen_t *peeraddr_len_out);

  // Logs socket write/read statistics of client.
  void LogClientIOStats();

 private:
  int connection_fd_;

  // |fd_closer_| is set as a member variable bound to |connection_fd_|.
  // |connection_fd_| will not be closed until SocketClient object is
  // destroyed or a new client is set up, so that |connection_fd_| is alive
  // after ClientSetup.
  platform::storage::FdCloser fd_closer_;

  SocketTransmit sock_transmit_;

  // Connects to |serv_addr| whose size is |addrlen| on |fd|.
  // Returns an OK Status on success or a Status with corresponding error code
  // on failure.
  Status ClientConnection(int fd, struct sockaddr *serv_addr,
                          socklen_t addrlen);
};

}  // namespace asylo

#endif  // ASYLO_PLATFORM_POSIX_SOCKETS_SOCKET_CLIENT_H_
