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

#ifndef ASYLO_PLATFORM_POSIX_SOCKETS_SOCKET_TRANSMIT_H_
#define ASYLO_PLATFORM_POSIX_SOCKETS_SOCKET_TRANSMIT_H_

#include <sys/socket.h>
#include <cstring>

#include "asylo/util/status.h"

namespace asylo {

// SocketTransmit is a wrapper around socket read/write. A SocketTransmit object
// provides interfaces of sending/receiving a buffer through sockets and records
// how many read/write syscalls are actually executed to fulfil the buffer
// transmission.
class SocketTransmit {
 public:
  // Constructs a SocketTrasmit object and sets the counts of executed
  // read/write syscalls to 0.
  SocketTransmit();

  // Reads |read_len| bytes from |fd| into |buf|.
  // Returns an OK Status on success or a Status with corresponding error code
  // on failure. If a non-OK Status is returned, the socket is in an undefined
  // state and the caller opts to close the channel. If there are insufficient
  // data fed to socket, this Read is always blocking, even for non-blocking
  // sockets. If the read syscall is always interrupted, this Read will be stuck
  // in a never-ending loop.
  Status Read(int fd, void *buf, size_t read_len);

  // Writes |write_len| bytes from |buf| into |fd|.
  // Returns an OK Status on success or a Status with corresponding error
  // code on failure. If a non-OK Status, the socket is in an undefined state
  // and the caller opts to close the channel. This Write will continue until
  // it sends |write_len| bytes or encounters an error, and is therefore always
  // effectively blocking, even for non-blocking sockets. If the write syscall
  // is always interrupted, this Write will be stuck in a never-ending loop.
  Status Write(int fd, const void *buf, size_t write_len);

  // Receives messages from a socked |sockfd| in |msg|.
  Status RecvMsg(int sockfd, struct msghdr *msg, int flags);

  // Transmits a message |msg| to another socket |sockfd|.
  Status SendMsg(int sockfd, const struct msghdr *msg, int flags);

  // RecvFrom on |socket| to |buffer|, optionally store source address in
  // |address| and the length of that address in |address_len|.
  Status RecvFrom(int socket, void *buffer, size_t length, int flags,
                  struct sockaddr *address, socklen_t *address_len);

  // Gets the number of times the write syscall has been executed.
  int GetWrite() const;

  // Gets the number of times the read syscall has been executed.
  int GetRead() const;

  // Resets the counts of executed read/write syscalls to 0.
  void reset();

 private:
  int write_count_;
  int read_count_;
};

}  // namespace asylo

#endif  // ASYLO_PLATFORM_POSIX_SOCKETS_SOCKET_TRANSMIT_H_
