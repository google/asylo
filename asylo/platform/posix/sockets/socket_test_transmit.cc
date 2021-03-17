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

#include "asylo/platform/posix/sockets/socket_test_transmit.h"

#include <string.h>
#include <sys/socket.h>

#include "absl/status/status.h"
#include "asylo/util/status.h"

namespace asylo {
namespace {

constexpr char kClientWriteSuccessStr[] = "Client Write is successful.";
constexpr char kServerWriteSuccessStr[] = "Server Write is successful.";
constexpr char kClientMsgSuccessStr1[] = "First Client SendMsg is successful.";
constexpr char kClientMsgSuccessStr2[] = "Second Client SendMsg is successful.";
constexpr char kServerMsgSuccessStr1[] = "First Server RecvMsg is successful.";
constexpr char kServerMsgSuccessStr2[] = "Second Server RecvMsg is successful.";
constexpr int kNumMsgs = 2;

void AssembleMsgHdr(struct msghdr *msg, struct iovec *iov, const char *msg1,
                    const char *msg2, char *buf1, char *buf2, bool isSend) {
  memset(iov, 0, sizeof(*iov));
  if (isSend) {
    iov[0].iov_base = reinterpret_cast<void *>(const_cast<char *>(msg1));
    iov[1].iov_base = reinterpret_cast<void *>(const_cast<char *>(msg2));
  } else {
    iov[0].iov_base = reinterpret_cast<void *>(buf1);
    iov[1].iov_base = reinterpret_cast<void *>(buf2);
  }
  iov[0].iov_len = sizeof(msg1);
  iov[1].iov_len = sizeof(msg2);
  memset(msg, 0, sizeof(*msg));
  msg->msg_iov = iov;
  msg->msg_iovlen = kNumMsgs;
}

}  // namespace

const char kLocalIpv6AddrStr[] = "::1";

Status ServerTransmit(SocketServer *socket_server) {
  Status status;
  if (!(status = socket_server->Write(kServerWriteSuccessStr,
                                      sizeof(kServerWriteSuccessStr)))
           .ok()) {
    return status;
  }
  char socket_buf[sizeof(kClientWriteSuccessStr)];
  if (!(status = socket_server->Read(socket_buf, sizeof(socket_buf))).ok()) {
    return status;
  }
  if (strncmp(socket_buf, kClientWriteSuccessStr, sizeof(socket_buf))) {
    return absl::DataLossError("expected client-write string not found");
  }

  if (!(status = socket_server->Write(kServerWriteSuccessStr,
                                      sizeof(kServerWriteSuccessStr)))
           .ok()) {
    return status;
  }

  if (!(status = socket_server->RecvFrom(socket_buf, sizeof(socket_buf), 0,
                                         nullptr, nullptr))
           .ok()) {
    return status;
  }
  if (strncmp(socket_buf, kClientWriteSuccessStr, sizeof(socket_buf))) {
    return absl::DataLossError("expected client-write string not found");
  }

  struct iovec msg_iov_send[kNumMsgs];
  struct msghdr msg_send;
  AssembleMsgHdr(&msg_send, msg_iov_send, kServerMsgSuccessStr1,
                 kServerMsgSuccessStr2, nullptr, nullptr, /*isSend=*/true);
  if (!(status = socket_server->SendMsg(&msg_send, /*flags=*/0)).ok()) {
    return status;
  }

  struct iovec msg_iov_recv[kNumMsgs];
  struct msghdr msg_recv;
  char buf1[sizeof(kClientMsgSuccessStr1)];
  char buf2[sizeof(kClientMsgSuccessStr2)];
  AssembleMsgHdr(&msg_recv, msg_iov_recv, kClientMsgSuccessStr1,
                 kClientMsgSuccessStr2, buf1, buf2, /*isSend=*/false);
  if (!(status = socket_server->RecvMsg(&msg_recv, /*flags=*/0)).ok()) {
    return status;
  }
  if (strncmp(reinterpret_cast<char *>(msg_recv.msg_iov[0].iov_base),
              kClientMsgSuccessStr1, msg_recv.msg_iov[0].iov_len) ||
      strncmp(reinterpret_cast<char *>(msg_recv.msg_iov[1].iov_base),
              kClientMsgSuccessStr2, msg_recv.msg_iov[1].iov_len)) {
    return absl::DataLossError("expected client-write string not found");
  }
  return absl::OkStatus();
}

Status ClientTransmit(SocketClient *socket_client) {
  char socket_buf[sizeof(kServerWriteSuccessStr)];
  Status status;
  if (!(status = socket_client->Read(socket_buf, sizeof(socket_buf))).ok()) {
    return status;
  }
  if (strncmp(socket_buf, kServerWriteSuccessStr, sizeof(socket_buf))) {
    return absl::DataLossError("expected server-write string not found");
  }
  if (!(status = socket_client->Write(kClientWriteSuccessStr,
                                      sizeof(kClientWriteSuccessStr)))
           .ok()) {
    return status;
  }

  if (!(status = socket_client->RecvFrom(socket_buf, sizeof(socket_buf), 0,
                                         nullptr, nullptr))
           .ok()) {
    return status;
  }
  if (strncmp(socket_buf, kServerWriteSuccessStr, sizeof(socket_buf))) {
    return absl::DataLossError("expected server-write string not found");
  }
  if (!(status = socket_client->Write(kClientWriteSuccessStr,
                                      sizeof(kClientWriteSuccessStr)))
           .ok()) {
    return status;
  }

  struct iovec msg_iov_recv[kNumMsgs];
  struct msghdr msg_recv;
  char buf1[sizeof(kServerMsgSuccessStr1)];
  char buf2[sizeof(kServerMsgSuccessStr2)];
  AssembleMsgHdr(&msg_recv, msg_iov_recv, kServerMsgSuccessStr1,
                 kServerMsgSuccessStr2, buf1, buf2, /*isSend=*/false);
  if (!(status = socket_client->RecvMsg(&msg_recv, /*flags=*/0)).ok()) {
    return status;
  }
  if (strncmp(reinterpret_cast<char *>(msg_recv.msg_iov[0].iov_base),
              kServerMsgSuccessStr1, msg_recv.msg_iov[0].iov_len) ||
      strncmp(reinterpret_cast<char *>(msg_recv.msg_iov[1].iov_base),
              kServerMsgSuccessStr2, msg_recv.msg_iov[1].iov_len)) {
    return absl::DataLossError("expected client-write string not found");
  }
  struct iovec msg_iov_send[kNumMsgs];
  struct msghdr msg_send;
  AssembleMsgHdr(&msg_send, msg_iov_send, kClientMsgSuccessStr1,
                 kClientMsgSuccessStr2, nullptr, nullptr, /*isSend=*/true);
  if (!(status = socket_client->SendMsg(&msg_send, /*flags=*/0)).ok()) {
    return status;
  }
  return absl::OkStatus();
}

}  // namespace asylo
