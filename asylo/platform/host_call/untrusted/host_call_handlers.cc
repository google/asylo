/*
 *
 * Copyright 2019 Asylo authors
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

#include "asylo/platform/host_call/untrusted/host_call_handlers.h"

#include <errno.h>
#include <sys/socket.h>
#include <unistd.h>

#include "asylo/platform/primitives/util/message.h"
#include "asylo/platform/primitives/util/status_conversions.h"
#include "asylo/platform/system_call/untrusted_invoke.h"
#include "asylo/util/status_macros.h"

namespace asylo {
namespace host_call {

Status SystemCallHandler(const std::shared_ptr<primitives::Client> &client,
                         void *context, primitives::MessageReader *input,
                         primitives::MessageWriter *output) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*input, 1);
  auto request = input->next();

  primitives::Extent response;  // To be owned by untrusted call parameters.
  primitives::PrimitiveStatus status =
      system_call::UntrustedInvoke(request, &response);
  if (!status.ok()) {
    return primitives::MakeStatus(status);
  }
  output->PushByCopy(response);
  free(response.data());

  return Status::OkStatus();
}

Status IsAttyHandler(const std::shared_ptr<primitives::Client> &client,
                     void *context, primitives::MessageReader *input,
                     primitives::MessageWriter *output) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*input, 1);
  int fd = input->next<int>();
  output->Push<int>(isatty(fd));  // Push return value first.
  output->Push<int>(
      errno);  // Push errno next. We always push the errno on the MessageWriter
               // regardless of the return value of the host call. The caller is
               // responsible for evaluating the return value and setting the
               // errno appropriately in its local environment.
  return Status::OkStatus();
}

Status USleepHandler(const std::shared_ptr<primitives::Client> &client,
                     void *context, primitives::MessageReader *input,
                     primitives::MessageWriter *output) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*input, 1);
  auto usec = input->next<useconds_t>();
  output->Push<int>(usleep(usec));  // Push return value first.
  output->Push<int>(errno);         // Push errno next.
  return Status::OkStatus();
}

Status SysconfHandler(const std::shared_ptr<primitives::Client> &client,
                      void *context, primitives::MessageReader *input,
                      primitives::MessageWriter *output) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*input, 1);
  int kLinux_name = input->next<int>();
  output->Push<int64_t>(sysconf(kLinux_name));  // Push return value first.
  output->Push<int>(errno);                     // Push errno next.
  return Status::OkStatus();
}

Status ReallocHandler(const std::shared_ptr<primitives::Client> &client,
                      void *context, primitives::MessageReader *input,
                      primitives::MessageWriter *output) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*input, 2);
  void *in_ptr = input->next<void *>();
  size_t size = input->next<size_t>();
  void *out_ptr = realloc(in_ptr, size);
  output->Push(reinterpret_cast<uint64_t>(out_ptr));
  output->Push<int>(errno);
  return Status::OkStatus();
}

Status SleepHandler(const std::shared_ptr<primitives::Client> &client,
                    void *context, primitives::MessageReader *input,
                    primitives::MessageWriter *output) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*input, 1);
  auto seconds = input->next<uint32_t>();
  output->Push<uint32_t>(sleep(seconds));  // Push return value first.
  output->Push<int>(errno);                // Push errno next.
  return Status::OkStatus();
}

Status SendMsgHandler(const std::shared_ptr<primitives::Client> &client,
                      void *context, primitives::MessageReader *input,
                      primitives::MessageWriter *output) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*input, 6);
  struct msghdr msg;
  int sockfd = input->next<int>();

  auto msg_name_extent = input->next();
  msg.msg_name = msg_name_extent.As<char>();
  msg.msg_namelen = msg_name_extent.size();

  auto msg_iov_extent = input->next();
  // The message is serialized into a single buffer on the trusted side.
  struct iovec msg_iov[1];
  memset(msg_iov, 0, sizeof(*msg_iov));
  msg_iov[0].iov_base = msg_iov_extent.As<char>();
  msg_iov[0].iov_len = msg_iov_extent.size();
  msg.msg_iov = msg_iov;
  msg.msg_iovlen = 1;

  auto msg_control_extent = input->next();
  msg.msg_control = msg_control_extent.As<char>();
  msg.msg_controllen = msg_control_extent.size();

  msg.msg_flags = input->next<int>();

  int flags = input->next<int>();
  output->Push<int64_t>(sendmsg(sockfd, &msg, flags));  // Push return value.
  output->Push<int>(errno);                             // Push errno.
  return Status::OkStatus();
}

Status RecvMsgHandler(const std::shared_ptr<primitives::Client> &client,
                      void *context, primitives::MessageReader *input,
                      primitives::MessageWriter *output) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*input, 6);
  int sockfd = input->next<int>();

  // An upper bound of buffer size for name/control to avoid allocating memory
  // for a non-initialized random size.
  constexpr size_t kMaxBufferSize = 1024;

  struct msghdr msg;
  msg.msg_namelen = input->next<uint64_t>();
  std::unique_ptr<char[]> msg_name_buffer(nullptr);
  if (msg.msg_namelen > 0 && msg.msg_namelen < kMaxBufferSize) {
    msg_name_buffer.reset(new char[msg.msg_namelen]);
  } else {
    msg.msg_namelen = 0;
  }
  msg.msg_name = msg_name_buffer.get();

  // Receive message in a single buffer, which will be copied into the scattered
  // buffers once back inside the enclave.
  msg.msg_iovlen = 1;
  struct iovec msg_iov[1];
  memset(msg_iov, 0, sizeof(*msg_iov));
  msg_iov[0].iov_len = input->next<uint64_t>();
  std::unique_ptr<char[]> msg_iov_buffer(nullptr);
  if (msg_iov[0].iov_len > 0) {
    msg_iov_buffer.reset(new char[msg_iov[0].iov_len]);
  }
  msg_iov[0].iov_base = msg_iov_buffer.get();
  msg.msg_iov = msg_iov;

  msg.msg_controllen = input->next<uint64_t>();
  std::unique_ptr<char[]> msg_control_buffer(nullptr);
  if (msg.msg_controllen > 0 && msg.msg_controllen < kMaxBufferSize) {
    msg_control_buffer.reset(new char[msg.msg_controllen]);
  } else {
    msg.msg_controllen = 0;
  }
  msg.msg_control = msg_control_buffer.get();

  msg.msg_flags = input->next<int>();
  int flags = input->next<int>();

  output->Push<int64_t>(recvmsg(sockfd, &msg, flags));  // Push return value.
  output->Push<int>(errno);                             // Push errno.
  output->PushByCopy(::asylo::primitives::Extent{
      msg.msg_name, msg.msg_namelen});  // Push msg name.
  output->PushByCopy(::asylo::primitives::Extent{
      msg.msg_iov[0].iov_base, msg.msg_iov[0].iov_len});  // Push received msg.
  output->PushByCopy(::asylo::primitives::Extent{
      msg.msg_control, msg.msg_controllen});  // Push control msg.

  return Status::OkStatus();
}

Status GetSocknameHandler(const std::shared_ptr<primitives::Client> &client,
                          void *context, primitives::MessageReader *input,
                          primitives::MessageWriter *output) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*input, 1);
  int sockfd = input->next<int>();
  struct sockaddr_storage sock_addr;
  socklen_t sock_len = sizeof(sock_addr);

  int ret = getsockname(sockfd, reinterpret_cast<struct sockaddr *>(&sock_addr),
                        &sock_len);

  LOG_IF(FATAL, sock_len > sizeof(sock_addr))
      << "Insufficient sockaddr buf space encountered for getsockname host "
         "call";

  output->Push<int>(ret);
  output->Push<int>(errno);
  output->Push<struct sockaddr_storage>(sock_addr);

  return Status::OkStatus();
}

Status AcceptHandler(const std::shared_ptr<primitives::Client> &client,
                     void *context, primitives::MessageReader *input,
                     primitives::MessageWriter *output) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*input, 1);
  int sockfd = input->next<int>();
  struct sockaddr_storage sock_addr;
  socklen_t sock_len = sizeof(sock_addr);

  int ret = accept(sockfd, reinterpret_cast<struct sockaddr *>(&sock_addr),
                   &sock_len);

  LOG_IF(FATAL, sock_len > sizeof(sock_addr))
      << "Insufficient sockaddr buf space encountered for accept host call.";

  output->Push<int>(ret);
  output->Push<int>(errno);
  output->Push<struct sockaddr_storage>(sock_addr);

  return Status::OkStatus();
}

Status GetPeernameHandler(const std::shared_ptr<primitives::Client> &client,
                          void *context, primitives::MessageReader *input,
                          primitives::MessageWriter *output) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*input, 1);
  int sockfd = input->next<int>();
  struct sockaddr_storage sock_addr;
  socklen_t sock_len = sizeof(sock_addr);

  int ret = getpeername(sockfd, reinterpret_cast<struct sockaddr *>(&sock_addr),
                        &sock_len);

  LOG_IF(FATAL, sock_len > sizeof(sock_addr))
      << "Insufficient sockaddr buf space encountered for getpeername host "
         "call.";

  output->Push<int>(ret);
  output->Push<int>(errno);
  output->Push<struct sockaddr_storage>(sock_addr);

  return Status::OkStatus();
}

Status RecvFromHandler(const std::shared_ptr<primitives::Client> &client,
                       void *context, primitives::MessageReader *input,
                       primitives::MessageWriter *output) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*input, 3);
  int sockfd = input->next<int>();
  size_t len = input->next<size_t>();
  int klinux_flags = input->next<int>();
  struct sockaddr_storage sock_addr;
  socklen_t sock_len = sizeof(sock_addr);

  auto buffer = absl::make_unique<char[]>(len);
  ssize_t ret = recvfrom(
      sockfd, reinterpret_cast<void *>(buffer.get()), len, klinux_flags,
      reinterpret_cast<struct sockaddr *>(&sock_addr), &sock_len);

  LOG_IF(FATAL, sock_len > sizeof(sock_addr))
      << "Insufficient sockaddr buf space encountered for recvfrom host call.";

  output->Push<int>(ret);
  output->Push<int>(errno);
  output->PushByCopy(primitives::Extent{buffer.get(), len});
  output->Push<struct sockaddr_storage>(sock_addr);

  return Status::OkStatus();
}

}  // namespace host_call
}  // namespace asylo
