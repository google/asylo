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

#ifndef ASYLO_PLATFORM_HOST_CALL_UNTRUSTED_HOST_CALL_HANDLERS_H_
#define ASYLO_PLATFORM_HOST_CALL_UNTRUSTED_HOST_CALL_HANDLERS_H_

#include "asylo/platform/primitives/untrusted_primitives.h"
#include "asylo/platform/primitives/util/message.h"
#include "asylo/util/status.h"

namespace asylo {
namespace host_call {

// This is a host call handler capable of servicing host calls which are true
// system calls, i.e., have an associated syscall number. It receives a
// MessageReader containing a serialized |request| (containing a system call
// number and the corresponding arguments) and writes back the serialized
// |response| containing the response message on the output MessageWriter.
// Returns ok status on success, otherwise an error message if a serialization
// error has occurred.
Status SystemCallHandler(const std::shared_ptr<primitives::Client> &client,
                         void *context, primitives::MessageReader *input,
                         primitives::MessageWriter *output);

// isatty library call handler on the host; expects [int fd] and returns [int].
Status IsAttyHandler(const std::shared_ptr<primitives::Client> &client,
                     void *context, primitives::MessageReader *input,
                     primitives::MessageWriter *output);

// usleep library call handler on the host; expects [useconds_t usec] and
// returns [int].
Status USleepHandler(const std::shared_ptr<primitives::Client> &client,
                     void *context, primitives::MessageReader *input,
                     primitives::MessageWriter *output);

// sysconf library call handler on the host; expects [int name] and returns
// [int].
Status SysconfHandler(const std::shared_ptr<primitives::Client> &client,
                      void *context, primitives::MessageReader *input,
                      primitives::MessageWriter *output);

// realloc library call handler on the host; expects [void *ptr, size_t size]
// and returns [void *output_ptr].
Status ReallocHandler(const std::shared_ptr<primitives::Client> &client,
                      void *context, primitives::MessageReader *input,
                      primitives::MessageWriter *output);

// sleep library call handler on the host; expects [uint32_t seconds] and
// returns [uint32_t].
Status SleepHandler(const std::shared_ptr<primitives::Client> &client,
                    void *context, primitives::MessageReader *input,
                    primitives::MessageWriter *output);

// sendmsg syscall handler on the host; expects [int sockfd, const struct msghdr
// *msg, int flags] and returns [ssize_t].
Status SendMsgHandler(const std::shared_ptr<primitives::Client> &client,
                      void *context, primitives::MessageReader *input,
                      primitives::MessageWriter *output);

// recvmsg syscall handler on the host; expects [int sockfd, struct msghdr *msg,
// int flags] and returns [ssize_t].
Status RecvMsgHandler(const std::shared_ptr<primitives::Client> &client,
                      void *context, primitives::MessageReader *input,
                      primitives::MessageWriter *output);

// getsockname syscall handler on the host; expects [int sockfd] and returns
// [int /*result*/, int /*errno*/, sockaddr] on the MessageWriter.
Status GetSocknameHandler(const std::shared_ptr<primitives::Client> &client,
                          void *context, primitives::MessageReader *input,
                          primitives::MessageWriter *output);

// accept syscall handler on the host; expects [int sockfd] and returns
// [int /*result*/, int /*errno*/, sockaddr] on the MessageWriter.
Status AcceptHandler(const std::shared_ptr<primitives::Client> &client,
                     void *context, primitives::MessageReader *input,
                     primitives::MessageWriter *output);

// getpeername syscall handler on the host; expects [int sockfd] and returns
// [int /*result*/, int /*errno*/, sockaddr] on the MessageWriter.
Status GetPeernameHandler(const std::shared_ptr<primitives::Client> &client,
                          void *context, primitives::MessageReader *input,
                          primitives::MessageWriter *output);

// recvfrom syscall handler on the host; expects [int sockfd, size_t len, int
// flags] and returns [int /*result*/, int /*errno*/, void * /*buf*/, sockaddr]
// on the MessageWriter.
Status RecvFromHandler(const std::shared_ptr<primitives::Client> &client,
                       void *context, primitives::MessageReader *input,
                       primitives::MessageWriter *output);

// raise library call handler on the host; expects [int sig] and returns [int
// /*result*/, int /*errno*/] on the MessageWriter.
Status RaiseHandler(const std::shared_ptr<primitives::Client> &client,
                    void *context, primitives::MessageReader *input,
                    primitives::MessageWriter *output);

// getsockopt library call handler on the host; expects [int sockfd, int level,
// int optname, Extent optval] and returns [int /*result*/, int /*errno*/,
// Extent /*optval*/] on the MessageWriter.
Status GetSockOptHandler(const std::shared_ptr<primitives::Client> &client,
                         void *context, primitives::MessageReader *input,
                         primitives::MessageWriter *output);

// getaddrinfo library call handler on the host. Expects one of the following on
// the input MessageReader, depending on whether hints to be provided to
// getaddrinfo is null -
// 1. [char *node, char *service]
// 2. [char *node, char *service, int ai_flags, int ai_family, int ai_socktype,
// ai_protocol].
// It returns the following on the MessageWriter -
// [int return_value, int errno, uint64_t number_of_addrinfos, (int ai_flags,
// int ai_family, int ai_socktype, int ai_protocol, struct sockaddr ai_addr,
// char *ai_canonname)...]
// The parameters in '()' above are repeated in multiples of
// number_of_addrinfos, which is the number of addrinfo structs in the linked
// list of the output addrinfo.
Status GetAddrInfoHandler(const std::shared_ptr<primitives::Client> &client,
                          void *context, primitives::MessageReader *input,
                          primitives::MessageWriter *output);

// inet_pton library call handler on the host; expects [int af, Extent src] and
// returns [int /*result*/, int /*errno*/, Extent /*addr*/] on the
// MessageWriter.
Status InetPtonHandler(const std::shared_ptr<primitives::Client> &client,
                       void *context, primitives::MessageReader *input,
                       primitives::MessageWriter *output);

// inet_ntop library call handler on the host; expects [int af, Extent src,
// socklen_t size] and returns [Extent /*result*/, int /*errno*/] on the
// MessageWriter.
Status InetNtopHandler(const std::shared_ptr<primitives::Client> &client,
                       void *context, primitives::MessageReader *input,
                       primitives::MessageWriter *output);

// sigprocmask library call handler on the host; expects [int how,
// klinux_sigset_t sigset] and returns [int /*result*/, int /*errno*/,
// klinux_sigset_t /*oldset*/] on the MessageWriter.
Status SigprocmaskHandler(const std::shared_ptr<primitives::Client> &client,
                          void *context, primitives::MessageReader *input,
                          primitives::MessageWriter *output);

}  // namespace host_call
}  // namespace asylo

#endif  // ASYLO_PLATFORM_HOST_CALL_UNTRUSTED_HOST_CALL_HANDLERS_H_
