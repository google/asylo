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
// [int (result), int (errno), sockaddr] on the MessageWriter.
Status GetSocknameHandler(const std::shared_ptr<primitives::Client> &client,
                          void *context, primitives::MessageReader *input,
                          primitives::MessageWriter *output);

}  // namespace host_call
}  // namespace asylo

#endif  // ASYLO_PLATFORM_HOST_CALL_UNTRUSTED_HOST_CALL_HANDLERS_H_
