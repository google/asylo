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
#include "asylo/util/status.h"

namespace asylo {
namespace host_call {

// This is a general purpose system call exit handler capable of servicing most
// kinds of system calls. It receives a parameter stack containing a serialized
// |request| (containing a system call number and the corresponding arguments)
// and writes back the serialized |response| containing the response message on
// the same parameter stack. Returns ok status on success, otherwise an error
// message if a serialization error has occurred.
Status SystemCallHandler(const std::shared_ptr<primitives::Client> &client,
                         void *context,
                         primitives::NativeParameterStack *parameters);

// This handler performs the IsAtty host call. IsAtty takes in a single
// parameter from the stack (int fd), and calls the libc function isatty,
// which returns an int. The int is passed on the parameter stack to be
// returned. Returns ok status on success, otherwise an error message.
Status IsAttyHandler(const std::shared_ptr<primitives::Client> &client,
                     void *context,
                     primitives::NativeParameterStack *parameters);

// This handler performs the USleep host call. USleep takes in a single
// parameter from the stack (useconds_t usec), and calls the libc function
// usleep, which returns an int. The int is passed on the parameter stack to be
// returned. Returns ok status on success, otherwise an error message.
Status USleepHandler(const std::shared_ptr<primitives::Client> &client,
                     void *context,
                     primitives::NativeParameterStack *parameters);

}  // namespace host_call
}  // namespace asylo

#endif  // ASYLO_PLATFORM_HOST_CALL_UNTRUSTED_HOST_CALL_HANDLERS_H_
