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

#ifndef ASYLO_PLATFORM_HOST_CALL_TRUSTED_HOST_CALL_DISPATCHER_H_
#define ASYLO_PLATFORM_HOST_CALL_TRUSTED_HOST_CALL_DISPATCHER_H_

#include <stddef.h>

#include <cstdint>

#include "asylo/platform/primitives/primitive_status.h"
#include "asylo/platform/primitives/trusted_primitives.h"
#include "asylo/platform/primitives/util/message.h"

namespace asylo {
namespace host_call {

// Provides the dispatcher used for making host calls that are system calls.
// This dispatcher is installed as a callback by the |system_call| library for
// making system calls across the enclave boundary. Takes in a serialized
// |request_buffer| (containing the system call number and its corresponding
// arguments), and provides a serialized |response_buffer| (containing the
// system call return value and the response arguments). Returns ok status when
// successful, otherwise a status containing the error code and error message
// when serialization, dispatch or other errors occur.
primitives::PrimitiveStatus SystemCallDispatcher(const uint8_t* request_buffer,
                                                 size_t request_size,
                                                 uint8_t** response_buffer,
                                                 size_t* response_size);

// Provides a dispatcher to wrap the UntrustedCall function and perform basic
// validations. Used for host calls which are not implemented using syscalls.
primitives::PrimitiveStatus NonSystemCallDispatcher(
    uint64_t exit_selector, primitives::MessageWriter* input,
    primitives::MessageReader* output);

}  // namespace host_call
}  // namespace asylo

#endif  // ASYLO_PLATFORM_HOST_CALL_TRUSTED_HOST_CALL_DISPATCHER_H_
