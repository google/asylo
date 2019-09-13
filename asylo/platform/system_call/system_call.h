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

#ifndef ASYLO_PLATFORM_SYSTEM_CALL_SYSTEM_CALL_H_
#define ASYLO_PLATFORM_SYSTEM_CALL_SYSTEM_CALL_H_

#include <cstddef>
#include <cstdint>

#include "asylo/platform/primitives/primitive_status.h"

#ifdef __cplusplus
extern "C" {
#endif

// Callback type installed at runtime to dispatch a system call across the
// enclave boundary. `request_buffer` and `request_size` designate a system call
// request owned by the caller, and on success `response_buffer` and
// `response_size` are populated with a response allocated by malloc() on the
// trusted heap.
typedef asylo::primitives::PrimitiveStatus (*syscall_dispatch_callback)(
    const uint8_t *request_buffer, size_t request_size,
    uint8_t **response_buffer, size_t *response_size);

// Installs a callback as dispatch function for serialized system calls.
void enc_set_dispatch_syscall(syscall_dispatch_callback callback);

// Installs an error handler function that aborts with a message in case of a
// failure.
void enc_set_error_handler(void (*abort_handler)(const char *message));

// Returns whether a dispatch function has been registered for making system
// calls.
bool enc_is_syscall_dispatcher_set();

// Returns whether an error handler function has been registered.
bool enc_is_error_handler_set();

// Invokes a system call on the host via the installed system call dispatch
// callback.
int64_t enc_untrusted_syscall(int sysno, ...);

#ifdef __cplusplus
}
#endif

#endif  // ASYLO_PLATFORM_SYSTEM_CALL_SYSTEM_CALL_H_
