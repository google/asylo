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

#ifndef ASYLO_PLATFORM_PRIMITIVES_SGX_TRUSTED_SGX_H_
#define ASYLO_PLATFORM_PRIMITIVES_SGX_TRUSTED_SGX_H_

// This file declares the trusted runtime interface for SGX.

#include <sys/types.h>

#include <cstdint>

#include "asylo/platform/common/bridge_types.h"

namespace asylo {
namespace primitives {

// Invokes the registered handler with pointers to input and output message for
// the trusted entry point designated by |selector|. Returns a non-zero error
// code on failure. This function is the one and only entry point inside the
// enclave for any enclave call, including initialization and trusted function
// calls.
int asylo_enclave_call(uint64_t selector, void *buffer);

// Exits the enclave and triggers the fork routine.
pid_t InvokeFork(const char *enclave_name, bool restore_snapshot);

// Sends the signal to registered signal handler through SignalManager.
int DeliverSignal(const char *input, size_t input_len);

int RegisterSignalHandler(
    int signum, void (*bridge_sigaction)(int, bridge_siginfo_t *, void *),
    const sigset_t mask, int flags, const char *enclave_name);

// Allocates |count| buffers of size |size| on the untrusted heap, returning a
// pointer to an array of buffer pointers.
void **AllocateUntrustedBuffers(size_t count, size_t size);

// Releases memory on the untrusted heap pointed to by buffer pointers stored in
// |free_list|.
void DeAllocateUntrustedBuffers(void **free_list, size_t count);

// Exits the enclave and, if the value stored at |futex| equals |expected|,
// suspends the calling thread until it is resumed by a call to
// enc_untrusted_sys_futex_wake. Otherwise returns immediately.
void enc_untrusted_sys_futex_wait(int32_t *futex, int32_t expected);

// Exits the enclave and wakes a suspended thread blocked on |futex|.
void enc_untrusted_sys_futex_wake(int32_t *futex);

}  // namespace primitives
}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_SGX_TRUSTED_SGX_H_
