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

#ifndef ASYLO_PLATFORM_ARCH_INCLUDE_TRUSTED_ENCLAVE_INTERFACE_H_
#define ASYLO_PLATFORM_ARCH_INCLUDE_TRUSTED_ENCLAVE_INTERFACE_H_

#include <pthread.h>

#include <cstring>

#ifdef __cplusplus
extern "C" {
#endif

// Returns the ID of the calling thread. Same as pthread_self(3).
pthread_t enc_thread_self();

// Validates that the address-range [|address|, |address| +|size|) is fully
// contained within the enclave.
bool enc_is_within_enclave(const void* address, size_t size);

// Validates that the address-range [|address|, |address| +|size|) is fully
// contained outside of the enclave.
bool enc_is_outside_enclave(void const* address, size_t size);

// A macro expanding to an expression appropriate for use as the body of a busy
// loop.
#ifdef __x86_64__
#define enc_pause() __builtin_ia32_pause()
#else
#define enc_pause() \
  do {              \
  } while (0)
#endif

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // ASYLO_PLATFORM_ARCH_INCLUDE_TRUSTED_ENCLAVE_INTERFACE_H_
