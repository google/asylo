/*
 *
 * Copyright 2018 Asylo authors
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

#ifndef ASYLO_PLATFORM_PRIMITIVES_TRUSTED_RUNTIME_H_
#define ASYLO_PLATFORM_PRIMITIVES_TRUSTED_RUNTIME_H_

#include <cstdint>

// This file declares a minimal set of trusted runtime functions each backend
// must export to support linking against libc.

extern "C" {

// Emulates the Unix `sbrk` system call. See sbrk(2).
void *enclave_sbrk(intptr_t increment);

}

#endif  // ASYLO_PLATFORM_PRIMITIVES_TRUSTED_RUNTIME_H_
