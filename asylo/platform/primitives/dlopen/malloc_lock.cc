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

#include <cstdlib>

#include "asylo/platform/core/trusted_spin_lock.h"

// The newlib implementation of malloc and free in mallocr.c depends on symbols
// _malloc_lock and _malloc_unlock, and requires that a thread waiting on a lock
// it already holds will not pause. This file provides a implementation of that
// interface inside the enclave with minimal dependencies on other runtime
// components which expect to call malloc.

namespace asylo {
namespace primitives {

// Global lock protecting the heap.
TrustedSpinLock heap_lock{/*is_recursive=*/true};

extern "C" {

void __malloc_lock(struct reent *) { heap_lock.Lock(); }

void __malloc_unlock(struct reent *) { heap_lock.Unlock(); }

}  // extern "C"

}  // namespace primitives
}  // namespace asylo
