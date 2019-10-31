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

#include "asylo/platform/primitives/util/primitive_locks.h"
#include "asylo/platform/primitives/x86/spin_lock.h"

// The newlib implementation of malloc and free in mallocr.c depends on symbols
// _malloc_lock and _malloc_unlock, and requires that a thread waiting on a lock
// it already holds will not pause. This file provides a implementation of that
// interface inside the enclave with minimal dependencies on other runtime
// components which expect to call malloc.

namespace asylo {
namespace primitives {

// Global lock protecting the heap.
asylo_spinlock_t heap_lock = ASYLO_SPIN_LOCK_INITIALIZER;

// Per-thread counter of how many times the lock was taken.
// It is only incremented once a thread took the lock, so for all threads except
// possibly one it will be zero.
thread_local int64_t thread_lock_count = 0;

extern "C" {

void __malloc_lock(struct reent *) {
  if (thread_lock_count == 0) {
    asylo_spin_lock(&heap_lock);
  }
  ++thread_lock_count;
}

void __malloc_unlock(struct reent *) {
  if (--thread_lock_count == 0) {
    asylo_spin_unlock(&heap_lock);
  }
}

}  // extern "C"

}  // namespace primitives
}  // namespace asylo
