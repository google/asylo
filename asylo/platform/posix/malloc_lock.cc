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

#include <atomic>
#include <cstdlib>

#include "asylo/platform/core/atomic.h"
#include "asylo/platform/primitives/trusted_runtime.h"

// The newlib implementation of malloc and free in mallocr.c depends on symbols
// _malloc_lock and _malloc_unlock, and requires that a thread waiting on a lock
// it already holds will not pause. This file provides a implementation of that
// interface inside the enclave with minimal dependencies on other runtime
// components which expect to call malloc.

#define CACHE_ALIGNED __attribute__((aligned(64)))

// The current owner of the lock, aligned to ensure atomic instructions do not
// straddle a cache line. A value of zero indicates the lock is not held by any
// thread.
static volatile uint64_t lock_owner CACHE_ALIGNED = kInvalidThread;

// The number of times the lock has been recursively acquired, aligned to ensure
// it does not fall in the same cache line as lock_owner to avoid false sharing.
// Notes that the count is only accessed by the thread holding the lock and does
// not need to be updated atomically.
static int lock_count CACHE_ALIGNED = 0;

extern "C" {

void __malloc_lock(struct reent *) {
  const uint64_t self = enc_thread_self();

  while (lock_owner != self) {
    uint64_t unlocked_value = kInvalidThread;

    // Attempt to acquire the mutex by swapping the lock with the current thread
    // id, specifying strong memory ordering to avoid unexpected memory
    // ordering. Try to obtain the lock by atomically testing that it is
    // unlocked and exchanging it with our thread id.
    if (asylo::AtomicCompareExchange<uint64_t>(
            &lock_owner,
            /*expected=*/&unlocked_value,
            /*desired=*/self,
            /*weak=*/true,
            /*success_memorder=*/std::memory_order_acquire,
            /*failure_memorder=*/std::memory_order_relaxed)) {
      break;
    }

    // If the lock is not free, avoid doing a synchronized read and busy wait
    // until it's released then try to obtain it again.
    while (lock_owner != kInvalidThread) {
      // Issue a busy-wait hint to the CPU if possible.
      enc_pause();
    }
  }

  lock_count++;
}

void __malloc_unlock(struct reent *) {
  // Unlock should only be called by the thread that holds the lock. If this is
  // not the case we abort.
  if (lock_owner != enc_thread_self()) {
    abort();
  }

  lock_count--;
  if (lock_count == 0) {
    // Release the lock with an atomic store.
    asylo::AtomicStore(&lock_owner, kInvalidThread, std::memory_order_release);
  }
}

}  // extern "C"
