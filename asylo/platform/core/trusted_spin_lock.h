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

#ifndef ASYLO_PLATFORM_CORE_TRUSTED_SPIN_LOCK_H_
#define ASYLO_PLATFORM_CORE_TRUSTED_SPIN_LOCK_H_

#include <cstdint>

#include "asylo/platform/core/atomic.h"
#include "asylo/platform/primitives/trusted_runtime.h"

namespace asylo {

// A spin lock implementation depending on only trusted resources.
//
// An TrustedSpinLock object is a thread synchronization primitive that depends
// on only resources inside the enclave.
//
// The 'alignas' aligns the object to to the cache line size and pads the object
// to the same cache line size.
class alignas(kCacheLineSize) TrustedSpinLock {
 public:
  // A spin lock is a 32-bit value. In this implementation, the value of the
  // spin lock distinguishes between two possible states:
  //
  // The spin lock is unlocked.
  constexpr static uint32_t kUnlocked = 0;
  //
  // The spin lock is locked.
  constexpr static uint32_t kLocked = 1;

  // Initializes an unlocked spin lock. If |is_recursive| is true, then the
  // mutex is a recursive lock and may 1) be locked more than once by the caller
  // and 2) does not become free until it is unlocked a corresponding number of
  // times. This optional functionality is provided for compatibility with
  // pthread_mutex.
  constexpr explicit TrustedSpinLock(bool is_recursive)
      : spin_lock_(kUnlocked),
        owner_(kInvalidThread),
        is_recursive_(is_recursive),
        recursive_lock_count_(0) {}

  ~TrustedSpinLock() = default;

  // If this lock is not already held, block until the calling thread is able to
  // acquire it. If configured as a recursive lock, an TrustedSpinLock may be
  // acquired multiple times, in which case it must be unlocked a corresponding
  // number of times before becoming free.
  void Lock();

  // Returns true if the calling thread is the owner of the mutex.
  bool Owned() const;

  // Tries to acquire the lock without blocking. Returns true if the lock was
  // acquired, otherwise false.
  bool TryLock();

  // Releases the lock, which must be held by the calling thread. If the mutex
  // is configured as a recursive lock and was locked multiple times, then it
  // must be unlocked a corresponding number of times before being released.
  void Unlock();

  // IMPORTANT: Only safe to call from a thread which currently holds
  // the TrustedSpinLock. Used to determine if next unlock or previous
  // lock operation actually changed the state of the lock (from
  // Unlocked to Locked or vice versa). Useful for building efficient
  // recursive locks which use TrustedSpinLock as their source of
  // truth. Will return true if locked and not recursive, false if
  // unlocked and not recursive.
  bool LockDepthIsOne();

 private:
  // A synchronization value in untrusted memory, aligned to a cache line.
  volatile uint32_t spin_lock_;

  // The enc_thread_self() value of the thread that owns the lock, or zero if
  // the mutex is unlocked.
  volatile uint64_t owner_;

  // True if this mutex has been configured as a recursive lock.
  const bool is_recursive_;

  // The number of times this lock has been locked recursively.
  uint64_t recursive_lock_count_;
};

static_assert(sizeof(TrustedSpinLock) == kCacheLineSize,
              "TrustedSpinLock must be sizeof a cache line.");

}  // namespace asylo

#endif  // ASYLO_PLATFORM_CORE_TRUSTED_SPIN_LOCK_H_
