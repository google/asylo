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

#ifndef ASYLO_PLATFORM_COMMON_SPIN_LOCK_H_
#define ASYLO_PLATFORM_COMMON_SPIN_LOCK_H_

#include <xmmintrin.h>
#include <atomic>
#include <cstddef>

// A spinlock in shared memory, suitable for sharing between trusted and
// untrusted applications. This implementation uses only synchronized
// instructions and does not depend on operating system resources.
class SpinLock {
 public:
  // Initializes an unlocked spinlock.
  SpinLock() : lock_word_(kUnlockedValue) {}

  // Spins in a busy loop until the lock is acquired.
  void Acquire() {
    while (!TryLock()) {
      _mm_pause();
    }
  }

  // Tries to acquire the lock without blocking. Returns true if the lock was
  // acquired, otherwise false.
  bool TryLock() {
    uint64_t expected_value = kUnlockedValue;
    return lock_word_.compare_exchange_strong(expected_value, kLockedValue,
                                              std::memory_order_acq_rel);
  }

  // Releases the lock, which must be held by the calling thread.
  void Release() {
    lock_word_.store(kUnlockedValue, std::memory_order_release);
  }

 private:
  // Lock value when spinlock is unlocked.
  static constexpr uint64_t kUnlockedValue = 0x0;
  // Lock value when spinlock is locked.
  static constexpr uint64_t kLockedValue = 0x1;

  std::atomic<uint64_t> lock_word_;
};

#endif  // ASYLO_PLATFORM_COMMON_SPIN_LOCK_H_
