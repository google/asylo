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

#include "asylo/platform/core/trusted_spin_lock.h"

#include <atomic>
#include <cstdio>
#include <cstdlib>

#include "asylo/platform/primitives/trusted_primitives.h"

namespace asylo {

void TrustedSpinLock::Lock() {
  while (!TryLock()) {
    enc_pause();
  }
}

bool TrustedSpinLock::Owned() const { return owner_ == enc_thread_self(); }

bool TrustedSpinLock::TryLock() {
  if (is_recursive_ && owner_ == enc_thread_self()) {
    recursive_lock_count_++;
    return true;
  }

  // This read of spin_lock_ does not need any atomicity. There are 3
  // cases to consider: 1) this thread holds the lock, 2) another
  // thread holds the lock, or 3) no thread holds the lock.
  //
  // 1) If we hold the lock, this load will always give the correct
  // value, since no other thread will store to this location while we
  // hold the lock.
  //
  // 2) If another thread holds the lock, we could get any value from
  // the read, either kLocked or kUnlocked. It is likely that we'll
  // read kLocked, which will give us a fast path to return false. If
  // we incorrectly read kUnlocked, we'll proceed into the correctly
  // synchronized compare and swap operation, which is slower but
  // correct.
  //
  // 3) If no one holds the lock, we could get any value from the
  // read. If we correctly read kUnlocked, we'll proceed to try and
  // acquire the lock. If we incorrectly read kLocked, TryLock will
  // spuriously fail, which is safe and correct.
  if (spin_lock_ != kUnlocked) {
    return false;
  }

  if (AtomicExchange(&spin_lock_, kLocked, std::memory_order_acquire) ==
      kUnlocked) {
    owner_ = enc_thread_self();
    recursive_lock_count_ = 1;

    return true;
  }
  return false;
}

void TrustedSpinLock::Unlock() {
  // It is a fatal error to attempt to unlock a spin lock the calling thread
  // does not own.
  if (owner_ != enc_thread_self()) {
    primitives::TrustedPrimitives::DebugPuts(
        "TrustedSpinLock::Unlock called by thread that does not own it.");
    return;
  }

  recursive_lock_count_--;
  if (recursive_lock_count_ == 0) {
    owner_ = kInvalidThread;
    AtomicClear(&spin_lock_, std::memory_order_release);
  }
}

bool TrustedSpinLock::LockDepthIsOne() { return recursive_lock_count_ == 1; }

}  // namespace asylo
