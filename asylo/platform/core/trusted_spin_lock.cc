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

#include <cstdio>
#include <cstdlib>

#include "asylo/platform/primitives/trusted_primitives.h"

namespace asylo {
namespace {

// Aborts if the value of the |spin_lock| is invalid.
void ValidateSpinLock(uint32_t spin_lock) {
  if (spin_lock > TrustedSpinLock::kLocked) {
    char buf[1024];
    snprintf(buf, sizeof(buf),
             "Invalid spin lock value in TrustedSpinLock operation: %u\n",
             spin_lock);
    primitives::TrustedPrimitives::BestEffortAbort(buf);
  }
}

}  // namespace

void TrustedSpinLock::Lock() {
  while (!TryLock()) {
    enc_pause();
  }
}

bool TrustedSpinLock::Owned() const { return owner_ == enc_thread_self(); }

bool TrustedSpinLock::TryLock() {
  ValidateSpinLock(spin_lock_);

  if (is_recursive_ && owner_ == enc_thread_self()) {
    recursive_lock_count_++;
    return true;
  }

  if (spin_lock_ != kUnlocked) {
    return false;
  }

  if (CompareAndSwap(&spin_lock_, kUnlocked, kLocked) == kUnlocked) {
    owner_ = enc_thread_self();
    if (is_recursive_) {
      recursive_lock_count_ = 1;
    }

    return true;
  }
  return false;
}

void TrustedSpinLock::Unlock() {
  ValidateSpinLock(spin_lock_);

  // It is a fatal error to attempt to unlock a spin lock the calling thread
  // does not own.
  if (owner_ != enc_thread_self()) {
    primitives::TrustedPrimitives::DebugPuts(
        "TrustedSpinLock::Unlock called by thread that does not own it.");
    return;
  }

  if (is_recursive_) {
    recursive_lock_count_--;
  }

  if (!is_recursive_ || recursive_lock_count_ == 0) {
    owner_ = kInvalidThread;
    AtomicRelease(&spin_lock_);
  }
}

}  // namespace asylo
