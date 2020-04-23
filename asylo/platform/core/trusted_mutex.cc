/*
 *
 * Copyright 2020 Asylo authors
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

#include "asylo/platform/core/trusted_mutex.h"

#include "asylo/platform/core/atomic.h"
#include "asylo/platform/core/trusted_spin_lock.h"
#include "asylo/platform/host_call/trusted/host_calls.h"

namespace asylo {

namespace {
// Value below was roughly experimentally determined using test/lock_test on SGX
// hardware.
static constexpr int64_t kLockAttemptThreshhold = 10000;
}  // namespace

TrustedMutex::TrustedMutex(bool is_recursive = false)
    : trusted_spin_lock_(is_recursive),
      wait_queue_(enc_untrusted_create_wait_queue()),
      number_threads_asleep_(0) {
  // ensure that waiting is currently disabled
  enc_untrusted_disable_waiting(wait_queue_);
}

void TrustedMutex::Lock() {
  while (true) {
    for (int i = 0; i < kLockAttemptThreshhold; i++) {
      if (TryLock()) {
        return;
      }
      enc_pause();
    }
    // This increment and decrement can be relaxed, as the thread
    // count doesn't serve as a lock word for any other data.
    AtomicIncrement(&number_threads_asleep_, std::memory_order_relaxed);
    enc_untrusted_thread_wait(wait_queue_);
    AtomicDecrement(&number_threads_asleep_, std::memory_order_relaxed);
  }
}

bool TrustedMutex::Owned() const { return trusted_spin_lock_.Owned(); }

bool TrustedMutex::TryLock() {
  if (trusted_spin_lock_.TryLock()) {
    // Lock is acquired, allow other threads to wait.
    // No need to enable waiting unless lock is changing states from
    // unlocked to locked.
    if (trusted_spin_lock_.LockDepthIsOne()) {
      enc_untrusted_enable_waiting(wait_queue_);
    }
    return true;
  }
  return false;
}

void TrustedMutex::Unlock() {
  // Make sure to do no extra work if this is a nested recursive
  // unlock, which won't actually leave the lock unlocked.
  bool getting_unlocked = trusted_spin_lock_.LockDepthIsOne();
  if (getting_unlocked) {
    // Lock is now unlocked, disable waiting
    enc_untrusted_disable_waiting(wait_queue_);
  }
  trusted_spin_lock_.Unlock();
  // While it would be safe to notify the queue unconditionally, it
  // requires an enclave exit, which is expensive. In practice, we
  // only need to wake up another thread if the lock has changed state
  // to Unlocked, and there is a thread waiting on the queue.
  if (getting_unlocked && number_threads_asleep_ > 0) {
    enc_untrusted_notify(wait_queue_);
  }
}

TrustedMutex::~TrustedMutex() { enc_untrusted_destroy_wait_queue(wait_queue_); }

}  // namespace asylo
