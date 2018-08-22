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

#include "asylo/platform/core/untrusted_mutex.h"

#include <cstdio>
#include <cstdlib>

#include "asylo/platform/arch/include/trusted/enclave_interface.h"
#include "asylo/platform/arch/include/trusted/host_calls.h"

namespace asylo {

// This file implements a mutex in untrusted shared memory using a Linux "Fast
// User-Space Mutex" or "futex." The algorithm here is taken from
// [Dre11]. Please see that paper for a more detailed discussion.
//
// [Dre11] Ulrich Drepper. Futexes are tricky. Technical Report FAT2011, Red
// Hat, Inc., Raleigh, NC, USA, November 2011.

namespace {

// A futex object is a 32-bit value in shared memory. In this implementation,
// the value of the futex distinguishes between three possible states:

constexpr int32_t kUnlocked = 0;  // The mutex is unlocked.

constexpr int32_t kHeld = 1;  // The futex is locked and zero threads are
                              // suspended waiting for futex_wake.

constexpr int32_t kQueued = 2;  // The futex is locked and there may be threads
                                // waiting on futex_wake.

constexpr int32_t kInvalidThread = 0;  // Invalid thread ID constant.

// Atomically compare the value at `location` to `expected` and, if-and-only-if
// they match, replace the value at `location` with `desired`. Returns the value
// stored `location` prior to the attempted exchange.
template <typename T>
inline T CompareAndSwap(T *location, T expected, T desired) {
  T previous = expected;
  __atomic_compare_exchange_n(location,
                              /*expected=*/&previous,
                              /*desired=*/desired,
                              /*weak=*/false,
                              /*success_memorder=*/__ATOMIC_SEQ_CST,
                              /*failure_memorder=*/__ATOMIC_SEQ_CST);
  return previous;
}

// Atomically decrements the value at `location`, returning the value at
// `location` prior to being decremented.
template <typename T>
inline T AtomicDecrement(T *location) {
  return __atomic_fetch_sub(location, 1, __ATOMIC_SEQ_CST);
}

// Sets the value at location to zero using __ATOMIC_RELEASE memory ordering.
template <typename T>
inline void AtomicRelease(T *location) {
  __atomic_clear(location, __ATOMIC_RELEASE);
}

// The size of an x86-64 cache line.
constexpr size_t kCacheLineSize = 64;

}  // namespace

UntrustedMutex::UntrustedMutex(bool is_recursive)
    : is_recursive_(is_recursive),
      owner_(kInvalidThread),
      recursive_lock_count_(0) {
  // Allocate and initialize a 32-bit futex object in shared memory, accessible
  // by the untrusted host kernel. Allocates a full cache line to avoid false
  // sharing with another object.
  //
  untrusted_futex_ =
      static_cast<int32_t *>(enc_untrusted_malloc(kCacheLineSize));

  // Initialize the futex as unlocked;
  *untrusted_futex_ = kUnlocked;
}

UntrustedMutex::~UntrustedMutex() { enc_untrusted_free(untrusted_futex_); }

void UntrustedMutex::Lock() {
  // Ensure the value of the shared futex word is valid.
  if (*untrusted_futex_ < kUnlocked || *untrusted_futex_ > kQueued) {
    enc_untrusted_puts("Invalid futex value in UntrustedMutex::Lock.");
    abort();
  }

  if (is_recursive_ && owner_ == enc_thread_self()) {
    recursive_lock_count_++;
    return;
  }

  // Attempt to atomically update the value of the futex from unlocked to locked
  // with no threads suspended in the kernel, storing the previous in
  // `futex_value`.
  int32_t futex_value = CompareAndSwap(untrusted_futex_, kUnlocked, kHeld);

  // If the value of the futex prior to the compare-and-swap was kUnlocked, then
  // the caller has successfully acquired the futex and it now stores the value
  // kHeld. Otherwise, suspend the thread by calling futex_wait.
  if (futex_value != kUnlocked) {
    do {
      // If necessary, update the futex value to reflect that the thread will
      // queue and a futex_wake is required. The kernel is assumed to implement
      // a fair wait queue.
      if (futex_value != kQueued) {
        futex_value = CompareAndSwap(untrusted_futex_, kHeld, kQueued);
      }

      // Unless another thread has released the futex already, suspend until the
      // thread are awoken by a call to futex_wait.
      enc_untrusted_sys_futex_wait(untrusted_futex_, kQueued);

      // After returning from futex_wait, try to obtain it again. On success,
      // futex_value will be set to kUnlocked and the loop is finished. Note
      // that it would not be correct to replace kUnlocked with kHeld because
      // there may be a thread waiting in the kernel.
      futex_value = CompareAndSwap(untrusted_futex_, kUnlocked, kQueued);
    } while (futex_value != kUnlocked);
  }

  owner_ = enc_thread_self();

  if (is_recursive_) {
    recursive_lock_count_++;
  }
}

bool UntrustedMutex::Owned() const { return owner_ == enc_thread_self(); }

bool UntrustedMutex::TryLock() {
  if (is_recursive_ && owner_ == enc_thread_self()) {
    recursive_lock_count_++;
    return true;
  }
  if (CompareAndSwap(untrusted_futex_, kUnlocked, kHeld) == kUnlocked) {
    owner_ = enc_thread_self();
    if (is_recursive_) {
      recursive_lock_count_ = 1;
    }
    return true;
  }
  return false;
}

void UntrustedMutex::Unlock() {
  // Ensure the value of the shared futex word is valid.
  if (*untrusted_futex_ < kUnlocked || *untrusted_futex_ > kQueued) {
    char buf[1024];
    snprintf(buf, sizeof(buf),
             "Invalid futex value in UntrustedMuted::Unlock: %i\n",
             *untrusted_futex_);
    enc_untrusted_puts(buf);
    abort();
  }

  // It is a fatal error to attempt to unlock a mutex the calling thread
  // does not own.
  if (owner_ != enc_thread_self()) {
    enc_untrusted_puts(
        "UntrustedMutex::Unlock called by thread that does not own it.");
    abort();
  }

  if (is_recursive_) {
    recursive_lock_count_--;
  }

  if (!is_recursive_ || recursive_lock_count_ == 0) {
    owner_ = kInvalidThread;

    // Atomically decrement the futex value, returning the value of
    // untrusted_futex_ prior to being decremented. Note that this will update
    // the state of the futex from kQueued to kHeld, irrespective of the fact
    // there may be multiple threads waiting in the kernel, which will then be
    // bumped up to kQueued when the awoken thread exits futex_wait. The details
    // of this protocol are discussed in more detail in [Dre11].
    int32_t futex_value = AtomicDecrement(untrusted_futex_);

    // If the previous value of untrusted_futex_ was kHeld rather than kQueued
    // then there are no threads suspended in the kernel and it is not necessary
    // to make a futex_wake system call. Otherwise, the lock value is set to
    // kUnlocked to allow another thread to acquire it and wake one of the
    // suspended threads.
    if (futex_value != kHeld) {
      AtomicRelease(untrusted_futex_);
      enc_untrusted_sys_futex_wake(untrusted_futex_);
    }
  }
}

}  // namespace asylo
