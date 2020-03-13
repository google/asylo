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

#ifndef ASYLO_PLATFORM_CORE_TRUSTED_MUTEX_H_
#define ASYLO_PLATFORM_CORE_TRUSTED_MUTEX_H_

#include "asylo/platform/core/trusted_spin_lock.h"

namespace asylo {

// A mutex implementation depending on untrusted resources guarded by a trusted
// spin lock.
//
// A TrustedMutex object is a thread-synchronization primitive that depends
// on resources outside the enclave for efficiency, and uses a spin lock inside
// the enclave for security.
class TrustedMutex {
 public:
  // Initializes an unlocked mutex. If |is_recursive| is true, then the mutex is
  // a recursive lock and may 1) be locked more than once by the caller and 2)
  // does not become free until it is unlocked a corresponding number of times.
  // This optional functionality is provided for compatibility with
  // pthread_mutex.
  explicit TrustedMutex(bool is_recursive);

  ~TrustedMutex();

  // If this lock is not already held, block until the calling thread is able to
  // acquire it. If configured as a recursive lock, an TrustedMutex may be
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

 private:
  // The source of truth for locking.
  TrustedSpinLock trusted_spin_lock_;
  // A pointer to an untrusted wait queue maintained by the OS. Likely
  // implemented via the futex syscall, with the pointer to the 4 byte
  // futex word.
  int32_t *const wait_queue_;
  // By keeping track of the number of threads asleep on the wait
  // queue, we can avoid an expensive wake operation in some common
  // cases.
  volatile uint32_t number_threads_asleep_;
};

}  // namespace asylo

#endif  // ASYLO_PLATFORM_CORE_TRUSTED_MUTEX_H_
