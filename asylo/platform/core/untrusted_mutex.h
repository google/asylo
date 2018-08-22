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

#ifndef ASYLO_PLATFORM_CORE_UNTRUSTED_MUTEX_H_
#define ASYLO_PLATFORM_CORE_UNTRUSTED_MUTEX_H_

#include <cstdint>

namespace asylo {

// A mutex implementation depending on untrusted resources.
//
// An UntrustedMutex object is a thread synchronization primitive that depends
// on resources outside the enclave. For example, the implementation may make
// calls that depend on the cooperation of the host kernel thread scheduler.
//
// While coordinating with the kernel is essential for efficient concurrency,
// users must assume an adversarial implementation of the kernel interfaces.  If
// a misbehaving mutex may affect the correctness or security of the trusted
// application then this must be used in combination with an trusted mutex.
class UntrustedMutex {
 public:
  // Initializes an unlocked mutex. If |is_recursive| is true, then the mutex is
  // a recursive lock and may 1) be locked more than once by the caller and 2)
  // does not become free until it is unlocked a corresponding number of times.
  // This optional functionality is provided for compatibility with
  // pthread_mutex.
  explicit UntrustedMutex(bool is_recursive);

  ~UntrustedMutex();

  // If this lock is not already held, block until the calling thread is able to
  // acquire it. If configured as a recursive lock, an UntrustedMutex may be
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
  // A synchronization value in untrusted memory, aligned to a cache line.
  int32_t *untrusted_futex_;

  // True if this mutex has been configured as a recursive lock.
  bool is_recursive_;

  // The enc_thread_self() value of the thread that owns the lock, or zero if
  // the mutex is unlocked.
  uint64_t owner_;

  // The number of times this lock has been locked recursively.
  uint64_t recursive_lock_count_;
};

}  // namespace asylo

#endif  // ASYLO_PLATFORM_CORE_UNTRUSTED_MUTEX_H_
