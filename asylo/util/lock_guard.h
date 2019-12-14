/*
 *
 * Copyright 2019 Asylo authors
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

#ifndef ASYLO_UTIL_LOCK_GUARD_H_
#define ASYLO_UTIL_LOCK_GUARD_H_

#include <type_traits>

#include "absl/base/thread_annotations.h"
#include "asylo/util/function_traits.h"

// Utility class for RAII locking. Works with any lock type which supports
// Lock() and Unlock() methods. This assumes that the type given as the template
// argument will work like a traditional mutual exclusion lock, similar to
// absl::Mutex.
template <class LockT>
class ABSL_SCOPED_LOCKABLE LockGuard {
 public:
  explicit LockGuard(LockT *lock) ABSL_EXCLUSIVE_LOCK_FUNCTION(lock)
      : lock_(lock) {
    static_assert(FunctionTraits<decltype(
                      &LockT::Lock)>::template CheckReturnType<void>::value,
                  "Lock() method must have a void return type");
    static_assert(FunctionTraits<decltype(
                      &LockT::Unlock)>::template CheckReturnType<void>::value,
                  "Unlock() method must have a void return type");
    lock->Lock();
  }
  LockGuard(LockGuard &&other) = delete;
  LockGuard &operator=(LockGuard &&other) = delete;
  LockGuard(const LockGuard &) = delete;
  LockGuard &operator=(const LockGuard &) = delete;
  ~LockGuard() ABSL_UNLOCK_FUNCTION() { lock_->Unlock(); }

 private:
  LockT *const lock_;
};

#ifdef __cpp_deduction_guides
// Provide explicit direction to infer the template parameter to the lock guard
// from the argument type to the constructor.
template <class LockT>
LockGuard(LockT) -> LockGuard<LockT>;
#endif

#endif  // ASYLO_UTIL_LOCK_GUARD_H_
