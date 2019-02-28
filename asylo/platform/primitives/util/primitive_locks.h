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

#ifndef ASYLO_PLATFORM_PRIMITIVES_UTIL_PRIMITIVE_LOCKS_H_
#define ASYLO_PLATFORM_PRIMITIVES_UTIL_PRIMITIVE_LOCKS_H_

#include "asylo/platform/primitives/x86/spin_lock.h"

namespace asylo {
namespace primitives {

// An RAII guard for a primitive spin lock, acquiring a lock at the time it is
// constructed and holding it for the life time of the SpinLockGuard object.
class SpinLockGuard {
 public:
  explicit SpinLockGuard(asylo_spinlock_t *lock) : lock_(lock) {
    asylo_spin_lock(lock_);
  }
  ~SpinLockGuard() { asylo_spin_unlock(lock_); }

 private:
  asylo_spinlock_t *lock_;
};

}  // namespace primitives
}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_UTIL_PRIMITIVE_LOCKS_H_
