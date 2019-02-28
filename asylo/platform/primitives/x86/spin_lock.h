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

#ifndef ASYLO_PLATFORM_PRIMITIVES_X86_SPIN_LOCK_H_
#define ASYLO_PLATFORM_PRIMITIVES_X86_SPIN_LOCK_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

// This file declares a spin lock synchronization primitive for x86-64. This
// header may be included from runtime components written in C, for instance
// newlib and the Asylo pthreads headers, and must not make use of C++ features.

// Spin lock type, aligned to an x86-64 cache line to prevent false sharing.
typedef volatile uint32_t asylo_spinlock_t __attribute__((aligned(64)));

// Static initializer expression for an unlocked spin lock.
#define ASYLO_SPIN_LOCK_INITIALIZER 0

// Unlocks the spin lock referred to by lock. The behavior of unlocking a lock
// not held by the calling thread is undefined.
// The -Wunused-but-set-parameter warning is ignored below as the compiler
// wrongly flags |lock| as set but unused.
// Note that we only add a GCC pragma here as GCC pragmas are also supported
// by Clang for compatibility and the "-Wunused-but-set-parameter" warning is
// supported by both GCC and Clang.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-but-set-parameter"
inline void asylo_spin_unlock(asylo_spinlock_t *lock) {
  uint32_t kUnlocked = 0;
  __atomic_store(lock, &kUnlocked, __ATOMIC_RELEASE);
}
#pragma GCC diagnostic pop

// Unlocks the spin lock referred to by |lock|, returning true if the spin lock
// was acquired. The behavior of calling this routine on a lock the calling
// thread already holds is undefined.
inline bool asylo_spin_trylock(asylo_spinlock_t *lock) {
  uint32_t previous = 0;
  __atomic_compare_exchange_n(lock,
                              /*expected=*/&previous,
                              /*desired=*/1,
                              /*weak=*/false,
                              /*success_memorder=*/__ATOMIC_ACQUIRE,
                              /*failure_memorder=*/__ATOMIC_ACQUIRE);
  return previous == 0;
}

// Locks the spin lock referred to by |lock|. If the spin lock is currently
// locked by another thread, the calling thread spins, testing the lock until it
// becomes available. The behavior of calling this routine on a lock the calling
// thread already holds is undefined.
inline void asylo_spin_lock(asylo_spinlock_t *lock) {
  while (!asylo_spin_trylock(lock)) {
    while (*lock) {
      __builtin_ia32_pause();
    }
  }
}

#ifdef  __cplusplus
}
#endif  //  __cplusplus
#endif  // ASYLO_PLATFORM_PRIMITIVES_X86_SPIN_LOCK_H_
