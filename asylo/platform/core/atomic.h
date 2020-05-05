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

#ifndef ASYLO_PLATFORM_CORE_ATOMIC_H_
#define ASYLO_PLATFORM_CORE_ATOMIC_H_

#include <atomic>
#include <cstdlib>

namespace asylo {
namespace internal {

inline int GetGCCMemOrder(std::memory_order order) {
  switch (order) {
    case std::memory_order_relaxed:
      return __ATOMIC_RELAXED;
    case std::memory_order_consume:
      return __ATOMIC_CONSUME;
    case std::memory_order_acquire:
      return __ATOMIC_ACQUIRE;
    case std::memory_order_release:
      return __ATOMIC_RELEASE;
    case std::memory_order_acq_rel:
      return __ATOMIC_ACQ_REL;
    case std::memory_order_seq_cst:
      return __ATOMIC_SEQ_CST;
  }
  return __ATOMIC_SEQ_CST;
}

}  // namespace internal

// Atomically exchanges value at `location` with `desired`,
// returning value originally at `location`.
template <typename T>
inline T AtomicExchange(
    volatile T *location, T desired,
    std::memory_order memorder = std::memory_order_seq_cst) {
  return __atomic_exchange_n(location, desired,
                             internal::GetGCCMemOrder(memorder));
}

// Atomically compare value at `location` with `expected`, and equal, exchange
// value at `location` with `desired`.
template <typename T>
inline bool AtomicCompareExchange(
    volatile T *location, T *expected, T desired, bool weak,
    std::memory_order success_memorder = std::memory_order_seq_cst,
    std::memory_order failure_memorder = std::memory_order_seq_cst) {
  return __atomic_compare_exchange_n(
      location, expected, desired, weak,
      internal::GetGCCMemOrder(success_memorder),
      internal::GetGCCMemOrder(failure_memorder));
}

// Atomically increments the value at `location`, returning the value at
// `location` prior to being incremented.
template <typename T>
inline T AtomicIncrement(volatile T *location, std::memory_order memorder =
                                                   std::memory_order_seq_cst) {
  return __atomic_fetch_add(location, 1, internal::GetGCCMemOrder(memorder));
}

// Atomically decrements the value at `location`, returning the value at
// `location` prior to being decremented.
template <typename T>
inline T AtomicDecrement(volatile T *location, std::memory_order memorder =
                                                   std::memory_order_seq_cst) {
  return __atomic_fetch_sub(location, 1, internal::GetGCCMemOrder(memorder));
}

// Sets the value at location to zero.
template <typename T>
inline void AtomicClear(volatile T *location, std::memory_order memorder =
                                                  std::memory_order_seq_cst) {
  __atomic_clear(location, internal::GetGCCMemOrder(memorder));
}

// Sets the value at `location` to `value`.
template <typename T>
inline void AtomicStore(
    volatile T *location, T value,
    std::memory_order memorder = std::memory_order_seq_cst) {
  __atomic_store_n(location, value, internal::GetGCCMemOrder(memorder));
}

// The size of an x86-64 cache line.
//
constexpr size_t kCacheLineSize = 64;

}  // namespace asylo

#endif  // ASYLO_PLATFORM_CORE_ATOMIC_H_
