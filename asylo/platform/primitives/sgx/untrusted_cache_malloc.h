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

#ifndef ASYLO_PLATFORM_PRIMITIVES_SGX_UNTRUSTED_CACHE_MALLOC_H_
#define ASYLO_PLATFORM_PRIMITIVES_SGX_UNTRUSTED_CACHE_MALLOC_H_

#include <cstddef>
#include <stack>
#include <unordered_set>

#include "asylo/platform/core/trusted_spin_lock.h"
#include "asylo/platform/primitives/sgx/trusted_sgx.h"
#include "asylo/platform/primitives/trusted_primitives.h"

namespace asylo {

// This class is responsible for allocating memory on the untrusted heap. This
// class optimizes the common case of small allocations on backends where the
// trusted and untrusted application partitions share an address space.
//
// For smaller allocations, the implementation allocates memory from a buffer
// pool maintained by the class. The buffer pool is implemented as a stack
// of untrusted buffers.
//
// This class is initialized in the trusted space and manages the buffers
// in untrusted memory 1) assigning buffers to threads requesting memory and
// 2) pushing back buffers to the pool (for reuse) when they are requested to
// be freed.
class UntrustedCacheMalloc {
 public:
  UntrustedCacheMalloc(UntrustedCacheMalloc const &) = delete;
  UntrustedCacheMalloc &operator=(UntrustedCacheMalloc const &) = delete;

  // The destructor frees all buffers in the buffer pool and the free list.
  ~UntrustedCacheMalloc();

  // Returns the UntrustedCacheMalloc singleton instance.
  static UntrustedCacheMalloc *Instance();

  // Allocates memory on the untrusted heap. This function never returns
  // nullptr. Instead of returning nullptr, it will abort in the following
  // cases:
  //   * If the memory allocation fails
  //   * If the host call fails for any reason (this may be backend-specific)
  void *Malloc(size_t size);

  // Releases memory on the untrusted heap.
  void Free(void *buffer);

 private:
  struct FreeList {
    primitives::UntrustedUniquePtr<void *> buffers;
    int count;
  };

  TrustedSpinLock lock_;

  // Number of entries added to the buffer pool when it's depleted.
  static constexpr size_t kPoolIncrement = 1024;

  // Size of a buffer pool entry in bytes.
  static constexpr size_t kPoolEntrySize = 4096;

  // Maximum entries in the free list. When this limit is reached, all memory
  // held by the pointers in the free list is freed.
  static constexpr size_t kFreeListCapacity = 1024;

  // Defaults to false. Set to true when the singleton class object is
  // destructed. The class will internally route all subsequent calls for memory
  // (de)allocation to the native malloc/free implementation.
  static bool is_destroyed_;

  UntrustedCacheMalloc();

  // Returns a buffer from the pool. If no buffers are available in the pool,
  // this function is responsible for adding new buffers to the pool before
  // returning the buffer.
  void *GetBuffer();

  // Pushes |buffer| to the free list. If the free list capacity is reached,
  // this function is also responsible for first emptying the free list by
  // freeing all buffer pointers stored in the list before pushing |buffer| to
  // the list.
  void PushToFreeList(void *buffer);

  // List of pointers to untrusted buffers which need to be freed.
  std::unique_ptr<FreeList> free_list_;

  // Pool of pointers to free buffers allocated on the untrusted heap. The
  // buffer pool is implemented as a stack. This allows for a warmer cache as a
  // recently returned buffer which is hot in the cache is the first to get
  // reassigned to a thread requesting a buffer.
  std::stack<void *> buffer_pool_;

  // Set of buffers returned to and owned by buffer pool clients.
  std::unordered_set<void *> busy_buffers_;
};

}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_SGX_UNTRUSTED_CACHE_MALLOC_H_
