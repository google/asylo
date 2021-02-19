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
#include "asylo/platform/primitives/sgx/untrusted_cache_malloc.h"

#include <cstdlib>
#include <memory>

#include "absl/memory/memory.h"
#include "asylo/platform/core/trusted_spin_lock.h"
#include "asylo/platform/posix/memory/memory.h"
#include "asylo/platform/primitives/trusted_primitives.h"
#include "asylo/platform/primitives/trusted_runtime.h"
#include "asylo/util/lock_guard.h"

extern "C" {
// Expose the untrusted memory cache via a C API. This interface allows C code
// to depend on the global memory pool singleton.

void *untrusted_cache_malloc(size_t size) {
  asylo::UntrustedCacheMalloc *instance =
      asylo::UntrustedCacheMalloc::Instance();
  return instance->Malloc(size);
}

void untrusted_cache_free(void *buffer) {
  asylo::UntrustedCacheMalloc *instance =
      asylo::UntrustedCacheMalloc::Instance();
  instance->Free(buffer);
}

}  // extern "C"

namespace asylo {

using primitives::TrustedPrimitives;

bool UntrustedCacheMalloc::is_destroyed_ = false;

UntrustedCacheMalloc *UntrustedCacheMalloc::Instance() {
  static TrustedSpinLock lock(/*is_recursive=*/false);
  static UntrustedCacheMalloc *instance = nullptr;
  if (instance == nullptr) {
    LockGuard guard(&lock);
    if (instance == nullptr) {
      instance = new UntrustedCacheMalloc();
    }
  }
  return instance;
}

UntrustedCacheMalloc::UntrustedCacheMalloc() : lock_(/*is_recursive=*/true) {
  if (is_destroyed_) {
    return;
  }
  // Initialize a free list object in the trusted heap. The free list object
  // stores an array of buffers stored in the untrusted heap.
  free_list_ = absl::make_unique<FreeList>();
  free_list_->buffers.reset(reinterpret_cast<void **>(
      primitives::TrustedPrimitives::UntrustedLocalAlloc(sizeof(void *) *
                                                         kFreeListCapacity)));
  free_list_->count = 0;
}

UntrustedCacheMalloc::~UntrustedCacheMalloc() {
  while (!buffer_pool_.empty()) {
    PushToFreeList(buffer_pool_.top());
    buffer_pool_.pop();
  }

  // Free remaining elements in the free_list_.
  // The free_list_ object and the struct FreeList member buffers are destroyed
  // when the unique pointers referencing them go out of scope.
  if (free_list_->count > 0) {
    primitives::DeAllocateUntrustedBuffers(free_list_->buffers.get(),
                                           free_list_->count);
  }
  is_destroyed_ = true;
}

void *UntrustedCacheMalloc::GetBuffer() {
  void **buffers = nullptr;
  void *buffer;
  bool is_pool_empty;

  {
    LockGuard spin_lock(&lock_);
    is_pool_empty = buffer_pool_.empty();
    if (is_pool_empty) {
      buffers =
          primitives::AllocateUntrustedBuffers(kPoolIncrement, kPoolEntrySize);
      for (int i = 0; i < kPoolIncrement; i++) {
        void *buf = buffers[i];
        if (!buf || !TrustedPrimitives::IsOutsideEnclave(buf, kPoolEntrySize)) {
          TrustedPrimitives::BestEffortAbort(
              "Cached buffer is not outside the enclave");
        }
        buffer_pool_.push(buf);
      }
    }
    buffer = buffer_pool_.top();
    buffer_pool_.pop();
    busy_buffers_.insert(buffer);
  }

  if (is_pool_empty) {
    // Free memory held by the array of buffer pointers returned by
    // AllocateUntrustedBuffers.
    Free(buffers);
  }
  return buffer;
}

void *UntrustedCacheMalloc::Malloc(size_t size) {
  // Don't access UnturstedCacheMalloc if not running on normal heap, otherwise
  // it will cause error when UntrustedCacheMalloc tries to free the memory on
  // the normal heap.
  if (is_destroyed_ || (size > kPoolEntrySize) || GetSwitchedHeapNext()) {
    return primitives::TrustedPrimitives::UntrustedLocalAlloc(size);
  }
  return GetBuffer();
}

void UntrustedCacheMalloc::PushToFreeList(void *buffer) {
  free_list_->buffers.get()[free_list_->count] = buffer;
  free_list_->count++;

  if (free_list_->count == kFreeListCapacity) {
    primitives::DeAllocateUntrustedBuffers(free_list_->buffers.get(),
                                           kFreeListCapacity);
    free_list_->count = 0;
  }
}

void UntrustedCacheMalloc::Free(void *buffer) {
  if (is_destroyed_ || GetSwitchedHeapNext()) {
    primitives::TrustedPrimitives::UntrustedLocalFree(buffer);
    return;
  }
  LockGuard spin_lock(&lock_);

  // Add the buffer to the free list if it was not allocated from the buffer
  // pool and was allocated via UntrustedLocalAlloc. If the
  // buffer was allocated from the buffer pool push it back to the pool.
  if (busy_buffers_.find(buffer) == busy_buffers_.end()) {
    PushToFreeList(buffer);
    return;
  }
  busy_buffers_.erase(buffer);
  buffer_pool_.push(buffer);
}

}  // namespace asylo
