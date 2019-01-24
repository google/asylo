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
#include "asylo/platform/core/untrusted_cache_malloc.h"

#include <cstdlib>
#include <memory>

#include "absl/memory/memory.h"
#include "asylo/platform/arch/include/trusted/enclave_interface.h"

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

bool UntrustedCacheMalloc::is_destroyed = false;

UntrustedCacheMalloc *UntrustedCacheMalloc::Instance() {
  static UntrustedCacheMalloc *instance = new UntrustedCacheMalloc();
  return instance;
}

UntrustedCacheMalloc::UntrustedCacheMalloc() {
  if (is_destroyed) {
    return;
  }
  // Initialize a free list object in the trusted heap. The free list object
  // stores an array of buffers stored in the untrusted heap.
  free_list_ = absl::make_unique<FreeList>();
  free_list_->buffers.reset(reinterpret_cast<void**>(enc_untrusted_malloc(
      sizeof(void*) * kFreeListCapacity)));
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
    enc_untrusted_deallocate_free_list(free_list_->buffers.get(),
                                       free_list_->count);
  }
  is_destroyed = true;
}

void *UntrustedCacheMalloc::GetBuffer() {
  void **buffers;
  void *buffer;
  bool is_pool_empty;

  {
    ScopedSpinLock spin_lock(&lock_);
    is_pool_empty = buffer_pool_.empty();
    if (is_pool_empty) {
      buffers = enc_untrusted_allocate_buffers(kPoolIncrement, kPoolEntrySize);
      for (int i = 0; i < kPoolIncrement; i++) {
        if (!buffers[i]
            || !enc_is_outside_enclave(buffers[i], kPoolEntrySize)) {
          abort();
        }
        buffer_pool_.push(buffers[i]);
      }
    }
    buffer = buffer_pool_.top();
    buffer_pool_.pop();
    busy_buffers_.insert(buffer);
  }

  if (is_pool_empty) {
    // Free memory held by the array of buffer pointers returned by
    // enc_untrusted_allocate_buffers.
    Free(buffers);
  }
  return buffer;
}

void *UntrustedCacheMalloc::Malloc(size_t size) {
  if (is_destroyed || (size > kPoolEntrySize)) {
    return enc_untrusted_malloc(size);
  }
  return GetBuffer();
}

void UntrustedCacheMalloc::PushToFreeList(void *buffer) {
  free_list_->buffers.get()[free_list_->count] = buffer;
  free_list_->count++;

  if (free_list_->count == kFreeListCapacity) {
    enc_untrusted_deallocate_free_list(free_list_->buffers.get(),
                                       kFreeListCapacity);
    free_list_->count = 0;
  }
}

void UntrustedCacheMalloc::Free(void *buffer) {
  if (is_destroyed) {
    enc_untrusted_free(buffer);
    return;
  }
  ScopedSpinLock spin_lock(&lock_);

  // Add the buffer to the free list if it was not allocated from the buffer
  // pool and was allocated via the enc_untrusted_malloc host call. If the
  // buffer was allocated from the buffer pool push it back to the pool.
  if (busy_buffers_.find(buffer) == busy_buffers_.end()) {
    PushToFreeList(buffer);
    return;
  }
  busy_buffers_.erase(buffer);
  buffer_pool_.push(buffer);
}

}  // namespace asylo
