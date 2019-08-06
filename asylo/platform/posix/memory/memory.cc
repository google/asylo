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

#include "asylo/platform/posix/memory/memory.h"

#include <malloc.h>
#include <stdint.h>
#include <stdlib.h>

#include <cstddef>

extern void set_malloc_hook(void*(*hook)(size_t, void *), void *);
extern void set_realloc_hook(void*(*hook)(void *, size_t, void *), void *);
extern void set_free_hook(void(*hook)(void *, void *), void *);

namespace {

// The next available address in the switched heap. It's set to the base address
// of the switched heap when heap_switch is called, and moving forward after
// each memory allocation on the switched heap.
uint8_t *switched_heap_next = nullptr;

// The bytes left to be allocated on the switched heap. It's set to the total
// size of the switched heap when heap_switch is called, and is reduced in each
// memory allocation. New malloc/realloc on switched heap will fail if the
// requested size is larger than the remaining size.
size_t switched_heap_remaining = 0;

// Allocate memory on an address space provided by the user.
// This function is not thread-safe. This should only be used by fork during
// snapshotting/restoring while other threads are not allowed to enter the
// enclave.
void *AllocateMemoryOnSwitchedHeap(size_t size, void *pool) {
  // Align the memory address.
  size_t align = alignof(std::max_align_t);
  int shift =
      (align - (reinterpret_cast<uintptr_t>(switched_heap_next) % align)) %
      align;

  size += shift;
  if (!switched_heap_next || switched_heap_remaining < size) {
    return nullptr;
  }

  void *ret = switched_heap_next + shift;
  switched_heap_next += size;
  switched_heap_remaining -= size;

  return ret;
}

void *MallocHook(size_t size, void *pool) {
  return AllocateMemoryOnSwitchedHeap(size, pool);
}

// realloc() is doing exactly the same thing as malloc() on switched heap, since
// free simply returns.
void *ReallocHook(void *ptr, size_t size, void *pool) {
  return AllocateMemoryOnSwitchedHeap(size, pool);
}

// Free does nothing on the switched heap. User should take caution to avoid
// mixing use of regular malloc/free with the switched malloc/heap.
void FreeHook(void *address, void *pool) {}

}  // namespace

void *GetSwitchedHeapNext() { return switched_heap_next; }

size_t GetSwitchedHeapRemaining() { return switched_heap_remaining; }

// This function is not thread-safe.
void heap_switch(void *base, size_t size) {
  if (base && size > 0) {
    switched_heap_next = static_cast<uint8_t *>(base);
    switched_heap_remaining = size;
    set_malloc_hook(&MallocHook, /*pool=*/nullptr);
    set_realloc_hook(&ReallocHook, /*pool=*/nullptr);
    set_free_hook(&FreeHook, /*pool=*/nullptr);
  } else {
    switched_heap_next = nullptr;
    switched_heap_remaining = 0;
    set_malloc_hook(/*hook=*/nullptr, /*pool=*/nullptr);
    set_realloc_hook(/*hook=*/nullptr, /*pool=*/nullptr);
    set_free_hook(/*hook=*/nullptr, /*pool=*/nullptr);
  }
}
