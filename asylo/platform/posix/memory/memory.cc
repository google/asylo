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

namespace {

uint8_t *switched_heap_base = nullptr;
size_t switched_heap_bytes_left = 0;

// Allocate memory on an address space provided by the user.
// This function is not thread-safe. This should only be used by fork during
// snapshotting/restoring while other threads are not allowed to enter the
// enclave.
void *MallocHook(size_t size, void *pool) {
  if (!switched_heap_base || switched_heap_bytes_left < size) {
    return nullptr;
  }
  void *ret = switched_heap_base;
  switched_heap_base += size;
  switched_heap_bytes_left -= size;
  return ret;
}

// Free does nothing on the switched heap. User should take caution to avoid
// mixing use of regular malloc/free with the switched malloc/heap.
void FreeHook(void *address, void *pool) { return; }

}  // namespace

// This function is not thread-safe.
void heap_switch(void *base, size_t size) {
  if (base && size > 0) {
    switched_heap_base = static_cast<uint8_t *>(base);
    switched_heap_bytes_left = size;
    set_malloc_hook(&MallocHook, /*pool=*/nullptr);
    set_free_hook(&FreeHook, /*pool=*/nullptr);
  } else {
    switched_heap_base = nullptr;
    switched_heap_bytes_left = 0;
    set_malloc_hook(/*malloc_hook=*/nullptr, /*pool=*/nullptr);
    set_free_hook(/*free_hook=*/nullptr, /*pool=*/nullptr);
  }
}
