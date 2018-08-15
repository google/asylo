/*
 *
 * Copyright 2017 Asylo authors
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

#include <enclave/enclave_syscalls.h>

#include <errno.h>
#include <stdlib.h>

#include "include/global_data.h"

namespace {

// Pointer to start of the heap.
void *heap_base = nullptr;

// Maximum size of the heap in bytes.
size_t heap_max_size = 0;

// Current size of the heap in bytes.
size_t heap_size = 0;

}  // namespace

extern "C" {

size_t g_peak_heap_used __attribute__((visibility("default"))) = 0;

int heap_init(void *_heap_base, size_t _heap_max_size, size_t _heap_min_size,
              int _is_edmm_supported) {
  heap_base = _heap_base;
  heap_max_size = _heap_max_size;
  // EDDM not supported so _heap_min_size and _is_edmm_supported are unused.
  return 0;
}

// sbrk implementation for SGX enclaves.
void *enclave_sbrk(int n) {
  if (!heap_base) {
    heap_init(&__ImageBase + g_global_data.heap_offset, g_global_data.heap_size,
              0, 0);
  }

  ssize_t new_heap_size = heap_size + n;
  if (heap_base == nullptr || new_heap_size < 0 ||
      new_heap_size > heap_max_size) {
    errno = ENOMEM;
    return reinterpret_cast<void *>(-1);
  }

  if (g_peak_heap_used < new_heap_size) {
    g_peak_heap_used = new_heap_size;
  }

  uintptr_t prev_heap_end = reinterpret_cast<uintptr_t>(heap_base) + heap_size;
  heap_size = new_heap_size;
  return reinterpret_cast<void *>(prev_heap_end);
}

}  //  extern "C"
