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

#include "common/inc/internal/global_data.h"

extern "C" {

size_t g_peak_heap_used __attribute__((visibility("default"))) = 0;

// sbrk implementation for SGX enclaves.
void *enclave_sbrk(int n) {
  static size_t heap_used = 0;
  uintptr_t heap_base =
      reinterpret_cast<uintptr_t>(&__ImageBase) + g_global_data.heap_offset;

  ssize_t new_heap_used = heap_used + n;
  if (!heap_base || new_heap_used < 0 ||
      new_heap_used > g_global_data.heap_size) {
    errno = ENOMEM;
    return reinterpret_cast<void *>(-1);
  }

  if (g_peak_heap_used < new_heap_used) {
    g_peak_heap_used = new_heap_used;
  }

  uintptr_t prev_heap_end = heap_base + heap_used;
  heap_used = new_heap_used;
  return reinterpret_cast<void *>(prev_heap_end);
}

}  //  extern "C"
