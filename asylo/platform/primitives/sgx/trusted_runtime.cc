/*
 *
 * Copyright 2019 Asylo authors
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

#include "asylo/platform/primitives/trusted_runtime.h"

#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>

#include "asylo/platform/primitives/sgx/generated_bridge_t.h"
#include "include/sgx_thread.h"
#include "include/sgx_trts.h"

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
void *enclave_sbrk(intptr_t increment) {
  ssize_t new_heap_size = heap_size + increment;
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

void enc_exit(int rc) {
  ocall_enc_untrusted__exit(rc);
}

void enc_update_pthread_info(void *pthread_info) {
  if (pthread_info) {
    auto thread_data =
        reinterpret_cast<struct __pthread_info *>(enc_thread_self());
    *thread_data = *reinterpret_cast<struct __pthread_info *>(pthread_info);
  }
}

// The SGX SDK function sgx_thread_self() returns nullptr during early
// initialization. To return a non-zero, distinct value for each thread and
// satisfy the specification of enc_thread_self(), return the address of a
// thread-local variable instead. Since each thread is allocated a distinct
// instance of this variable, and all instances are in the same address space,
// this guarantees a distinct non-zero value is provisioned to each thread.
uint64_t enc_thread_self() {
  static thread_local struct __pthread_info thread_identity = {0, nullptr, 0, 0,
                                                               nullptr};
  return reinterpret_cast<uint64_t>(&thread_identity);
}

void enc_block_entries() { sgx_block_entries(); }

void enc_unblock_entries() { sgx_unblock_entries(); }

void enc_reject_entries() { sgx_reject_entries(); }

void enc_get_memory_layout(struct EnclaveMemoryLayout *enclave_memory_layout) {
  if (!enclave_memory_layout) return;
  struct SgxMemoryLayout memory_layout;
  sgx_memory_layout(&memory_layout);
  enclave_memory_layout->base = memory_layout.base;
  enclave_memory_layout->size = memory_layout.size;
  enclave_memory_layout->data_base = memory_layout.data_base;
  enclave_memory_layout->data_size = memory_layout.data_size;
  enclave_memory_layout->bss_base = memory_layout.bss_base;
  enclave_memory_layout->bss_size = memory_layout.bss_size;
  enclave_memory_layout->heap_base = memory_layout.heap_base;
  enclave_memory_layout->heap_size = memory_layout.heap_size;
  enclave_memory_layout->thread_base = memory_layout.thread_base;
  enclave_memory_layout->thread_size = memory_layout.thread_size;
  enclave_memory_layout->stack_base = memory_layout.stack_base;
  enclave_memory_layout->stack_limit = memory_layout.stack_limit;
  enclave_memory_layout->reserved_data_base = memory_layout.reserved_data_base;
  enclave_memory_layout->reserved_data_size = memory_layout.reserved_data_size;
  enclave_memory_layout->reserved_bss_base = memory_layout.reserved_bss_base;
  enclave_memory_layout->reserved_bss_size = memory_layout.reserved_bss_size;
  enclave_memory_layout->reserved_heap_base = memory_layout.reserved_heap_base;
  enclave_memory_layout->reserved_heap_size = memory_layout.reserved_heap_size;
}

int active_entry_count() { return sgx_active_entry_count(); }

int active_exit_count() { return sgx_active_exit_count(); }

int blocked_entry_count() { return sgx_blocked_entry_count(); }

}  //  extern "C"
