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

#include "asylo/platform/arch/include/trusted/enclave_interface.h"

#include "include/sgx_thread.h"
#include "include/sgx_trts.h"

#ifdef __cplusplus
extern "C" {
#endif

// The SGX SDK function sgx_thread_self() returns nullptr during early
// initialization. To return a non-zero, distinct value for each thread and
// satisfy the specification of enc_thread_self(), return the address of a
// thread-local variable instead. Since each thread is allocated a distinct
// instance of this variable, and all instances are in the same address space,
// this guarantees a distinct non-zero value is provisioned to each thread.
uint64_t enc_thread_self() {
  static thread_local int thread_identity;
  return reinterpret_cast<uint64_t>(&thread_identity);
}

bool enc_is_within_enclave(void const* address, size_t size) {
  return sgx_is_within_enclave(address, size) == 1;
}

bool enc_is_outside_enclave(void const* address, size_t size) {
  return sgx_is_outside_enclave(address, size) == 1;
}

void enc_get_memory_layout(struct EnclaveMemoryLayout* enclave_memory_layout) {
  if (!enclave_memory_layout) return;
  struct SgxMemoryLayout memory_layout;
  sgx_memory_layout(&memory_layout);
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
  enclave_memory_layout->reserved_base = memory_layout.reserved_base;
  enclave_memory_layout->reserved_size = memory_layout.reserved_size;
}

#ifdef __cplusplus
}  //  extern "C"
#endif
