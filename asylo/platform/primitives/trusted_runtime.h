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

#ifndef ASYLO_PLATFORM_PRIMITIVES_TRUSTED_RUNTIME_H_
#define ASYLO_PLATFORM_PRIMITIVES_TRUSTED_RUNTIME_H_

#include <signal.h>
#include <stddef.h>
#include <sys/types.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>

#include "asylo/platform/primitives/primitive_status.h"

namespace asylo {

pid_t enc_fork(const char *enclave_name);

}  // namespace asylo

#ifdef __cplusplus
extern "C" {
#endif

// Exit the current process.
void enc_exit(int rc);

// Writes `count`-many random bytes into `buf` with a hardware source of
// randomness.
ssize_t enc_hardware_random(uint8_t *buf, size_t count);

// Returns the number of entropy bits from the randomness source for
// enc_hardware_random.
int enc_hardware_random_entropy();

// Registers a signal handler on the host.
int enc_register_signal(int signum, const sigset_t mask, int flags);

// Prototype of the user-defined enclave initialization function.
asylo::primitives::PrimitiveStatus asylo_enclave_init();

// Prototype of the user-defined enclave finalization function.
asylo::primitives::PrimitiveStatus asylo_enclave_fini();

// Emulates the Unix `sbrk` system call. See sbrk(2). This functions must be
// exported by each backend to support linking against libc.
void *enclave_sbrk(intptr_t increment);

// Updates the thread info of the current thread for pthread library to use.
void enc_update_pthread_info(void *pthread_info);

// Returns a unique identifier for the calling thread, which is guaranteed to be
// a 64-bit non-zero scalar value on all architectures.
uint64_t enc_thread_self();

// An invalid thread ID constant. This value will never be returned by
// enc_thread_self.
constexpr uint64_t kInvalidThread = 0;

struct EnclaveMemoryLayout {
  // Enclave base load address.
  void *base;
  // Enclave size in bytes.
  size_t size;
  // Base address of the initialized data section in the current enclave.
  void *data_base;
  // Size of the initialized data section in the current enclave.
  size_t data_size;
  // Base address of the uninitialized data section in the current enclave.
  void *bss_base;
  // Size of the uninitialized data section in the current enclave.
  size_t bss_size;
  // Base address of heap in the current enclave.
  void *heap_base;
  // size of heap in the current enclave.
  size_t heap_size;
  // Base address of the thread data for the current thread.
  void *thread_base;
  // Size of the thread data for the current thread.
  size_t thread_size;
  // Base address of the stack for the current thread. This is the upper bound
  // of the stack since stack goes down.
  void *stack_base;
  // Limit address of the stack for the current thread. This is the lower bound
  // of the stack since stack goes down.
  void *stack_limit;
  // Base address of the data storage reserved to the Asylo runtime.
  void *reserved_data_base;
  // Size of the data storage reserved to the Asylo runtime.
  size_t reserved_data_size;
  // Base address of the bss storage reserved to the Asylo runtime.
  void *reserved_bss_base;
  // Size of the bss storage reserved to the Asylo runtime.
  size_t reserved_bss_size;
  // Base address of the heap storage reserved to the Asylo runtime.
  void *reserved_heap_base;
  // Size of the heap storage reserved to the Asylo runtime.
  size_t reserved_heap_size;
};

// Blocks all entries into the enclave.
void enc_block_entries();

// Unblocks all entries into the enclave.
void enc_unblock_entries();

// Rejects all entries into the enclave.
void enc_reject_entries();

void enc_get_memory_layout(struct EnclaveMemoryLayout *enclave_memory_layout);

// Returns the number of total active enclave entries.
int active_entry_count();

// Returns the number of total enclave exits, which haven't yet reenter the
// enclave.
int active_exit_count();

// Returns the number of total entries blocked from entering the enclave.
int blocked_entry_count();

// A macro expanding to an expression appropriate for use as the body of a busy
// loop.
#ifdef __x86_64__
#define enc_pause() __builtin_ia32_pause()
#else
#define enc_pause() \
  do {              \
  } while (0)
#endif

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // ASYLO_PLATFORM_PRIMITIVES_TRUSTED_RUNTIME_H_
