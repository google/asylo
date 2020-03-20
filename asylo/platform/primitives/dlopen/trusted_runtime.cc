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

#include "asylo/platform/primitives/trusted_runtime.h"

#include <cstdlib>

extern "C" int enclave_write(int fd, const void *buf, size_t count) {
  // Make a write(2) system call. This is provided as a convenience for
  // debugging, pending integration with system call marshaling across the
  // enclave boundary.
  int ret;
  asm volatile(
      "movq $1, %%rax\n"  // Write syscall.
      "movl %1, %%edi\n"  // Argument fd.
      "movq %2, %%rsi\n"  // Argument buf.
      "movq %3, %%rdx\n"  // Argument count.
      "syscall"
      : "=a"(ret)                      // Output parameters
      : "g"(fd), "g"(buf), "g"(count)  // Input parameters
      : "rcx", "r11"                   // Clobbered registers
  );
  return ret;
}

void enc_exit(int rc) { abort(); }

void enc_update_pthread_info(void *pthread_info) { abort(); }

uint64_t enc_thread_self() {
  static thread_local int thread_identity;
  return reinterpret_cast<uint64_t>(&thread_identity);
}
