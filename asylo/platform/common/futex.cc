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

#include "asylo/platform/common/futex.h"

#include <linux/futex.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>

namespace asylo {

namespace {

// libc does not provide a generic wrapper for the futex system call, so here we
// make the call explicitly.
int sys_futex(int32_t *uaddr, int32_t futex_op, int32_t val,
              const struct timespec *timeout, int32_t *uaddr2, int32_t val3) {
  return syscall(SYS_futex, uaddr, futex_op, val, timeout, uaddr2, val3);
}

}  // namespace

extern "C" {

void sys_futex_wait(int32_t *futex, int32_t expected) {
  sys_futex(futex, FUTEX_WAIT, expected, nullptr, nullptr, 0);
}

void sys_futex_wake(int32_t *futex) {
  sys_futex(futex, FUTEX_WAKE, 0, nullptr, nullptr, 0);
}
}

}  // namespace asylo
