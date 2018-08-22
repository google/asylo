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

#ifndef ASYLO_PLATFORM_COMMON_FUTEX_H_
#define ASYLO_PLATFORM_COMMON_FUTEX_H_

#include <cstdint>

extern "C" {

// Tests that the memory location `futex` contains the value `expected` and, if
// so, suspends the calling thread until `futex` is notified by a call to
// `futex_wake`. Otherwise returns immediately.
void sys_futex_wait(int32_t *futex, int32_t expected);

// Wakes at most one of the threads waiting on `futex`.
void sys_futex_wake(int32_t *futex);

}
#endif  // ASYLO_PLATFORM_COMMON_FUTEX_H_
