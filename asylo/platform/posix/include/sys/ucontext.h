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

#ifndef ASYLO_PLATFORM_POSIX_INCLUDE_SYS_UCONTEXT_H_
#define ASYLO_PLATFORM_POSIX_INCLUDE_SYS_UCONTEXT_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

// Type for general register.
typedef int64_t greg_t;

// Number of general registers.
#define NGREG 23

// Container for all general registers.
typedef greg_t gregset_t[NGREG];

// Context to describe whole processor state.
typedef struct {
  gregset_t gregs;
} mcontext_t;

// Userlevel context.
typedef struct ucontext {
  mcontext_t uc_mcontext;
} ucontext_t;

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // ASYLO_PLATFORM_POSIX_INCLUDE_SYS_UCONTEXT_H_
