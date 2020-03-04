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

#ifndef ASYLO_PLATFORM_POSIX_INCLUDE_INTERNAL_SCHED_H_
#define ASYLO_PLATFORM_POSIX_INCLUDE_INTERNAL_SCHED_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// The maximum number of CPUs we support. Should match KLINUX_CPU_SET_MAX_CPUS
// in asylo/platform/system_call/type_conversions/kernel_types.h.
#define CPU_SET_MAX_CPUS 1024

typedef uint64_t CpuSetWord;

#define CPU_SET_T_NUM_WORDS \
  ((CPU_SET_MAX_CPUS / 8 + sizeof(CpuSetWord) - 1) / sizeof(CpuSetWord))

// Represents a set of (up to) CPU_SETSIZE_INTERNAL CPUs as a bitset. The nth
// bit of words[i] corresponds to CPU no. sizeof(CpuSetWord) * i + n.
typedef struct CpuSet {
  CpuSetWord words[CPU_SET_T_NUM_WORDS];
} CpuSet;

// Functions to be called by the macros in CPU_SET(3).

void CpuSetZero(CpuSet *set);

void CpuSetAddBit(int cpu, CpuSet *set);

void CpuSetClearBit(int cpu, CpuSet *set);

int CpuSetCheckBit(int cpu, const CpuSet *set);

int CpuSetCountBits(CpuSet *set);

int CpuSetEqual(CpuSet *set1, CpuSet *set2);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // ASYLO_PLATFORM_POSIX_INCLUDE_INTERNAL_SCHED_H_
