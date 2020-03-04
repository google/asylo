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

#include <errno.h>
#include <sched.h>
#include <string.h>  // memset

#include <bitset>

#include "asylo/platform/host_call/trusted/host_calls.h"

inline size_t WordNum(int cpu) { return cpu / (8 * sizeof(CpuSetWord)); }

inline CpuSetWord BitNum(int cpu) { return cpu % (8 * sizeof(CpuSetWord)); }

void CpuSetZero(CpuSet *set) { memset(set->words, 0, sizeof(set->words)); }

constexpr CpuSetWord one_word = 1;

void CpuSetAddBit(int cpu, CpuSet *set) {
  set->words[WordNum(cpu)] |= one_word << BitNum(cpu);
}

void CpuSetClearBit(int cpu, CpuSet *set) {
  set->words[WordNum(cpu)] &= ~(one_word << BitNum(cpu));
}

int CpuSetCheckBit(int cpu, const CpuSet *set) {
  return ((set->words[WordNum(cpu)] & (one_word << BitNum(cpu))) ? 1 : 0);
}

int CpuSetCountBits(CpuSet *set) {
  int cpu_count = 0;
  CpuSetWord word;

  // For each word...
  for (size_t i = 0; i < CPU_SET_T_NUM_WORDS; ++i) {
    word = set->words[i];
    // ...for each bit...
    cpu_count += std::bitset<8 * sizeof(CpuSetWord)>(word).count();
  }
  return cpu_count;
}

int CpuSetEqual(CpuSet *set1, CpuSet *set2) {
  // For each pair of corresponding words...
  for (size_t i = 0; i < CPU_SET_T_NUM_WORDS; ++i) {
    // ...if the words are different...
    if (set1->words[i] != set2->words[i]) {
      // ...then the CPU sets are different.
      return 0;
    }
  }
  return 1;
}

int sched_getaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask) {
  return enc_untrusted_sched_getaffinity(pid, cpusetsize, mask);
}

int sched_setaffinity(pid_t pid, size_t cpusetsize, const cpu_set_t *cpuset) {
  errno = ENOSYS;
  return -1;
}

int sched_yield() { return enc_untrusted_sched_yield(); }

int sched_getcpu(void) {
  errno = ENOSYS;
  return -1;
}
