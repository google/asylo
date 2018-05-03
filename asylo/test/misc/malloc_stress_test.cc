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

#include <pthread.h>

#include <stdlib.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/strings/str_cat.h"

namespace asylo {
namespace {

constexpr size_t kNumThreads = 5;
constexpr size_t kAllocations = 100;
constexpr size_t kAllocationSize = 10000;

static void *MallocStress(void *) {
  void *mem[kAllocations];
  for (int i = 0; i < kAllocations; ++i) {
    mem[i] = malloc(kAllocationSize);
  }
  for (int i = 0; i < kAllocations; ++i) {
    free(mem[i]);
  }

  return nullptr;
}

// Creates kNumThreads that run |MallocStress| and waits for all threads to
// join.
TEST(MallocTest, EnclaveMalloc) {
  pthread_t threads[kNumThreads];

  for (int i = 0; i < kNumThreads; ++i) {
    ASSERT_EQ(pthread_create(&threads[i], nullptr, &MallocStress, nullptr), 0);
  }

  for (int i = 0; i < kNumThreads; ++i) {
    ASSERT_EQ(pthread_join(threads[i], nullptr), 0);
  }
}

}  // namespace
}  // namespace asylo
