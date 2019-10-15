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

#include "asylo/platform/primitives/sgx/untrusted_cache_malloc.h"

#include <cstddef>
#include <cstdlib>
#include <random>
#include <thread>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace asylo {
namespace {

class UntrustedCacheMallocTest : public ::testing::Test {
 protected:
  UntrustedCacheMalloc *untrusted_cache_malloc_ =
      UntrustedCacheMalloc::Instance();
};

TEST_F(UntrustedCacheMallocTest, StressTest) {
  constexpr int kNumThreads = 1;
  constexpr int kAllocations = 2;
  constexpr size_t kMaxPoolEntrySize = 8192;

  // Define a lambda allocating and freeing buffers.
  auto try_malloc_free = [](UntrustedCacheMalloc *untrusted_cache_malloc) {
    void *mem[kAllocations];
    for (int i = 0; i < kAllocations; i++) {
      // Allocate buffer of random sizes including sizes greater than the size
      // of buffers supported by the buffer pool.
      std::mt19937 rand_engine;
      std::uniform_int_distribution<uint64_t> rand_gen(1, kMaxPoolEntrySize);
      size_t size = rand_gen(rand_engine);
      mem[i] = untrusted_cache_malloc->Malloc(size);
    }
    // Free all buffers grabbed from the pool.
    for (int i = 0; i < kAllocations; i++) {
      untrusted_cache_malloc->Free(mem[i]);
    }
  };

  std::vector<std::thread> threads;
  for (int i = 0; i < kNumThreads; i++) {
    threads.emplace_back(try_malloc_free, untrusted_cache_malloc_);
  }
  for (auto &thread : threads) {
    thread.join();
  }
}

}  // namespace
}  // namespace asylo
