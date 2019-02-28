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

#include <thread>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/platform/primitives/x86/spin_lock.h"

namespace asylo {
namespace {

constexpr int kManyThreads = 128;

TEST(LockTest, ManyThreadsTest) {
  int shared_counter = 0;
  asylo_spinlock_t lock = ASYLO_SPIN_LOCK_INITIALIZER;
  std::vector<std::thread> threads;
  threads.reserve(kManyThreads);
  for (int i = 0; i < kManyThreads; i++) {
    threads.emplace_back([&]() {
      for (int i = 0; i < 256; i++) {
        if (!asylo_spin_trylock(&lock)) {
          asylo_spin_lock(&lock);
        }
        shared_counter++;
        EXPECT_EQ(shared_counter, 1);
        shared_counter--;
        EXPECT_EQ(shared_counter, 0);
        asylo_spin_unlock(&lock);
      }
    });
  }

  for (auto &thread : threads) {
    thread.join();
  }

  EXPECT_EQ(shared_counter, 0);
}

}  // namespace
}  // namespace asylo
