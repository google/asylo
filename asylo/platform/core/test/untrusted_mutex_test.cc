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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/platform/core/untrusted_mutex.h"

namespace asylo {
namespace {

TEST(UntrustedMutexTest, RecursiveTest) {
  UntrustedMutex mutex(true);
  EXPECT_FALSE(mutex.Owned());
  mutex.Lock();
  EXPECT_TRUE(mutex.Owned());
  mutex.Lock();
  EXPECT_TRUE(mutex.Owned());
  mutex.Lock();
  EXPECT_TRUE(mutex.Owned());
  mutex.Unlock();
  EXPECT_TRUE(mutex.Owned());
  mutex.Unlock();
  EXPECT_TRUE(mutex.Owned());
  mutex.Unlock();
  EXPECT_FALSE(mutex.Owned());
  ASSERT_TRUE(mutex.TryLock());
}

TEST(UntrustedMutexTest, RecursiveManyThreadsTest) {
  UntrustedMutex mutex(true);
  int shared_counter = 0;
  std::vector<std::thread> threads;
  for (int i = 0; i < 64; i++) {
    threads.emplace_back([&]() {
      for (int i = 0; i < 128 * 1024; i++) {
        mutex.Lock();
        mutex.Lock();
        EXPECT_TRUE(mutex.TryLock());
        EXPECT_EQ(shared_counter, 0);
        shared_counter++;
        EXPECT_EQ(shared_counter, 1);
        shared_counter--;
        mutex.Unlock();
        mutex.Unlock();
        mutex.Unlock();
      }
    });
  }

  for (auto &thread : threads) {
    thread.join();
  }

  EXPECT_EQ(shared_counter, 0);
}


TEST(UntrustedMutexTest, NonRecursiveManyThreadsTest) {
  UntrustedMutex mutex(false);
  int shared_counter = 0;
  std::vector<std::thread> threads;
  for (int i = 0; i < 64; i++) {
    threads.emplace_back([&]() {
      for (int i = 0; i < 128 * 1024; i++) {
        mutex.Lock();
        EXPECT_FALSE(mutex.TryLock());
        EXPECT_EQ(shared_counter, 0);
        shared_counter++;
        EXPECT_EQ(shared_counter, 1);
        shared_counter--;
        mutex.Unlock();
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
