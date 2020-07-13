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
#include "asylo/platform/core/trusted_mutex.h"
#include "asylo/platform/core/trusted_spin_lock.h"

namespace asylo {
namespace {

constexpr int kManyThreads = 12;
constexpr int kNumIters = 128 * 256;

template <typename LockType>
class LockTest : public ::testing::Test {
 protected:
  LockTest() : lock_(true), non_recursive_(false) {}
  LockType lock_;
  LockType non_recursive_;
};

typedef ::testing::Types<TrustedSpinLock, TrustedMutex> Implementations;

TYPED_TEST_SUITE(LockTest, Implementations);

TYPED_TEST(LockTest, RecursiveTest) {
  EXPECT_FALSE(this->lock_.Owned());
  this->lock_.Lock();
  EXPECT_TRUE(this->lock_.Owned());
  this->lock_.Lock();
  EXPECT_TRUE(this->lock_.Owned());
  this->lock_.Lock();
  EXPECT_TRUE(this->lock_.Owned());
  this->lock_.Unlock();
  EXPECT_TRUE(this->lock_.Owned());
  this->lock_.Unlock();
  EXPECT_TRUE(this->lock_.Owned());
  this->lock_.Unlock();
  EXPECT_FALSE(this->lock_.Owned());
  ASSERT_TRUE(this->lock_.TryLock());
}

TYPED_TEST(LockTest, RecursiveManyThreadsTest) {
  int shared_counter = 0;
  std::vector<std::thread> threads;
  for (int i = 0; i < kManyThreads; i++) {
    threads.emplace_back([&]() {
      for (int i = 0; i < kNumIters; i++) {
        this->lock_.Lock();
        this->lock_.Lock();
        EXPECT_TRUE(this->lock_.TryLock());
        EXPECT_EQ(shared_counter, 0);
        shared_counter++;
        EXPECT_EQ(shared_counter, 1);
        shared_counter--;
        this->lock_.Unlock();
        this->lock_.Unlock();
        this->lock_.Unlock();
      }
    });
  }

  for (auto &thread : threads) {
    thread.join();
  }

  EXPECT_EQ(shared_counter, 0);
}

TYPED_TEST(LockTest, NonRecursiveManyThreadsTest) {
  int shared_counter = 0;
  std::vector<std::thread> threads;
  for (int i = 0; i < kManyThreads; i++) {
    threads.emplace_back([&]() {
      for (int i = 0; i < kNumIters; i++) {
        this->non_recursive_.Lock();
        EXPECT_FALSE(this->non_recursive_.TryLock());
        EXPECT_EQ(shared_counter, 0);
        shared_counter++;
        EXPECT_EQ(shared_counter, 1);
        shared_counter--;
        this->non_recursive_.Unlock();
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
