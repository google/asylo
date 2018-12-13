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
#include <stdio.h>
#include <cstring>
#include <thread>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/synchronization/barrier.h"
#include "asylo/util/logging.h"
#include "asylo/platform/common/time_util.h"
#include "asylo/test/util/pthread_test_util.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status.h"

namespace asylo {
namespace {

static constexpr int kNumThreads = 5;

static constexpr int kCountsPerThread = 500;

class RwLockTest : public ::testing::Test {
 protected:
  // Ensure that the counter is within the intended bounds.
  void CheckCounter() {
    ASSERT_GE(count_, 0) << "counter value out of bounds!";
    ASSERT_LE(count_, kCountsPerThread * kNumThreads)
        << "counter value out of bounds!";
  }

  void ThreadRoutine() {
    for (int i = 0; i < kCountsPerThread; ++i) {
      EXPECT_EQ(pthread_rwlock_wrlock(&rwlock_), 0);
      CheckCounter();
      int counter_copy = count_;
      BusyWork();
      count_ = counter_copy + 1;
      EXPECT_EQ(pthread_rwlock_unlock(&rwlock_), 0);

      EXPECT_EQ(pthread_rwlock_rdlock(&rwlock_), 0);
      CheckCounter();
      EXPECT_EQ(pthread_rwlock_unlock(&rwlock_), 0);
    }
  }

  static void *ThreadTrampoline(void *arg) {
    RwLockTest *test = static_cast<RwLockTest *>(arg);
    CHECK(test != nullptr) << "Test pointer is unexpectedly null";
    test->ThreadRoutine();
    return nullptr;
  }

  // The rwlock under test.
  pthread_rwlock_t rwlock_ = PTHREAD_RWLOCK_INITIALIZER;

  volatile uint count_ = 0;
};

TEST_F(RwLockTest, InvalidPointers) {
  // Test various functions to ensure they return EFAULT rather than crashing if
  // they get invalid pointers.

  ASSERT_EQ(pthread_rwlock_init(nullptr, nullptr), -1);
  ASSERT_EQ(errno, EFAULT);

  ASSERT_EQ(pthread_rwlock_destroy(nullptr), -1);
  ASSERT_EQ(errno, EFAULT);

  ASSERT_EQ(pthread_rwlock_trywrlock(nullptr), -1);
  ASSERT_EQ(errno, EFAULT);

  ASSERT_EQ(pthread_rwlock_wrlock(nullptr), -1);
  ASSERT_EQ(errno, EFAULT);

  ASSERT_EQ(pthread_rwlock_tryrdlock(nullptr), -1);
  ASSERT_EQ(errno, EFAULT);

  ASSERT_EQ(pthread_rwlock_rdlock(nullptr), -1);
  ASSERT_EQ(errno, EFAULT);

  ASSERT_EQ(pthread_rwlock_unlock(nullptr), -1);
  ASSERT_EQ(errno, EFAULT);
}

TEST_F(RwLockTest, Init) {
  // Confirm pthread_rwlock_init and PTHREAD_RWLOCK_INITIALIZER are the same.
  pthread_rwlock_t rwlock;
  ASSERT_EQ(pthread_rwlock_init(&rwlock, nullptr), 0);

  ASSERT_EQ(rwlock._write_owner, rwlock_._write_owner);
  ASSERT_EQ(rwlock._queue._first, rwlock_._queue._first);
  ASSERT_EQ(rwlock._lock, rwlock_._lock);
  ASSERT_EQ(rwlock._reader_count, rwlock_._reader_count);
}

TEST_F(RwLockTest, ManyThreads) {
  std::vector<pthread_t> threads;
  ASYLO_ASSERT_OK(LaunchThreads(kNumThreads, ThreadTrampoline, this, &threads));
  LOG(INFO) << "Threads launched";

  ASYLO_ASSERT_OK(JoinThreads(threads));

  LOG(INFO) << "Threads joined";

  ASSERT_EQ(count_, kNumThreads * kCountsPerThread);
}

TEST_F(RwLockTest, MultipleReaders) {
  // Ensure multiple readers can have the rwlock_ with a read lock at a time.
  constexpr int kNumReaders = 3;
  absl::Barrier read_barrier(kNumReaders);

  std::vector<std::thread> threads;
  for (int i = 0; i < kNumReaders; ++i) {
    threads.emplace_back([&]() {
      EXPECT_EQ(pthread_rwlock_rdlock(&rwlock_), 0);
      read_barrier.Block();
      EXPECT_EQ(pthread_rwlock_unlock(&rwlock_), 0);
    });
  }

  for (auto &thread : threads) {
    thread.join();
  }

  EXPECT_EQ(pthread_rwlock_wrlock(&rwlock_), 0);
  EXPECT_EQ(pthread_rwlock_unlock(&rwlock_), 0);
  EXPECT_EQ(pthread_rwlock_destroy(&rwlock_), 0);
}

}  // namespace
}  // namespace asylo
