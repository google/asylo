/*
 *
 * Copyright 2019 Asylo authors
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

#include "asylo/util/thread.h"

#include <cstddef>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/container/flat_hash_set.h"
#include "absl/synchronization/mutex.h"
#include "absl/synchronization/notification.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "asylo/util/mutex_guarded.h"

using ::testing::AllOf;
using ::testing::Eq;
using ::testing::Ge;
using ::testing::Lt;

namespace asylo {
namespace {

class ThreadTest : public ::testing::Test {
 protected:
  static constexpr size_t kThreads = 4;
  static constexpr size_t kIterations = 64;
};

using ThreadDeathTest = ThreadTest;

TEST_F(ThreadTest, SimpleThread) {
  bool executed = false;
  Thread thread([&executed] { executed = true; });
  thread.Join();
  EXPECT_TRUE(executed);
}

TEST_F(ThreadTest, MovedThread) {
  bool executed = false;
  Thread thread([&executed] { executed = true; });
  auto moved = std::move(thread);
  moved.Join();
  EXPECT_TRUE(executed);
}

TEST_F(ThreadTest, DetachedThread) {
  MutexGuarded<bool> executed(false);
  Thread::StartDetached([&executed] {
    absl::SleepFor(absl::Seconds(3));
    *executed.Lock() = true;
  });
  EXPECT_FALSE(*executed.ReaderLock());
  absl::SleepFor(absl::Seconds(6));
  EXPECT_TRUE(*executed.ReaderLock());
}

TEST_F(ThreadTest, MultipleThreads) {
  MutexGuarded<absl::flat_hash_set<Thread::Id>> ids(
      (absl::flat_hash_set<Thread::Id>()));
  std::vector<Thread> threads;
  for (size_t t = 0; t < kThreads; ++t) {
    threads.emplace_back(
        [&ids] { ids.Lock()->insert(Thread::this_thread_id()); });
  }
  for (auto& thread : threads) {
    thread.Join();
  }
  EXPECT_THAT(ids.ReaderLock()->size(), Eq(kThreads));
}

TEST_F(ThreadTest, MultipleThreadsMultipleTimes) {
  MutexGuarded<absl::flat_hash_set<Thread::Id>> ids(
      (absl::flat_hash_set<Thread::Id>()));
  for (size_t i = 0; i < kIterations; ++i) {
    std::vector<Thread> threads;
    for (size_t t = 0; t < kThreads; ++t) {
      threads.emplace_back(
          [&ids] { ids.Lock()->insert(Thread::this_thread_id()); });
    }
    for (auto& thread : threads) {
      thread.Join();
    }
  }
  // Expect that some of the thread ids will be reused after being joined.
  EXPECT_THAT(ids.ReaderLock()->size(),
              AllOf(Ge(kThreads), Lt(kThreads * kIterations)));
}

void CStyleBody(bool* executed) { *executed = true; }

TEST_F(ThreadTest, CStyleThread) {
  bool executed = false;
  Thread thread(CStyleBody, &executed);
  thread.Join();
  EXPECT_TRUE(executed);
}

void CStyleDetachedBody(MutexGuarded<bool> *executed) {
  absl::SleepFor(absl::Seconds(3));
  *executed->Lock() = true;
}

TEST_F(ThreadTest, CStyleDetachedThread) {
  MutexGuarded<bool> executed(false);
  Thread::StartDetached(CStyleDetachedBody, &executed);
  EXPECT_FALSE(*executed.ReaderLock());
  absl::SleepFor(absl::Seconds(6));
  EXPECT_TRUE(*executed.ReaderLock());
}

}  // namespace
}  // namespace asylo
