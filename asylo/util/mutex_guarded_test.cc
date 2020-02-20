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

#include "asylo/util/mutex_guarded.h"

#include <atomic>
#include <memory>
#include <thread>
#include <utility>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/memory/memory.h"
#include "absl/synchronization/barrier.h"
#include "absl/synchronization/notification.h"
#include "absl/time/time.h"

namespace asylo {
namespace {

using ::testing::Eq;
using ::testing::Ge;
using ::testing::Gt;

constexpr int kNumThreads = 100;
constexpr absl::Duration kLongEnoughForThreadSwitch = absl::Milliseconds(500);

struct TypeWithNoDefaultCtor {
  TypeWithNoDefaultCtor() = delete;
  explicit TypeWithNoDefaultCtor(int v) : value(v) {}
  int value;
};

struct TypeWithDefaultCtor {
  TypeWithDefaultCtor() : value(31415) {}
  int value;
};

// A matcher that expects an absl::optional<> to have no value.
MATCHER(Nullopt, negation ? "has a value" : "has no value") {
  return !arg.has_value();
}

TEST(MutexGuardedTest, CompatibleWithTypesWithoutDefaultCtor) {
  MutexGuarded<TypeWithNoDefaultCtor> safe(TypeWithNoDefaultCtor(42));
  EXPECT_THAT(safe.Lock()->value, Eq(42));
}

TEST(MutexGuardedTest, DefaultCtorSucceeds) {
  MutexGuarded<TypeWithDefaultCtor> safe;
  EXPECT_THAT(safe.Lock()->value, Eq(31415));
}

TEST(MutexGuardedTest, HeldReaderLocksDoNotPreventAcquiringOtherReaderLocks) {
  MutexGuarded<int> safe_int(0);
  absl::Barrier barrier(kNumThreads);

  std::vector<std::thread> threads;
  threads.reserve(kNumThreads);
  std::atomic<int> num_locks_obtained(0);
  for (int i = 0; i < kNumThreads; ++i) {
    threads.emplace_back([&barrier, &num_locks_obtained, &safe_int] {
      auto maybe_readable_view = safe_int.ReaderTryLock();
      if (maybe_readable_view.has_value()) {
        ++num_locks_obtained;
      }
      barrier.Block();
    });
  }

  for (auto &thread : threads) {
    thread.join();
  }

  // absl::Mutex allows ReaderTryLock() to fail occasionally even if no thread
  // holds the lock exclusively.
  EXPECT_THAT(num_locks_obtained.load(), Ge(0.9 * kNumThreads));
}

TEST(MutexGuardedTest, HeldWriterLocksPreventAcquiringOtherWriterLocks) {
  static constexpr absl::Duration kWaitForSomeThreadToAcquireLock =
      absl::Seconds(10);

  MutexGuarded<int> safe_int(0);
  absl::Barrier barrier(kNumThreads);
  absl::Notification some_thread_acquired_lock;

  std::vector<std::thread> threads;
  threads.reserve(kNumThreads);
  for (int i = 0; i < kNumThreads; ++i) {
    threads.emplace_back([&barrier, &safe_int, &some_thread_acquired_lock] {
      auto maybe_writer_view = safe_int.TryLock();
      if (maybe_writer_view.has_value()) {
        some_thread_acquired_lock.Notify();
      } else {
        EXPECT_TRUE(some_thread_acquired_lock.WaitForNotificationWithTimeout(
            kWaitForSomeThreadToAcquireLock));
      }
      barrier.Block();
    });
  }

  for (auto &thread : threads) {
    thread.join();
  }
}

TEST(MutexGuardedTest, HeldReaderLocksPreventAcquiringWriterLocks) {
  MutexGuarded<int> safe_int(0);

  auto readable_view = safe_int.ReaderLock();

  std::thread try_writer_lock_thread(
      [&safe_int] { EXPECT_THAT(safe_int.TryLock(), Nullopt()); });
  try_writer_lock_thread.join();
}

TEST(MutexGuardedTest, HeldWriterLocksPreventAcquiringReaderLocks) {
  MutexGuarded<int> safe_int(0);

  auto writeable_view = safe_int.Lock();

  std::thread try_reader_lock_thread([&safe_int] {
    EXPECT_THAT(safe_int.ReaderTryLock(), Nullopt());
  });
  try_reader_lock_thread.join();
}

TEST(MutexGuardedTest, WritesFromAllThreadsAreVisibleFromLaterReads) {
  MutexGuarded<int> safe_int(0);

  std::vector<std::thread> threads;
  threads.reserve(kNumThreads);
  for (int i = 0; i < kNumThreads; ++i) {
    threads.emplace_back([&safe_int]() { ++*safe_int.Lock(); });
  }

  for (auto &thread : threads) {
    thread.join();
  }

  EXPECT_THAT(*safe_int.ReaderLock(), Eq(kNumThreads));
}

TEST(MutexGuardedTest, WritesFromAllThreadsAreVisibleFromALaterRelease) {
  MutexGuarded<int> safe_int(0);

  std::vector<std::thread> threads;
  threads.reserve(kNumThreads);
  for (int i = 0; i < kNumThreads; ++i) {
    threads.emplace_back([&safe_int]() { ++*safe_int.Lock(); });
  }

  for (auto &thread : threads) {
    thread.join();
  }

  EXPECT_THAT(safe_int.Release(), Eq(kNumThreads));
}

TEST(MutexGuardedTest, WritesAreVisibleToReadsAfterMoveConstruction) {
  MutexGuarded<std::unique_ptr<int>> safe_int(absl::make_unique<int>(0));
  **safe_int.Lock() = 5;

  MutexGuarded<std::unique_ptr<int>> safe_int_move(std::move(safe_int));
  EXPECT_THAT(**safe_int_move.ReaderLock(), Eq(5));
}

TEST(MutexGuardedTest, WritesAreVisibleToReadsAfterMoveAssignment) {
  MutexGuarded<std::unique_ptr<int>> safe_int(absl::make_unique<int>(0));
  **safe_int.Lock() = 5;

  MutexGuarded<std::unique_ptr<int>> safe_int_move = std::move(safe_int);
  EXPECT_THAT(**safe_int_move.ReaderLock(), Eq(5));
}

TEST(MutexGuardedTest, LockedViewObjectsCanBeMoveConstructedSafely) {
  MutexGuarded<int> safe_int(0);

  {
    auto writeable_view = safe_int.Lock();
    auto writeable_view_move(std::move(writeable_view));
    *writeable_view_move = 5;
  }

  EXPECT_THAT(*safe_int.ReaderLock(), Eq(5));
}

TEST(MutexGuardedTest, LockedViewObjectsCanBeMoveAssignedSafely) {
  MutexGuarded<int> safe_int(0);

  {
    auto writeable_view = safe_int.Lock();
    auto writeable_view_move = std::move(writeable_view);
    *writeable_view_move = 5;
  }

  EXPECT_THAT(*safe_int.ReaderLock(), Eq(5));
}

TEST(MutexGuardedTest, ReaderLockedViewObjectsCanBeMoveConstructedSafely) {
  MutexGuarded<int> safe_int(0);
  *safe_int.Lock() = 5;

  auto readable_view = safe_int.ReaderLock();
  auto readable_view_move(std::move(readable_view));
  EXPECT_THAT(*readable_view_move, Eq(5));
}

TEST(MutexGuardedTest, ReaderLockedViewObjectsCanBeMoveAssignedSafely) {
  MutexGuarded<int> safe_int(0);
  *safe_int.Lock() = 5;

  auto readable_view = safe_int.ReaderLock();
  auto readable_view_move = std::move(readable_view);
  EXPECT_THAT(*readable_view_move, Eq(5));
}

TEST(MutexGuardedTest, LockWhenLocksAfterConditionIsTrue) {
  MutexGuarded<int> safe_int(0);

  std::vector<std::thread> threads;
  threads.reserve(kNumThreads);
  for (int i = 0; i < kNumThreads; ++i) {
    threads.emplace_back([i, &safe_int] {
      ++*safe_int.LockWhen([i](int value) { return value == i; });
    });
  }

  for (auto &thread : threads) {
    thread.join();
  }

  EXPECT_THAT(*safe_int.ReaderLock(), Eq(kNumThreads));
}

TEST(MutexGuardedTest, ReaderLockWhenLocksAfterConditionIsTrue) {
  MutexGuarded<int> safe_int(0);

  std::vector<std::thread> threads;
  threads.reserve(kNumThreads);
  for (int i = 0; i < kNumThreads; ++i) {
    threads.emplace_back([i, &safe_int] {
      EXPECT_THAT(
          *safe_int.ReaderLockWhen([i](int value) { return value > i; }),
          Gt(i));
    });
  }

  for (int i = 0; i < kNumThreads; ++i) {
    ++*safe_int.Lock();
  }

  for (auto &thread : threads) {
    thread.join();
  }
}

TEST(MutexGuardedTest,
     LockWhenWithTimeoutLocksAfterConditionIsTrueOrTimeoutExpires) {
  MutexGuarded<int> safe_int(0);

  std::thread wait_until_zero_then_increment([&safe_int] {
    auto lock_when_pair = safe_int.LockWhenWithTimeout(
        [](int value) { return value == 0; }, kLongEnoughForThreadSwitch);
    EXPECT_TRUE(lock_when_pair.first);
    ++*lock_when_pair.second;
  });

  std::thread wait_until_fifty_then_increment([&safe_int] {
    auto lock_when_pair = safe_int.LockWhenWithTimeout(
        [](int value) { return value == 50; }, kLongEnoughForThreadSwitch);
    EXPECT_FALSE(lock_when_pair.first);
    ++*lock_when_pair.second;
  });

  wait_until_zero_then_increment.join();
  wait_until_fifty_then_increment.join();

  EXPECT_THAT(*safe_int.ReaderLock(), Eq(2));
}

TEST(MutexGuardedTest,
     ReaderLockWhenWithTimeoutLocksAfterConditionIsTrueOrTimeoutExpires) {
  MutexGuarded<int> safe_int(0);

  EXPECT_FALSE(
      safe_int
          .ReaderLockWhenWithTimeout([](int value) { return value > 0; },
                                     kLongEnoughForThreadSwitch)
          .first);
  EXPECT_THAT(*safe_int.ReaderLock(), Eq(0));

  std::thread increment_safe_int([&safe_int] { ++*safe_int.Lock(); });
  EXPECT_TRUE(
      safe_int
          .ReaderLockWhenWithTimeout([](int value) { return value > 0; },
                                     kLongEnoughForThreadSwitch)
          .first);
  EXPECT_THAT(*safe_int.ReaderLock(), Eq(1));

  increment_safe_int.join();
}

TEST(MutexGuardedTest,
     LockWhenWithDeadlineLocksAfterConditionIsTrueOrDeadlinePasses) {
  MutexGuarded<int> safe_int(0);

  std::thread wait_until_zero_then_increment([&safe_int] {
    auto lock_when_pair =
        safe_int.LockWhenWithDeadline([](int value) { return value == 0; },
                                      absl::Now() + kLongEnoughForThreadSwitch);
    EXPECT_TRUE(lock_when_pair.first);
    ++*lock_when_pair.second;
  });

  std::thread wait_until_fifty_then_increment([&safe_int] {
    auto lock_when_pair =
        safe_int.LockWhenWithDeadline([](int value) { return value == 50; },
                                      absl::Now() + kLongEnoughForThreadSwitch);
    EXPECT_FALSE(lock_when_pair.first);
    ++*lock_when_pair.second;
  });

  wait_until_zero_then_increment.join();
  wait_until_fifty_then_increment.join();

  EXPECT_THAT(*safe_int.ReaderLock(), Eq(2));
}

TEST(MutexGuardedTest,
     ReaderLockWhenWithDeadlineLocksAfterConditionIsTrueOrDeadlinePasses) {
  MutexGuarded<int> safe_int(0);

  EXPECT_FALSE(
      safe_int
          .ReaderLockWhenWithDeadline([](int value) { return value > 0; },
                                      absl::Now() + kLongEnoughForThreadSwitch)
          .first);
  EXPECT_THAT(*safe_int.ReaderLock(), Eq(0));

  std::thread increment_safe_int([&safe_int] { ++*safe_int.Lock(); });
  EXPECT_TRUE(
      safe_int
          .ReaderLockWhenWithDeadline([](int value) { return value > 0; },
                                      absl::Now() + kLongEnoughForThreadSwitch)
          .first);
  EXPECT_THAT(*safe_int.ReaderLock(), Eq(1));

  increment_safe_int.join();
}

TEST(MutexGuardedTest, LockViewAwaitLocksAfterConditionIsTrue) {
  MutexGuarded<int> safe_int(0);

  std::vector<std::thread> threads;
  threads.reserve(kNumThreads);
  for (int i = 0; i < kNumThreads; ++i) {
    threads.emplace_back([i, &safe_int] {
      auto writeable_view = safe_int.Lock();
      writeable_view.Await([i](int value) { return value == i; });
      ++*writeable_view;
    });
  }

  for (auto &thread : threads) {
    thread.join();
  }

  EXPECT_THAT(*safe_int.ReaderLock(), Eq(kNumThreads));
}

TEST(MutexGuardedTest,
     LockViewAwaitWithTimeoutLocksAfterConditionIsTrueOrTimeoutExpires) {
  MutexGuarded<int> safe_int(0);

  std::thread wait_until_zero_then_increment([&safe_int] {
    auto writeable_view = safe_int.Lock();
    EXPECT_TRUE(writeable_view.AwaitWithTimeout(
        [](int value) { return value == 0; }, kLongEnoughForThreadSwitch));
    ++*writeable_view;
  });

  std::thread wait_until_fifty_then_increment([&safe_int] {
    auto writeable_view = safe_int.Lock();
    EXPECT_FALSE(writeable_view.AwaitWithTimeout(
        [](int value) { return value == 50; }, kLongEnoughForThreadSwitch));
    ++*writeable_view;
  });

  wait_until_zero_then_increment.join();
  wait_until_fifty_then_increment.join();

  EXPECT_THAT(*safe_int.ReaderLock(), Eq(2));
}

TEST(MutexGuardedTest,
     LockViewAwaitWithDeadlineLocksAfterConditionIsTrueOrDeadlinePasses) {
  MutexGuarded<int> safe_int(0);

  std::thread wait_until_zero_then_increment([&safe_int] {
    auto writeable_view = safe_int.Lock();
    EXPECT_TRUE(writeable_view.AwaitWithDeadline(
        [](int value) { return value == 0; },
        absl::Now() + kLongEnoughForThreadSwitch));
    ++*writeable_view;
  });

  std::thread wait_until_fifty_then_increment([&safe_int] {
    auto writeable_view = safe_int.Lock();
    EXPECT_FALSE(writeable_view.AwaitWithDeadline(
        [](int value) { return value == 50; },
        absl::Now() + kLongEnoughForThreadSwitch));
    ++*writeable_view;
  });

  wait_until_zero_then_increment.join();
  wait_until_fifty_then_increment.join();

  EXPECT_THAT(*safe_int.ReaderLock(), Eq(2));
}

TEST(MutexGuardedTest, ReaderLockViewAwaitLocksAfterConditionIsTrue) {
  MutexGuarded<int> safe_int(0);

  std::vector<std::thread> threads;
  threads.reserve(kNumThreads);
  for (int i = 0; i < kNumThreads; ++i) {
    threads.emplace_back([i, &safe_int] {
      auto readable_view = safe_int.ReaderLock();
      readable_view.Await([i](int value) { return value > i; });
      EXPECT_THAT(*readable_view, Gt(i));
    });
  }

  for (int i = 0; i < kNumThreads; ++i) {
    ++*safe_int.Lock();
  }

  for (auto &thread : threads) {
    thread.join();
  }
}

TEST(MutexGuardedTest,
     ReaderLockViewAwaitWithTimeoutLocksAfterConditionIsTrueOrTimeoutExpires) {
  MutexGuarded<int> safe_int(0);

  {
    auto readable_view = safe_int.ReaderLock();
    EXPECT_FALSE(readable_view.AwaitWithTimeout(
        [](int value) { return value > 0; }, kLongEnoughForThreadSwitch));
    EXPECT_THAT(*readable_view, Eq(0));
  }

  std::thread increment_safe_int([&safe_int] { ++*safe_int.Lock(); });

  {
    auto readable_view = safe_int.ReaderLock();
    EXPECT_TRUE(readable_view.AwaitWithTimeout(
        [](int value) { return value > 0; }, kLongEnoughForThreadSwitch));
    EXPECT_THAT(*readable_view, Eq(1));
  }

  increment_safe_int.join();
}

TEST(MutexGuardedTest,
     ReaderLockViewAwaitWithDeadlineLocksAfterConditionIsTrueOrDeadlinePasses) {
  MutexGuarded<int> safe_int(0);

  {
    auto readable_view = safe_int.ReaderLock();
    EXPECT_FALSE(readable_view.AwaitWithDeadline(
        [](int value) { return value > 0; },
        absl::Now() + kLongEnoughForThreadSwitch));
    EXPECT_THAT(*readable_view, Eq(0));
  }

  std::thread increment_safe_int([&safe_int] { ++*safe_int.Lock(); });

  {
    auto readable_view = safe_int.ReaderLock();
    EXPECT_TRUE(readable_view.AwaitWithDeadline(
        [](int value) { return value > 0; },
        absl::Now() + kLongEnoughForThreadSwitch));
    EXPECT_THAT(*readable_view, Eq(1));
  }

  increment_safe_int.join();
}

TEST(MutexGuardedTest, LockingStressTest) {
  constexpr int kNumIncrementsPerThread = 10000;

  MutexGuarded<int> safe_int(0);

  std::vector<std::thread> threads;
  threads.reserve(kNumThreads);
  for (int i = 0; i < kNumThreads; ++i) {
    threads.emplace_back([&safe_int] {
      for (int j = 0; j < kNumIncrementsPerThread; j++) {
        ++*safe_int.Lock();
      }
    });
  }

  for (auto &thread : threads) {
    thread.join();
  }

  EXPECT_THAT(*safe_int.ReaderLock(),
              Eq(kNumThreads * kNumIncrementsPerThread));
}

}  // namespace
}  // namespace asylo
