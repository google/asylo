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
#include "asylo/util/lock_guard.h"

#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/base/thread_annotations.h"
#include "absl/synchronization/mutex.h"
#include "asylo/platform/core/trusted_mutex.h"
#include "asylo/platform/core/trusted_spin_lock.h"
#include "asylo/util/thread.h"

namespace asylo {
namespace {

using ::testing::InSequence;
using ::testing::StrictMock;

// The most boring and incorrect fake lock.
class MockLock {
 public:
  MOCK_METHOD(void, Lock, ());
  MOCK_METHOD(void, Marker, ());
  MOCK_METHOD(void, Unlock, ());
};

TEST(MockLockGuardTest, LockOnce) {
  StrictMock<MockLock> lock;
  {
    // Guarantee Lock happens before Unlock by using InSequence.
    InSequence s;
    EXPECT_CALL(lock, Marker()).Times(1);
    EXPECT_CALL(lock, Lock()).Times(1);
    EXPECT_CALL(lock, Marker()).Times(1);
    EXPECT_CALL(lock, Unlock()).Times(1);
    EXPECT_CALL(lock, Marker()).Times(1);
  }
  lock.Marker();
  {
    LockGuard guard(&lock);
    lock.Marker();
  }
  lock.Marker();
}

static constexpr int kNumThreads = 6;
static constexpr int kNumIters = 500;

// Enable testing with multiple different lock types by parameterizing
// tests over the lock type.
template <class T>
class OneArgLockGuardTest : public testing::Test {};

TYPED_TEST_SUITE_P(OneArgLockGuardTest);

template <typename LockType>
void increment_then_decrement(volatile int* counter, int original_value,
                              LockType* lock) {
  LockGuard guard(lock);
  EXPECT_EQ(*counter, original_value);
  *counter = *counter + 1;
  EXPECT_EQ(*counter, original_value + 1);
  *counter = *counter - 1;
  EXPECT_EQ(*counter, original_value);
}

// Ensure that the LockGuard correctly acquires and releases the lock,
// by using it for mutual exclusion.
TYPED_TEST_P(OneArgLockGuardTest, OneArgOneLockNonrecursive) {
  TypeParam lock(/*is_recursive = */ false);
  volatile int counter ABSL_GUARDED_BY(lock) = 0;
  std::vector<Thread> threads;
  for (int i = 0; i < kNumThreads; i++) {
    threads.emplace_back([&counter, &lock] {
      for (int j = 0; j < kNumIters; j++) {
        increment_then_decrement(&counter, 0, &lock);
      }
    });
  }
  for (auto& thread : threads) {
    thread.Join();
  }
}

// Ensure that the LockGuard correctly acquires and releases the lock,
// in a re-entrant (or recursive) case.
TYPED_TEST_P(OneArgLockGuardTest, OneArgOneLockRecursive) {
  TypeParam lock(/*is_recursive = */ true);
  volatile int counter ABSL_GUARDED_BY(lock) = 0;
  std::vector<Thread> threads;
  for (int i = 0; i < kNumThreads; i++) {
    threads.emplace_back([&counter, &lock] {
      for (int j = 0; j < kNumIters; j++) {
        LockGuard guard(&lock);
        EXPECT_EQ(counter, 0);
        counter++;
        EXPECT_EQ(counter, 1);
        { increment_then_decrement(&counter, 1, &lock); }
        EXPECT_EQ(counter, 1);
        counter--;
        EXPECT_EQ(counter, 0);
      }
    });
  }
  for (auto& thread : threads) {
    thread.Join();
  }
}

REGISTER_TYPED_TEST_SUITE_P(OneArgLockGuardTest, OneArgOneLockRecursive,
                            OneArgOneLockNonrecursive);

typedef testing::Types<TrustedMutex, TrustedSpinLock> OneArgLockTypes;
INSTANTIATE_TYPED_TEST_SUITE_P(LockGuardAllLocksTest, OneArgLockGuardTest,
                               OneArgLockTypes);

template <class T>
class ZeroArgLockGuardTest : public testing::Test {};

TYPED_TEST_SUITE_P(ZeroArgLockGuardTest);

// Ensure that the LockGuard correctly acquires and releases the lock,
// by using it for mutual exclusion.
TYPED_TEST_P(ZeroArgLockGuardTest, ZeroArgOneLock) {
  TypeParam lock;
  volatile int counter ABSL_GUARDED_BY(lock) = 0;
  std::vector<Thread> threads;
  for (int i = 0; i < kNumThreads; i++) {
    threads.emplace_back([&counter, &lock] {
      for (int j = 0; j < kNumIters; j++) {
        increment_then_decrement(&counter, 0, &lock);
      }
    });
  }
  for (auto& thread : threads) {
    thread.Join();
  }
}

REGISTER_TYPED_TEST_SUITE_P(ZeroArgLockGuardTest, ZeroArgOneLock);

typedef testing::Types<absl::Mutex> ZeroArgLockTypes;

INSTANTIATE_TYPED_TEST_SUITE_P(LockGuardAllLocksTest, ZeroArgLockGuardTest,
                               ZeroArgLockTypes);

}  // namespace
}  // namespace asylo
