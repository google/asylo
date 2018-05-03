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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/synchronization/mutex.h"
#include "asylo/util/logging.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status.h"
#include <openssl/mem.h>

namespace asylo {
namespace {

// Controls the number of threads modifying a shared counter variable.
const int kNumThreads = 8;

// Controls the number of loops in StartRoutine.
const int kNumLoops = 50000;

// Controls the size of the buffer that is cleansed in StartRoutine.
const int kBufferSize = 4096;

// The expected final value of a counter.
const int kExpectedResult = kNumThreads * kNumLoops;
// Mutex used in the Mutex-enabled routine.
absl::Mutex mu;

// Mutex used in the MutexLock-enabled routine.
absl::Mutex mu2;

// Mutex used in the TryLock-enabled routine.
absl::Mutex mu3;

// A counter incremented by many threads.
volatile int counter = 0;

// A routine that increments the integer pointed to by |counter| kNumLoop times.
// This routine is not thread-safe.
void StartRoutine(volatile int *counter) {
  if (!counter) {
    LOG(FATAL) << "Counter pointer is unexpectedly null";
  }

  // Critical section: read and write a variable that is shared amongst multiple
  // threads.
  for (int i = 0; i < kNumLoops; ++i) {
    volatile int counter_copy = *counter;

    // Do an expensive operation in between reading and writing.
    // OPENSSL_cleanse is a good candidate because it performs a loop that is
    // not performance-optimized in any way (for security reasons).
    uint8_t buf[kBufferSize];
    OPENSSL_cleanse(buf, kBufferSize);

    *counter = counter_copy + 1;
  }
}

// Creates kNumThreads that run the given |start_routine| and waits for all
// threads to join.
Status LaunchThreads(void *(*start_routine)(void *)) {
  pthread_t threads[kNumThreads];
  int ret = 0;

  for (int i = 0; i < kNumThreads; ++i) {
    ret = pthread_create(&threads[i], nullptr, start_routine, nullptr);
    if (ret != 0) {
      LOG(ERROR) << "pthread_create() returned " << ret;
      return Status(error::GoogleError::INTERNAL, "Failed to create thread");
    }
  }

  for (int i = 0; i < kNumThreads; ++i) {
    ret = pthread_join(threads[i], nullptr);
    if (ret != 0) {
      LOG(ERROR) << "pthread_join() returned " << ret;
      return Status(error::GoogleError::INTERNAL, "Failed to join thread");
    }
  }
  return Status::OkStatus();
}

// Runs StartRoutine without any mutual-exclusion mechanism.  In this routine,
// each of the kNumThreads increments a counter kNumLoops times. Due to an
// inherent race condition in the thread routine, we expect that the final value
// of the counter will be less than kNumThreads * kNumLoops, with high
// probability.
void *StartRoutineUnguarded(void *) {
  // Run the routine without using a mutex.
  StartRoutine(&counter);
  return nullptr;
}

// Runs StartRoutine under a Mutex. The critical section is protected by a
// mutual-exclusion mechanism so we expect the final value of the counter to be
// kExpectedResult.
void *StartRoutineMutex(void *) {
  // Run the routine under a Mutex.
  mu.Lock();
  StartRoutine(&counter);
  mu.Unlock();
  return nullptr;
}

// Runs StartRoutine under a MutexLock. The critical section is protected by a
// mutual-exclusion mechanism so we expect the final value of the counter to be
// kExpectedResult.
void *StartRoutineMutexLock(void *) {
  // Run the routine under a MutexLock.
  absl::MutexLock mu(&mu2);
  StartRoutine(&counter);
  return nullptr;
}

// Runs StartRoutine under a TryLock. The critical section is protected by a
// mutual-exclusion mechanism so we expect the final value of the counter to be
// kExpectedResult.
void *StartRoutineTryLock(void *) {
  // Run the routine under a MutexLock.
  while (!mu3.TryLock()) { ;}
  StartRoutine(&counter);
  mu3.Unlock();
  return nullptr;
}

TEST(RunWithUnguardedTest, EnclaveMutex) {
  counter = 0;
  ASSERT_THAT(LaunchThreads(&StartRoutineUnguarded), IsOk());
  LOG(INFO) << "unguarded_counter: " << counter;
  ASSERT_LT(counter, kExpectedResult);
}

TEST(RunWithMutexTest, EnclaveMutex) {
  counter = 0;
  ASSERT_THAT(LaunchThreads(&StartRoutineMutex), IsOk());
  LOG(INFO) << "mutex_guarded_counter: " << counter;
  ASSERT_EQ(counter, kExpectedResult);
}

TEST(RunWithMutexLockTest, EnclaveMutex) {
  counter = 0;
  ASSERT_THAT(LaunchThreads(&StartRoutineMutexLock), IsOk());
  LOG(INFO) << "lock_guarded_counter: " << counter;
  ASSERT_EQ(counter, kExpectedResult);
}

TEST(RunWithTryLockTest, EnclaveMutex) {
  counter = 0;
  ASSERT_THAT(LaunchThreads(&StartRoutineTryLock), IsOk());
  LOG(INFO) << "try_lock_guarded_counter: " << counter;
  ASSERT_EQ(counter, kExpectedResult);
}

}  // namespace
}  // namespace asylo
