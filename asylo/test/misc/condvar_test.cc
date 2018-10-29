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
#include "asylo/platform/common/time_util.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status.h"
#include <openssl/mem.h>

namespace asylo {
namespace {

// A struct with state needed by each thread. A pointer to this is passed into
// each thread start function.
struct CounterState {
  // A counter that simulates the length of a work queue.
  volatile int counter = 0;

  // Mutex used to lock critical sections.
  pthread_mutex_t mu;

  // Condition variable used to signal queue state changes.
  pthread_cond_t cv;
};

// Controls the number of threads modifying a shared counter variable.
const int kNumThreads = 8;

// Controls the total number of items to be queued.
const int kCountsPerThread = 50000;

// Controls the maximum number of "outstanding work items" that can be queued.
const int kMaxQueueLength = 50;

// The expected number of total items to be drained from the "queue".
const int kExpectedTotalCounts = kNumThreads * kCountsPerThread;

// Controls the size of the buffer that is cleansed in StartRoutine.
const int kBufferSize = 4096;

// Ensure that the counter is within the intended bounds.
void CheckInvariants(CounterState *counter_state) {
  CHECK_GE(counter_state->counter, 0) << "Counter out of bounds!";
  CHECK_LE(counter_state->counter, kMaxQueueLength) << "Counter out of bounds!";
}

// Do an expensive operation in between reading and writing. OPENSSL_cleanse is
// a good candidate because it performs a loop that is not performance-optimized
// in any way (for security reasons).
void BusyWork() {
  uint8_t buf[kBufferSize];
  OPENSSL_cleanse(buf, kBufferSize);
}

// This routine increments the integer pointed to by |arg|->counter
// kCountsPerThread times, but with the constraint that the counter never go
// above kMaxQueueLength. (There's another thread simultaneously "draining the
// queue", i.e. reducing the counter value.) The mutex |arg|->mu is guards
// the critical section and the condition variable |arg|->cv is signalled on
// each increment.
void *ProducerRoutine(void *arg) {
  CounterState *counter_state = static_cast<CounterState *>(arg);
  CHECK(counter_state != nullptr) << "Counter pointer is unexpectedly null";

  // Critical section: read and write a variable that is shared amongst multiple
  // threads.
  pthread_mutex_lock(&counter_state->mu);
  for (int i = 0; i < kCountsPerThread; ++i) {
    CheckInvariants(counter_state);
    while (counter_state->counter == kMaxQueueLength) {
      pthread_cond_wait(&counter_state->cv, &counter_state->mu);
      CheckInvariants(counter_state);
    }
    volatile int counter_copy = counter_state->counter;
    BusyWork();
    counter_state->counter = counter_copy + 1;
    pthread_cond_broadcast(&counter_state->cv);
  }
  pthread_mutex_unlock(&counter_state->mu);
  return nullptr;
}

// This routine decrements |arg|->counter kExpectedTotalCounts times, "draining
// the queue" that's being filled by all the producer threads. It ensures the
// counter never goes below zero and signals |arg|->cv each time it makes more
// room in the "queue".
void *ConsumerRoutine(void *arg) {
  CounterState *counter_state = static_cast<CounterState *>(arg);
  CHECK(counter_state != nullptr) << "Counter pointer is unexpectedly null";

  pthread_mutex_lock(&counter_state->mu);
  for (int i = 0; i < kExpectedTotalCounts; i++) {
    CheckInvariants(counter_state);
    while (counter_state->counter == 0) {
      pthread_cond_wait(&counter_state->cv, &counter_state->mu);
      CheckInvariants(counter_state);
    }

    volatile int counter_copy = counter_state->counter;
    BusyWork();
    counter_state->counter = counter_copy - 1;
    pthread_cond_broadcast(&counter_state->cv);
  }
  pthread_mutex_unlock(&counter_state->mu);
  return nullptr;
}

// Creates |numThreads| threads with the given |start_routine| and |arg|. Each
// thread that is started is placed in the |threads| vector.
Status LaunchThreads(const int numThreads, void *(*start_routine)(void *),
                     void *arg, std::vector<pthread_t> *threads) {
  for (int i = 0; i < numThreads; ++i) {
    pthread_t new_thread;
    int ret = pthread_create(&new_thread, nullptr, start_routine, arg);
    if (ret != 0) {
      LOG(ERROR) << "pthread_create() returned " << ret;
      return Status(error::GoogleError::INTERNAL, "Failed to create thread");
    }
    threads->emplace_back(new_thread);
  }

  return Status::OkStatus();
}

// Joins all threads in the |threads| vector.
Status JoinThreads(const std::vector<pthread_t> &threads) {
  for (int i = 0; i < threads.size(); ++i) {
    int ret = pthread_join(threads[i], nullptr);
    if (ret != 0) {
      LOG(ERROR) << "pthread_join() returned " << ret;
      return Status(error::GoogleError::INTERNAL, "Failed to join thread");
    }
  }

  return Status::OkStatus();
}

TEST(BasicTest, EnclaveCondVar) {
  CounterState cs;
  pthread_mutex_init(&cs.mu, nullptr);
  pthread_cond_init(&cs.cv, nullptr);
  cs.counter = 0;
  std::vector<pthread_t> threads;

  ASSERT_THAT(LaunchThreads(kNumThreads, ProducerRoutine, &cs, &threads),
              IsOk());
  LOG(INFO) << "Producer threads launched";
  ASSERT_THAT(LaunchThreads(1, ConsumerRoutine, &cs, &threads), IsOk());
  LOG(INFO) << "Consumer thread launched";
  ASSERT_THAT(JoinThreads(threads), IsOk());
  LOG(INFO) << "Threads joined";
  ASSERT_EQ(cs.counter, 0);
}

TEST(TimeoutTest, EnclaveCondVar) {
  const int kDeadlineSeconds = 3;

  // Test to ensure a cond var that's never signaled returns ETIMEDOUT.
  pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
  pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;

  timespec deadline;
  ASSERT_EQ(clock_gettime(CLOCK_REALTIME, &deadline), 0);
  deadline.tv_sec += kDeadlineSeconds;
  pthread_mutex_lock(&mu);
  LOG(INFO) << "Going to sleep";
  ASSERT_EQ(pthread_cond_timedwait(&cv, &mu, &deadline), ETIMEDOUT);
  LOG(INFO) << "Waking up";
  pthread_mutex_unlock(&mu);

  // Make sure the current time is at least the deadline time.
  timespec curr_time, result;
  ASSERT_EQ(clock_gettime(CLOCK_REALTIME, &curr_time), 0);
  ASSERT_TRUE(asylo::TimeSpecSubtract(deadline, curr_time, &result));
}

}  // namespace
}  // namespace asylo
