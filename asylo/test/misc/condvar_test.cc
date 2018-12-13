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
#include "asylo/util/logging.h"
#include "asylo/platform/common/time_util.h"
#include "asylo/test/util/pthread_test_util.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status.h"

namespace asylo {
namespace {

TEST(EnclaveCondVar, IllegalPointer) {
  // Test various pthread_condvar_* functions to ensure they reject invalid
  // pointers.

  // pthread_cond_init
  EXPECT_EQ(pthread_cond_init(nullptr, nullptr), EFAULT);

  // pthread_cond_destroy
  EXPECT_EQ(pthread_cond_destroy(nullptr), EFAULT);

  // pthread_cond_wait
  pthread_mutex_t mu;
  EXPECT_EQ(pthread_cond_wait(nullptr, &mu), EFAULT);
  pthread_cond_t cv;
  EXPECT_EQ(pthread_cond_wait(&cv, nullptr), EFAULT);

  // pthread_cond_timedwait
  EXPECT_EQ(pthread_cond_timedwait(nullptr, &mu, nullptr), EFAULT);
  EXPECT_EQ(pthread_cond_timedwait(&cv, nullptr, nullptr), EFAULT);

  // pthread_cond_signal
  EXPECT_EQ(pthread_cond_signal(nullptr), EFAULT);

  // pthread_cond_broadcast
  EXPECT_EQ(pthread_cond_broadcast(nullptr), EFAULT);
}

// This test creates a typical "producer-consumer" pattern using the mutex and
// condition variable. We bound the maximum length our "queue" is allowed to
// grow to. Producers signal when they've added something to the queue and
// block on the signal when they need more space. Consumers signal when
// they've created space and block when they need a work item.
class ProducerConsumerTest : public ::testing::Test {
 protected:
  // The number of producer threads.
  static constexpr int kNumProducerThreads = 8;

  // The number of items to be queued per threads.
  static constexpr int kCountsPerThread = 5000;

  // Controls the maximum number of "outstanding work items" that can be queued.
  static constexpr int kMaxQueueLength = 50;

  // The expected number of total items to be drained from the "queue".
  static constexpr int kExpectedTotalCounts =
      kNumProducerThreads * kCountsPerThread;

  // Ensure that the counter is within the intended bounds. Lock must be held.
  Status CheckInvariants() {
    return CheckInRange(counter_, "counter_", 0, kMaxQueueLength);
  }

  // Producer routine increments our "queue" counter kCountsPerThread times. We
  // run kNumThreads of these. Each "adds" to the "queue" as long as there's
  // space, never exceeding kMaxQueueLength. It waits on the CV if there's not
  // space, and signals the CV if it adds something to the queue.
  void ProducerRoutine() {
    // Critical section: read and write a variable that is shared amongst
    // multiple threads.
    pthread_mutex_lock(&mu_);
    for (int i = 0; i < kCountsPerThread; ++i) {
      ASYLO_ASSERT_OK(CheckInvariants());
      while (counter_ == kMaxQueueLength) {
        pthread_cond_wait(&cv_, &mu_);
        ASYLO_ASSERT_OK(CheckInvariants());
      }
      volatile int counter_copy = counter_;
      BusyWork();
      counter_ = counter_copy + 1;
      pthread_cond_broadcast(&cv_);
    }
    pthread_mutex_unlock(&mu_);
  }

  static void *ProducerTrampoline(void *arg) {
    ProducerConsumerTest *test = static_cast<ProducerConsumerTest *>(arg);
    CHECK(test != nullptr) << "Corrupt test pointer";
    test->ProducerRoutine();
    return nullptr;
  }

  // Consumer routine "drains" our "queue" counter, ensuring it never drops
  // below 0. It blocks on the CV if the queue is empty and signals the CV each
  // time it makes more room in the queue by consuming a "work item".
  void ConsumerRoutine() {
    pthread_mutex_lock(&mu_);
    for (int i = 0; i < kExpectedTotalCounts; i++) {
      ASYLO_ASSERT_OK(CheckInvariants());
      while (counter_ == 0) {
        pthread_cond_wait(&cv_, &mu_);
        ASYLO_ASSERT_OK(CheckInvariants());
      }

      volatile int counter_copy = counter_;
      BusyWork();
      counter_ = counter_copy - 1;
      pthread_cond_broadcast(&cv_);
    }
    pthread_mutex_unlock(&mu_);
  }

  static void *ConsumerTrampoline(void *arg) {
    ProducerConsumerTest *test = static_cast<ProducerConsumerTest *>(arg);
    CHECK(test != nullptr) << "Corrupt test pointer";
    test->ConsumerRoutine();
    return nullptr;
  }

  // A counter that simulates the length of a work queue.
  volatile int counter_ = 0;

  // Mutex and CV. These are initialized using the explicit initialization
  // function in this test, to ensure those functions work.
  pthread_mutex_t mu_;
  pthread_cond_t cv_;
};

TEST_F(ProducerConsumerTest, ProducerConsumer) {
  ASSERT_EQ(pthread_mutex_init(&mu_, nullptr), 0);
  ASSERT_EQ(pthread_cond_init(&cv_, nullptr), 0);
  std::vector<pthread_t> threads;

  ASYLO_ASSERT_OK(
      LaunchThreads(kNumProducerThreads, ProducerTrampoline, this, &threads));
  LOG(INFO) << "Producer threads launched";
  ASYLO_ASSERT_OK(LaunchThreads(1, ConsumerTrampoline, this, &threads));
  LOG(INFO) << "Consumer thread launched";
  ASYLO_ASSERT_OK(JoinThreads(threads));
  LOG(INFO) << "Threads joined";
  ASSERT_EQ(counter_, 0);

  // Clean up. This will return an error if there are any waiters.
  ASSERT_EQ(pthread_mutex_destroy(&mu_), 0);
  ASSERT_EQ(pthread_cond_destroy(&cv_), 0);
}

// This test waits for a bunch of threads to block on a single CV, then sends
// a single broadcast to that CV and ensures that all threads unblock. As part
// of the test, we use a second CV to help indicate when all threads have
// blocked.
class BroadcastTest : public ::testing::Test {
 protected:
  static constexpr int kNumThreads = 8;

  void WaitForSignal() {
    CHECK_EQ(pthread_mutex_lock(&mu_), 0);
    num_blocked_++;
    CHECK_EQ(pthread_cond_signal(&counter_cv_), 0);
    CHECK_EQ(pthread_cond_wait(&broadcast_cv_, &mu_), 0);
    CHECK_EQ(pthread_mutex_unlock(&mu_), 0);
  }

  static void *WaitForSignalTrampoline(void *arg) {
    BroadcastTest *test = static_cast<BroadcastTest *>(arg);
    CHECK(test != nullptr) << "Corrupt test pointer";
    test->WaitForSignal();
    return nullptr;
  }

  // Number of threads blocked on broadcast_cv_.
  volatile int num_blocked_ = 0;

  // Mutex that protects all critical sections.
  pthread_mutex_t mu_ = PTHREAD_MUTEX_INITIALIZER;

  // Condition variable used to send the test broadcast.
  pthread_cond_t broadcast_cv_ = PTHREAD_COND_INITIALIZER;

  // Condition variable used to track the number of blocked threads.
  pthread_cond_t counter_cv_ = PTHREAD_COND_INITIALIZER;
};

TEST_F(BroadcastTest, Broadcast) {
  // Start up all the threads that will wait on the broadcast signal.
  std::vector<pthread_t> threads;
  ASYLO_ASSERT_OK(
      LaunchThreads(kNumThreads, WaitForSignalTrampoline, this, &threads));

  // Wait for all threads to block.
  ASSERT_EQ(pthread_mutex_lock(&mu_), 0);
  while (num_blocked_ != kNumThreads) {
    ASSERT_EQ(pthread_cond_wait(&counter_cv_, &mu_), 0);
  }
  ASSERT_EQ(pthread_mutex_unlock(&mu_), 0);

  // Send that one magic broadcast.
  ASSERT_EQ(pthread_cond_broadcast(&broadcast_cv_), 0);

  // Wait for all threads to complete. They should have been unblocked by that
  // broadcast.
  ASYLO_ASSERT_OK(JoinThreads(threads));

  // Clean up. This will return an error if there are any waiters.
  ASSERT_EQ(pthread_mutex_destroy(&mu_), 0);
  ASSERT_EQ(pthread_cond_destroy(&counter_cv_), 0);
  ASSERT_EQ(pthread_cond_destroy(&broadcast_cv_), 0);
}

TEST(EnclaveCondVar, Timeout) {
  constexpr int kDeadlineSeconds = 3;

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

  // Clean up. This will return an error if there are any waiters.
  ASSERT_EQ(pthread_mutex_destroy(&mu), 0);
  ASSERT_EQ(pthread_cond_destroy(&cv), 0);
}

}  // namespace
}  // namespace asylo
