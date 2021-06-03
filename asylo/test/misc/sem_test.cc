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
#include <semaphore.h>
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

TEST(EnclaveSem, InvalidSemPointer) {
  // Test various functions to ensure they return EFAULT rather than crashing if
  // they get invalid pointers.

  // sem_init
  ASSERT_EQ(sem_init(nullptr, /*pshared=*/0, /*value=*/0), -1);
  ASSERT_EQ(errno, EFAULT);

  // sem_destroy
  ASSERT_EQ(sem_destroy(nullptr), -1);
  ASSERT_EQ(errno, EFAULT);

  // sem_post
  ASSERT_EQ(sem_post(nullptr), -1);
  ASSERT_EQ(errno, EFAULT);

  // sem_wait
  ASSERT_EQ(sem_wait(nullptr), -1);
  ASSERT_EQ(errno, EFAULT);

  // sem_trywait
  ASSERT_EQ(sem_wait(nullptr), -1);
  ASSERT_EQ(errno, EFAULT);

  // sem_timedwait
  timespec ts;
  ASSERT_EQ(sem_timedwait(nullptr, &ts), -1);
  ASSERT_EQ(errno, EFAULT);

  // sem_getvalue
  int value;
  ASSERT_EQ(sem_getvalue(nullptr, &value), -1);
  ASSERT_EQ(errno, EFAULT);
  sem_t sem;
  ASSERT_EQ(sem_getvalue(&sem, nullptr), -1);
  ASSERT_EQ(errno, EFAULT);
}

TEST(EnclaveSem, SharedNotAllowed) {
  // Shared semaphores are not supported. Test to ensure they return ENOSYS.
  sem_t sem;
  ASSERT_EQ(sem_init(&sem, /*pshared=*/1, /*value=*/0), -1);
  ASSERT_EQ(errno, ENOSYS);
}

TEST(EnclaveSem, InitialValue) {
  // Ensure that if we pass an initial value other than zero to the semaphore,
  // it doesn't block until those initial values are consumed.
  sem_t sem;
  constexpr int kInitialValue = 10;
  ASSERT_EQ(sem_init(&sem, /*pshared=*/0, kInitialValue), 0);
  int value;
  ASSERT_EQ(sem_getvalue(&sem, &value), 0);
  ASSERT_EQ(value, kInitialValue);
  for (int i = 0; i < kInitialValue; i++) {
    ASSERT_EQ(sem_wait(&sem), 0);
  }

  // Semaphore should now be zero; next wait should return EAGAIN.
  ASSERT_EQ(sem_trywait(&sem), -1);
  ASSERT_EQ(errno, EAGAIN);

  ASSERT_EQ(sem_destroy(&sem), 0);
}

TEST(EnclaveSem, PostAndWait) {
  // Basic test to ensure posting and waiting work.
  sem_t sem;
  sem_init(&sem, /*pshared=*/0, /*value=*/0);

  ASSERT_EQ(sem_post(&sem), 0);
  ASSERT_EQ(sem_post(&sem), 0);
  ASSERT_EQ(sem_wait(&sem), 0);
  ASSERT_EQ(sem_wait(&sem), 0);

  // Semaphore should now be locked; the next wait should block.
  ASSERT_EQ(sem_trywait(&sem), -1);
  ASSERT_EQ(errno, EAGAIN);
}

TEST(EnclaveSem, TryWait) {
  // Ensure that sem_trywait does not block; if the semaphore is not ready, it
  // should return EAGAIN.
  sem_t sem;
  sem_init(&sem, /*pshared=*/0, /*value=*/0);

  // Semaphore value starts at 0, so this should return EAGAIN.
  ASSERT_EQ(sem_trywait(&sem), -1);
  ASSERT_EQ(errno, EAGAIN);

  // Increase semaphore value to 1.
  ASSERT_EQ(sem_post(&sem), 0);

  // A wait should succeed, reducing the semaphore value to 0.
  ASSERT_EQ(sem_trywait(&sem), 0);

  // The next wait should return EAGAIN again.
  ASSERT_EQ(sem_trywait(&sem), -1);
  ASSERT_EQ(errno, EAGAIN);

  ASSERT_EQ(sem_destroy(&sem), 0);
}

TEST(EnclaveSem, GetValue) {
  // Test to ensure sem_getvalue properly returns the value of a semaphore.
  sem_t sem;
  ASSERT_EQ(sem_init(&sem, /*pshared=*/0, /*value=*/0), 0);
  int value;
  ASSERT_EQ(sem_getvalue(&sem, &value), 0);
  ASSERT_EQ(value, 0);

  // Increment semaphore and ensure value is now 1.
  ASSERT_EQ(sem_post(&sem), 0);
  ASSERT_EQ(sem_getvalue(&sem, &value), 0);
  ASSERT_EQ(value, 1);

  // Wait on semaphore and ensure its value goes back to 0.
  ASSERT_EQ(sem_trywait(&sem), 0);
  ASSERT_EQ(sem_getvalue(&sem, &value), 0);
  ASSERT_EQ(value, 0);

  ASSERT_EQ(sem_destroy(&sem), 0);
}

// Given a |sem| that we assume to be not-ready, perform a timedwait on it with
// a deadline several seconds in the future. Ensure that the timeout works
// correctly, i.e. that we neither block indefinitely nor that we return
// immediately.
static void TimeoutTest(sem_t *sem) {
  constexpr int kDeadlineSeconds = 3;

  timespec deadline;
  ASSERT_EQ(clock_gettime(CLOCK_REALTIME, &deadline), 0);
  deadline.tv_sec += kDeadlineSeconds;
  LOG(INFO) << "Going to sleep";
  ASSERT_EQ(sem_timedwait(sem, &deadline), -1);
  ASSERT_EQ(errno, ETIMEDOUT);
  LOG(INFO) << "Waking up";

  // Make sure the current time is at least the deadline time.
  timespec curr_time, result;
  ASSERT_EQ(clock_gettime(CLOCK_REALTIME, &curr_time), 0);
  ASSERT_TRUE(asylo::TimeSpecSubtract(deadline, curr_time, &result));
}

TEST(EnclaveSem, Timeout) {
  // Test a semaphore that's never unlocked to ensure it times out correctly.
  sem_t sem;
  ASSERT_EQ(sem_init(&sem, /*pshared=*/0, /*value=*/0), 0);
  TimeoutTest(&sem);
  ASSERT_EQ(sem_destroy(&sem), 0);
}

TEST(EnclaveSem, TimeoutWithReadySempahore) {
  // Ensure that sem_timedwait successfully unlocks the semaphore without a
  // timeout even if the deadline has passed, if the semaphore is ready anyway.
  // In other words, ensure we aren't so eager to return a timeout because the
  // deadline has passed that we fail to unlock a sempahore that's ready.
  sem_t sem;
  ASSERT_EQ(sem_init(&sem, /*pshared=*/0, /*value=*/1), 0);

  // Put the deadline into the past and try waiting on the semaphore. The wait
  // should return success (0), not ETIMEDOUT.
  timespec deadline;
  ASSERT_EQ(clock_gettime(CLOCK_REALTIME, &deadline), 0);
  deadline.tv_sec -= 1;
  ASSERT_EQ(sem_timedwait(&sem, &deadline), 0);

  // Now that the semaphore is at 0, ensure that the timeout mechanism works as
  // usual.
  TimeoutTest(&sem);

  // Done!
  ASSERT_EQ(sem_destroy(&sem), 0);
}

class ProducerConsumerTest : public ::testing::Test {
 protected:
  // The semaphore under test.
  sem_t sem;

  // The number of producer threads and the number of consumer threads.
  static constexpr int kNumThreads = 4;

  // The number of items to be queued per thread.
  static constexpr int kCountsPerThread = 2000;

  // The number of times each thread should log.
  static constexpr int kLogsPerTest = 10;

  // The number of iterations per log, derived from total desired logs.
  static constexpr int kItersPerLog = kCountsPerThread / kLogsPerTest;

  // Ensure that the counter is within the intended bounds.
  void CheckInvariants() {
    int count;
    ASSERT_EQ(sem_getvalue(&sem, &count), 0);
    ASSERT_GE(count, 0) << "Sem value out of bounds!";
    ASSERT_LE(count, kCountsPerThread * kNumThreads)
        << "Sem value out of bounds!";
  }

  // This routine posts to the semaphore kCountsPerThread times, doing busy
  // work in between each post. Meanwhile, the consumer routine is waiting on
  // the semaphore.
  void ProducerRoutine() {
    LOG(INFO) << "Starting producer routine";
    for (int i = 0; i < kCountsPerThread; ++i) {
      if (i % kItersPerLog == 0) {
        int count;
        ASSERT_EQ(sem_getvalue(&sem, &count), 0);
        LOG(INFO) << "Producer has completed " << i
                  << " iterations, sem value: " << count;
      }
      CheckInvariants();
      sem_post(&sem);
      BusyWork();
    }
    LOG(INFO) << "Ending producer routine";
  }

  static void *ProducerTrampoline(void *arg) {
    ProducerConsumerTest *test = static_cast<ProducerConsumerTest *>(arg);
    CHECK(test != nullptr) << "Test pointer is unexpectedly null";
    test->ProducerRoutine();
    return nullptr;
  }

  // This consumer routine waits on the semaphore kCountsPerThread times, doing
  // busy work in between each wait to simulate doing work on the "dequeued
  // resource".
  void ConsumerRoutine() {
    LOG(INFO) << "Starting consumer routine";
    for (int i = 0; i < kCountsPerThread; i++) {
      if (i % kItersPerLog == 0) {
        int count;
        ASSERT_EQ(sem_getvalue(&sem, &count), 0);
        LOG(INFO) << "Consumer has completed " << i
                  << " iterations, sem value: " << count;
      }
      CheckInvariants();
      sem_wait(&sem);
      BusyWork();
    }
    LOG(INFO) << "Ending consumer routine";
  }

  static void *ConsumerTrampoline(void *arg) {
    ProducerConsumerTest *test = static_cast<ProducerConsumerTest *>(arg);
    CHECK(test != nullptr) << "Test pointer is unexpectedly null";
    test->ConsumerRoutine();
    return nullptr;
  }
};

TEST_F(ProducerConsumerTest, ProducerConsumer) {
  // End-to-end test of a producer consumer pattern. We have a single producer
  // and multiple consumers. At the end, the semaphore's value should be 0.
  ASSERT_EQ(sem_init(&sem, /*pshared=*/0, /*value=*/0), 0);

  // Launch a heartbeat thread to help diagnose scheduling weirdness versus
  // a possible deadlock.
  auto heartbeat_or = LaunchHeartbeat(/*periodms=*/1000);
  ASSERT_THAT(heartbeat_or, IsOk());
  auto heartbeat = std::move(heartbeat_or.value());

  std::vector<pthread_t> threads;
  ASSERT_THAT(LaunchThreads(kNumThreads, ProducerTrampoline, this, &threads),
              IsOk());
  LOG(INFO) << "Producer threads launched";
  ASSERT_THAT(LaunchThreads(kNumThreads, ConsumerTrampoline, this, &threads),
              IsOk());
  LOG(INFO) << "Consumer threads launched";
  ASSERT_THAT(JoinThreads(threads), IsOk());
  LOG(INFO) << "Threads joined";

  int count;
  ASSERT_EQ(sem_getvalue(&sem, &count), 0);
  ASSERT_EQ(count, 0);

  heartbeat->Stop();
}

}  // namespace
}  // namespace asylo
