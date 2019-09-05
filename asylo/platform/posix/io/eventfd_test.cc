/*
 *
 * Copyright 2018 Asylo authors
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

#include <sys/eventfd.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <thread>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/container/flat_hash_set.h"
#include "absl/synchronization/mutex.h"

namespace asylo {
namespace {

constexpr int kNumWorkers = 6;
constexpr int kCounterStart = 6;
constexpr int kCounterStartMultiThread = kNumWorkers / 2;
constexpr int kSleepDur = 256;
// The value below is the maximum possible value an eventfd instance can hold.
constexpr uint64_t kMaxCounter = 0xfffffffffffffffe;

class EventFdTest : public ::testing::Test {
 protected:
  void InitializeEventFd(bool semaphore, uint64_t start = kCounterStart,
                         bool nonblock = false) {
    int flags = 0;
    if (semaphore) flags |= EFD_SEMAPHORE;
    if (nonblock) flags |= EFD_NONBLOCK;
    event_fd_ = eventfd(start, flags);
    ASSERT_NE(event_fd_, -1);
    num_current_working_threads_.store(0);
  }
  // In semaphore mode, 1 should always be returned.
  void SemaphoreWait() { EXPECT_EQ(Read(), 1); }

  void SemaphoreSignal() { Write(1); }

  // A wrapper for the read operation on an eventfd.
  uint64_t Read() {
    uint64_t result;
    ssize_t num_bytes = read(event_fd_, reinterpret_cast<char *>(&result),
                             sizeof(uint64_t));
    if (num_bytes == -1) return -1;
    EXPECT_EQ(num_bytes, sizeof(uint64_t));
    return result;
  }

  // A wrapper for the write operation on an eventfd.
  int Write(uint64_t add) {
    int num_bytes =
        write(event_fd_, reinterpret_cast<char *>(&add), sizeof(uint64_t));
    if (num_bytes == -1) return -1;
    EXPECT_EQ(num_bytes, sizeof(uint64_t));
    return num_bytes;
  }

  // Every thread will run this routine.
  void Work(int i, absl::flat_hash_set<int> *thread_indexes,
            absl::Mutex *thread_indexes_mutex) {
    // Wait on semaphore.
    SemaphoreWait();
    // Increment the number of current working threads (atomic).
    num_current_working_threads_++;
    // Ensure that the semaphore is not being simultaneously accessed by too
    // many threads.
    EXPECT_LE(num_current_working_threads_.load(), kCounterStartMultiThread);
    std::this_thread::sleep_for(std::chrono::milliseconds(kSleepDur));
    // Add the current thread idx to the set.
    thread_indexes_mutex->Lock();
    thread_indexes->insert(i);
    thread_indexes_mutex->Unlock();
    // Decrement the number of current working threads (atomic).
    num_current_working_threads_--;
    // Signal semaphore.
    SemaphoreSignal();
  }

  int event_fd_;
  std::atomic_int num_current_working_threads_;
};

TEST_F(EventFdTest, SemaphoreMultipleThreads) {
  InitializeEventFd(true, kCounterStartMultiThread);
  absl::flat_hash_set<int> thread_indexes;
  absl::Mutex thread_indexes_mutex;
  std::vector<std::thread> workers;
  for (int i = 0; i < kNumWorkers; ++i) {
    workers.push_back(std::thread([this, i, &thread_indexes,
                                   &thread_indexes_mutex] {
      Work(i, &thread_indexes, &thread_indexes_mutex);
    }));
  }
  for (int i = 0; i < kNumWorkers; ++i) {
    workers[i].join();
  }
  // Verify that all of the thread indexes show up in the set.
  for (int i = 0; i < kNumWorkers; ++i) {
    EXPECT_NE(thread_indexes.find(i), thread_indexes.end());
  }
}

TEST_F(EventFdTest, SemaphoreWaitWhenZero) {
  InitializeEventFd(true);
  for (int i = 0; i < kCounterStart; ++i) {
    SemaphoreWait();
  }
  // Make sure we wait for the worker thread to signal the semaphore.
  std::atomic_bool wait_complete(false);
  std::thread worker([this, &wait_complete] {
    std::this_thread::sleep_for(std::chrono::milliseconds(kSleepDur));
    wait_complete.store(true);
    SemaphoreSignal();
  });
  SemaphoreWait();
  EXPECT_TRUE(wait_complete.load());
  worker.join();
}

TEST_F(EventFdTest, NonSemaphoreWaitWhenZero) {
  InitializeEventFd(false);
  EXPECT_EQ(Read(), kCounterStart);
  // Make sure we wait for the worker thread to write to eventfd.
  std::atomic_bool wait_complete(false);
  std::thread worker([this, &wait_complete] {
    std::this_thread::sleep_for(std::chrono::milliseconds(kSleepDur));
    wait_complete.store(true);
    Write(kCounterStart);
  });
  EXPECT_EQ(Read(), kCounterStart);
  EXPECT_TRUE(wait_complete.load());
  worker.join();
}

TEST_F(EventFdTest, SemaphoreNonBlock) {
  InitializeEventFd(true, kCounterStart, true);
  for (int i = 0; i < kCounterStart; ++i) {
    SemaphoreWait();
  }
  EXPECT_EQ(Read(), -1);
  EXPECT_EQ(errno, EAGAIN);
}

TEST_F(EventFdTest, NonSemaphoreNonBlock) {
  InitializeEventFd(false, kCounterStart, true);
  EXPECT_EQ(Read(), kCounterStart);
  EXPECT_EQ(Read(), -1);
  EXPECT_EQ(errno, EAGAIN);
}

TEST_F(EventFdTest, MaxCounterBlock) {
  InitializeEventFd(false, 0, false);
  // Write kMaxCounter since we can only initialize using an int.
  ASSERT_EQ(Write(kMaxCounter), sizeof(uint64_t));
  std::atomic_bool wait_complete(false);
  std::thread worker([this, &wait_complete] {
    std::this_thread::sleep_for(std::chrono::milliseconds(kSleepDur));
    wait_complete.store(true);
    uint64_t counter = 0;
    ssize_t num_bytes =
        read(event_fd_, reinterpret_cast<char *>(&counter), sizeof(uint64_t));
    ASSERT_EQ(num_bytes, sizeof(uint64_t));
    ASSERT_EQ(counter, kMaxCounter);
  });
  // The Write below should be blocked until the thread above decrements the
  // eventfd counter when it executes Read().
  Write(1);
  EXPECT_TRUE(wait_complete.load());
  worker.join();
}

TEST_F(EventFdTest, MaxCounterNonBlock) {
  InitializeEventFd(false, 0, true);
  // Write kMaxCounter since we can only initialize using an int.
  ASSERT_EQ(Write(kMaxCounter), sizeof(uint64_t));
  EXPECT_EQ(Write(1), -1);
  EXPECT_EQ(errno, EAGAIN);
}

}  // namespace
}  // namespace asylo
