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

#include <cstdio>
#include <thread>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/container/flat_hash_set.h"
#include "absl/strings/str_cat.h"
#include "absl/synchronization/mutex.h"
#include "absl/time/clock.h"

namespace asylo {
namespace {

static constexpr int kNumThreads = 5;
static pthread_mutex_t many_thread_lock = PTHREAD_MUTEX_INITIALIZER;
static int many_thread_counter = 0;

static pthread_mutex_t count_lock = PTHREAD_MUTEX_INITIALIZER;
static volatile int count = 0;
static int global_arg = 1;

static pthread_once_t once = PTHREAD_ONCE_INIT;
static volatile int once_count = 0;

static constexpr int kNumLocks = 12;
static pthread_mutex_t many_locks[kNumLocks];

// Acquire every lock in the many_locks array. Always lock in the same order, to
// avoid deadlocking.
void *cycle_all_locks(void *arg) {
  for (int i = 0; i < kNumLocks; i++) {
    EXPECT_EQ(pthread_mutex_lock(&many_locks[i]), 0);
  }
  absl::SleepFor(absl::Milliseconds(100));
  for (int i = kNumLocks - 1; i >= 0; i--) {
    EXPECT_EQ(pthread_mutex_unlock(&many_locks[i]), 0);
  }
  return nullptr;
}

void once_function() { ++once_count; }

// Acquire the lock guarding many_thread_counter, increment the counter,
// decrement it, and release lock. Sleep in between each operation, to allow
// interleaving, and ensure the counter always has the correct value.
void *ensure_exclusive_counter(void *arg) {
  EXPECT_EQ(pthread_mutex_lock(&many_thread_lock), 0);
  EXPECT_EQ(many_thread_counter, 0);
  absl::SleepFor(absl::Milliseconds(100));
  EXPECT_EQ(many_thread_counter, 0);
  many_thread_counter = many_thread_counter + 1;
  EXPECT_EQ(many_thread_counter, 1);
  absl::SleepFor(absl::Milliseconds(100));
  EXPECT_EQ(many_thread_counter, 1);
  many_thread_counter = many_thread_counter - 1;
  EXPECT_EQ(many_thread_counter, 0);
  absl::SleepFor(absl::Milliseconds(100));
  EXPECT_EQ(many_thread_counter, 0);
  EXPECT_EQ(pthread_mutex_unlock(&many_thread_lock), 0);
  return nullptr;
}

void *increment_count(void *arg) {
  printf("self: %lu\n", reinterpret_cast<uint64_t>(pthread_self()));
  if (!arg || arg != &global_arg) {
    printf("arg == nullptr || arg != &global_arg\n");
    return nullptr;
  }

  int ret = pthread_once(&once, &once_function);
  if (ret) {
    printf("pthread_once: %u\n", ret);
    return nullptr;
  }

  printf("increment_count\n");
  pthread_mutex_lock(&count_lock);
  ++count;
  pthread_mutex_unlock(&count_lock);
  return arg;
}

void *detachable_function(void *arg) {
  printf("self: %lu\n", reinterpret_cast<uint64_t>(pthread_self()));
  if (!arg || arg != &global_arg) {
    printf("arg == nullptr || arg != &global_arg\n");
    return nullptr;
  }
  return arg;
}

void *thread_specific_function(void *arg) {
  // The key to use may be passed in to the spawned thread. If so, use that. If
  // not, allocate a new one and make sure it's unique.
  pthread_key_t tls_key;
  if (arg != nullptr) {
    tls_key = *static_cast<pthread_key_t *>(arg);
  } else {
    EXPECT_EQ(pthread_key_create(&tls_key, nullptr), 0);

    static absl::Mutex used_key_mutex;
    static absl::flat_hash_set<pthread_key_t> used_keys;
    absl::MutexLock used_key_lock(&used_key_mutex);
    EXPECT_EQ(used_keys.find(tls_key), used_keys.end());
    used_keys.insert(tls_key);
  }

  // If this thread hasn't set it yet, it should be null.
  EXPECT_EQ(pthread_getspecific(tls_key), nullptr);

  int used_for_address;
  pthread_setspecific(tls_key, &used_for_address);
  EXPECT_EQ(pthread_getspecific(tls_key), &used_for_address);
  return nullptr;
}

static volatile int cc11_count = 0;
static absl::Mutex cc11_mutex;

void cc11_increment_count() {
  absl::MutexLock lock(&cc11_mutex);
  ++cc11_count;
}

void *get_self(void *arg) {
  uint64_t self = reinterpret_cast<uint64_t>(pthread_self());
  *(reinterpret_cast<uint64_t *>(arg)) = self;
  return nullptr;
}

TEST(ThreadedTest, ThreadKeys) {
  pthread_key_t tls_key, tls_key2;

  // Assign keys.
  EXPECT_EQ(pthread_key_create(&tls_key, nullptr), 0);
  EXPECT_EQ(pthread_key_create(&tls_key2, nullptr), 0);

  // Ensure assigned different keys
  EXPECT_NE(tls_key, tls_key2);

  // Delete both keys.
  EXPECT_EQ(pthread_key_delete(tls_key), 0);
  EXPECT_EQ(pthread_key_delete(tls_key2), 0);

  // Assign key 2 and ensure it picks up tls_key's previous value.
  EXPECT_EQ(pthread_key_create(&tls_key2, nullptr), 0);
  EXPECT_EQ(tls_key2, tls_key);

  // Clean up.
  EXPECT_EQ(pthread_key_delete(tls_key2), 0);
}

// Tests that pthread_create works and that the pthread_mutex_.* symbols are
// present and do not crash. This does not test the correctness of the mutex.
TEST(ThreadedTest, EnclaveThread) {
  printf("Initialize: begin\n");

  printf("self: %lu\n", reinterpret_cast<uint64_t>(pthread_self()));

  pthread_t thread;
  printf("about to create thread\n");
  ASSERT_EQ(pthread_create(&thread, nullptr, increment_count, &global_arg), 0);
  printf("child: %lu\n", reinterpret_cast<uint64_t>(thread));

  ASSERT_EQ(pthread_once(&once, &once_function), 0);

  void *ret_val;
  ASSERT_EQ(pthread_join(thread, &ret_val), 0);
  ASSERT_NE(ret_val, nullptr);
  ASSERT_EQ(ret_val, &global_arg);

  pthread_mutex_lock(&count_lock);
  ASSERT_EQ(count, 1);

  pthread_mutex_unlock(&count_lock);
  ASSERT_EQ(once_count, 1);

  std::thread t(cc11_increment_count);
  t.join();

  absl::MutexLock lock(&cc11_mutex);
  if (cc11_count != 1) {
    printf("cc11_count == %i, wanted %i\n", once_count, 1);
  }
}

// Tests that a mutex guards access to one thread at a time
TEST(ThreadedTest, PthreadMutexTest) {
  printf("Initialize: begin\n");

  printf("self: %lu\n", reinterpret_cast<uint64_t>(pthread_self()));

  pthread_t threads[kNumThreads];
  for (int i = 0; i < kNumThreads; i++) {
    ASSERT_EQ(
        pthread_create(&threads[i], nullptr, ensure_exclusive_counter, nullptr),
        0);
  }

  for (int i = 0; i < kNumThreads; i++) {
    EXPECT_EQ(pthread_join(threads[i], nullptr), 0);
  }
}

// Tests that multiple mutexes work together. Also uses dynamic mutex
// initialization.
TEST(ThreadedTest, MultipleMutexTest) {
  pthread_mutexattr_t attr;
  ASSERT_EQ(pthread_mutexattr_init(&attr), 0);

  for (int i = 0; i < kNumLocks; i++) {
    ASSERT_EQ(pthread_mutex_init(&many_locks[i], &attr), 0);
  }

  pthread_t threads[kNumThreads];
  for (int i = 0; i < kNumThreads; i++) {
    ASSERT_EQ(pthread_create(&threads[i], nullptr, cycle_all_locks, nullptr),
              0);
  }

  for (int i = 0; i < kNumThreads; i++) {
    EXPECT_EQ(pthread_join(threads[i], nullptr), 0);
  }

  for (int i = 0; i < kNumLocks; i++) {
    EXPECT_EQ(pthread_mutex_destroy(&many_locks[i]), 0);
  }

  ASSERT_EQ(pthread_mutexattr_destroy(&attr), 0);
}

// Tests that pthread_create works for detached threads and pthread_join fails.
TEST(ThreadedTest, DetachedThread) {
  pthread_t thread;
  pthread_attr_t attr;
  ASSERT_EQ(pthread_attr_init(&attr), 0);
  ASSERT_EQ(pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED), 0);
  ASSERT_EQ(pthread_create(&thread, &attr, detachable_function, &global_arg),
            0);

  EXPECT_EQ(pthread_attr_destroy(&attr), 0);

  EXPECT_NE(pthread_join(thread, nullptr), 0);
  EXPECT_NE(pthread_detach(thread), 0);
}

TEST(ThreadedTest, DetachThread) {
  pthread_t thread;
  ASSERT_EQ(pthread_create(&thread, nullptr, detachable_function, &global_arg),
            0);

  EXPECT_EQ(pthread_detach(thread), 0);
  EXPECT_NE(pthread_join(thread, nullptr), 0);
}

TEST(ThreadedTest, ThreadSpecific) {
  pthread_key_t tls_key;
  EXPECT_EQ(pthread_key_create(&tls_key, nullptr), 0);

  // Set and verify thread-specific data for main thread.
  int used_for_address;
  pthread_setspecific(tls_key, &used_for_address);
  EXPECT_EQ(pthread_getspecific(tls_key), &used_for_address);

  // Make sure spawned threads can use thread-specific data.
  pthread_t thread;
  ASSERT_EQ(
      pthread_create(&thread, nullptr, thread_specific_function, &tls_key), 0);
  EXPECT_EQ(pthread_join(thread, nullptr), 0);

  // Ensure the spawned thread setting a value didn't affect this value.
  EXPECT_EQ(pthread_getspecific(tls_key), &used_for_address);

  // Create new keys in separate threads.
  constexpr int kNumThreads = 10;
  absl::flat_hash_set<pthread_t> spawned_threads;
  for (int i = 0; i < kNumThreads; ++i) {
    pthread_t thread;
    ASSERT_EQ(
        pthread_create(&thread, nullptr, thread_specific_function, nullptr), 0);
    spawned_threads.insert(thread);
  }

  // Wait for all of the spawned threads to complete.
  for (pthread_t thread : spawned_threads) {
    EXPECT_EQ(pthread_join(thread, nullptr), 0);
  }
}

// Tests that pthread_self() returns distinct values for different threads, and
// that thread ID generated by pthread_create matches thread ID in
// pthread_self().
TEST(ThreadedTest, ThreadSelf) {
  // Run this test with relatively large number of threads
  constexpr int kNumThreads = 25;
  constexpr int kNumIters = 2;
  pthread_t threads[kNumThreads];
  uint64_t thread_ids_external[kNumThreads];
  uint64_t thread_ids_internal[kNumThreads];

  for (int iter = 0; iter < kNumIters; iter++) {
    for (int i = 0; i < kNumThreads; i++) {
      ASSERT_EQ(pthread_create(&threads[i], nullptr, get_self,
                               &thread_ids_internal[i]),
                0);
      thread_ids_external[i] = reinterpret_cast<uint64_t>(threads[i]);
    }
    for (int i = 0; i < kNumThreads; i++) {
      EXPECT_EQ(pthread_join(threads[i], nullptr), 0);
    }
    // Ensure thread ID is identical internally and externally.
    for (int i = 0; i < kNumThreads; i++) {
      EXPECT_EQ(thread_ids_internal[i], thread_ids_external[i]);
    }
    // Ensure thread ID is unique from others.
    for (int i = 0; i < kNumThreads; i++) {
      for (int j = i + 1; j < kNumThreads; j++) {
        // Only need to check external IDs, as we know internal = external.
        EXPECT_NE(thread_ids_external[i], thread_ids_external[j]);
      }
    }
  }
}

}  // namespace
}  // namespace asylo
