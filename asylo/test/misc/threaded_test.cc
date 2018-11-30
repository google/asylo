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
#include <mutex>
#include <thread>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/strings/str_cat.h"

namespace asylo {
namespace {

static pthread_mutex_t count_lock = PTHREAD_MUTEX_INITIALIZER;
static volatile int count = 0;
static int global_arg = 1;
static pthread_key_t tls_key;

static pthread_once_t once = PTHREAD_ONCE_INIT;
static volatile int once_count = 0;

void once_function() { ++once_count; }

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

static volatile int cc11_count = 0;
static std::mutex cc11_mutex;

void cc11_increment_count() {
  std::lock_guard<std::mutex> lock(cc11_mutex);
  ++cc11_count;
}

// Tests that pthread_create works and that the pthread_mutex_.* symbols are
// present and do not crash. This does not test the correctness of the mutex.
TEST(ThreadedTest, EnclaveThread) {
  printf("Initialize: begin\n");

  printf("self: %lu\n", reinterpret_cast<uint64_t>(pthread_self()));

  int used_for_address;
  pthread_key_create(&tls_key, nullptr);
  pthread_setspecific(tls_key, &used_for_address);
  ASSERT_EQ(pthread_getspecific(tls_key), &used_for_address);

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

  std::lock_guard<std::mutex> lock(cc11_mutex);
  if (cc11_count != 1) {
    printf("cc11_count == %i, wanted %i\n", once_count, 1);
  }
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

}  // namespace
}  // namespace asylo
