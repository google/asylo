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

#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/platform/host_call/trusted/host_calls.h"
#include "asylo/util/thread.h"

namespace asylo {
namespace {

class WaitQueueTest : public ::testing::Test {};

TEST_F(WaitQueueTest, NotifyAllTest) {
  constexpr int kNumThreads = 10;

  auto wait = [](int32_t *queue) { enc_untrusted_thread_wait(queue); };

  std::vector<std::thread> threads;
  int32_t *queue = enc_untrusted_create_wait_queue();
  enc_untrusted_enable_waiting(queue);
  for (int i = 0; i < kNumThreads; i++) {
    threads.emplace_back(wait, queue);
  }
  enc_untrusted_disable_waiting(queue);
  enc_untrusted_notify(queue, INT32_MAX);
  for (auto &thread : threads) {
    thread.join();
  }
  enc_untrusted_destroy_wait_queue(queue);
}

TEST_F(WaitQueueTest, NotifyOneTest) {
  auto notify_one = [](int32_t *queue) {
    enc_untrusted_disable_waiting(queue);
    enc_untrusted_notify(queue);
  };

  int32_t *queue = enc_untrusted_create_wait_queue();
  enc_untrusted_enable_waiting(queue);
  std::thread notifier(notify_one, queue);
  enc_untrusted_thread_wait(queue);
  notifier.join();
  enc_untrusted_destroy_wait_queue(queue);
}

TEST_F(WaitQueueTest, DisabledTest) {
  int32_t *queue = enc_untrusted_create_wait_queue();
  constexpr int kNumIters = 1000;
  enc_untrusted_disable_waiting(queue);
  for (int i = 0; i < kNumIters; i++) {
    enc_untrusted_thread_wait(queue);
  }
}

}  // namespace
}  // namespace asylo
