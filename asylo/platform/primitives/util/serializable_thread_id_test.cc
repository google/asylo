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

#include "asylo/platform/primitives/util/serializable_thread_id.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <sstream>
#include <string>
#include <thread>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/container/flat_hash_map.h"
#include "absl/memory/memory.h"
#include "absl/synchronization/mutex.h"

using ::testing::Eq;
using ::testing::StrEq;

namespace asylo {
namespace primitives {
namespace {

class ThreadIdTest : public ::testing::Test {
 protected:
  ThreadIdTest() {
    for (size_t t = 0; t < kThreads; t++) {
      auto thread_context = absl::make_unique<ThreadContext>();
      const auto thread_id = thread_context->thread_id();
      threads_.emplace(thread_id, std::move(thread_context));
    }
  }

  const size_t kThreads = 16;

  // A context of each thread being created.
  // Once created, the thread waits for is_exiting_ flag to be set
  // and then exits.
  class ThreadContext {
   public:
    ThreadContext()
        : thread_(absl::make_unique<std::thread>([this] {
            auto thread_signaled = [this] {
              mutex_.AssertReaderHeld();
              return is_exiting_;
            };
            absl::MutexLock lock(&mutex_);
            mutex_.Await(absl::Condition(&thread_signaled));
          })) {}
    ~ThreadContext() {
      // Signal to `thread_` that it should wake up and exit.
      {
        absl::MutexLock lock(&mutex_);
        is_exiting_ = true;
      }
      if (thread_->joinable()) {
        thread_->join();
      }
    }
    ThreadId thread_id() const { return ThreadId(thread_->get_id()); }

   private:
    absl::Mutex mutex_;
    bool is_exiting_ GUARDED_BY(mutex_) = false;
    const std::unique_ptr<std::thread> thread_;
  };

  absl::flat_hash_map<ThreadId, std::unique_ptr<ThreadContext>> threads_;
};

TEST_F(ThreadIdTest, DefaultId) {
  // Default value matches the current thread.
  ThreadId default_id;
  EXPECT_THAT(default_id, std::this_thread::get_id());
}

TEST_F(ThreadIdTest, ThreadIds) {
  for (const auto &thread : threads_) {
    // ThreadId can be generated from std::thread::id.
    ThreadId id(thread.second->thread_id());

    // ThreadId can be compared to std::thread::id.
    EXPECT_THAT(id, Eq(thread.second->thread_id()));
  }
}

TEST_F(ThreadIdTest, ConvertIds) {
  for (const auto &thread : threads_) {
    // ThreadId can be converted back into std::thread::id.
    ThreadId id(thread.second->thread_id());
    EXPECT_THAT(std::thread::id(id), Eq(thread.second->thread_id()));
  }
}

TEST_F(ThreadIdTest, CopyAssignIds) {
  for (const auto &thread : threads_) {
    // ThreadId can be copied keeping its value.
    ThreadId id(thread.second->thread_id());
    ThreadId copy_id(id);
    EXPECT_THAT(copy_id, Eq(thread.second->thread_id()));

    // ThreadId can be assigned keeping its value.
    ThreadId assigned_id;
    assigned_id = id;
    EXPECT_THAT(assigned_id, Eq(thread.second->thread_id()));
  }
}

TEST_F(ThreadIdTest, IdsEquality) {
  for (const auto &thread : threads_) {
    ThreadId id(thread.second->thread_id());
    // == and != work as expected.
    EXPECT_TRUE(id == ThreadId(thread.second->thread_id()));
    EXPECT_FALSE(id != ThreadId(thread.second->thread_id()));
    EXPECT_TRUE(id != ThreadId())
        << "Expected the thread id of the test runner to differ "
        << "from the id of each thread in threads_";
    EXPECT_FALSE(id == ThreadId())
        << "Expected the thread id of the test runner to differ "
        << "from the id of each thread in threads_";
  }
}

TEST_F(ThreadIdTest, IdsToOstream) {
  for (const auto &thread : threads_) {
    ThreadId id(thread.second->thread_id());
    // << works as expected.
    std::ostringstream id_stream;
    id_stream << id;
    std::ostringstream thread_id_stream;
    thread_id_stream << thread.second->thread_id();
    EXPECT_THAT(id_stream.str(), StrEq(thread_id_stream.str()));
  }
}

TEST_F(ThreadIdTest, IdsSerialization) {
  for (const auto &thread : threads_) {
    ThreadId id(thread.second->thread_id());

    // ThreadId can be cast into number and back keeping its value.
    const uint64_t id_number = id.Serialize();
    ThreadId restored_id = ThreadId::Deserialize(id_number);
    EXPECT_THAT(restored_id, Eq(thread.second->thread_id()));
  }
}

}  // namespace
}  // namespace primitives
}  // namespace asylo
