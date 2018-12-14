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
#include <functional>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/synchronization/mutex.h"
#include "asylo/util/logging.h"
#include "asylo/platform/posix/pthread_impl.h"
#include "asylo/test/util/status_matchers.h"

namespace asylo {
namespace pthread_impl {
namespace {

using ::testing::Test;

pthread_t TestThread(uint64_t num) { return static_cast<pthread_t>(num); }

// Simple test fixture for pthread_list_* unit tests.
class QueueOperationsTest : public Test {
 protected:
  QueueOperationsTest() : list_(&raw_list_) {}

  // Destructively evaluates the list_ to ensure its items match what's passed
  // in as |expected_list|. list_ is empty after this function runs. If there is
  // a mismatch, reports a test error using EXPECT macros.
  void VerifyListContentsAndDelete(const std::vector<int> &expected_list) {
    for (const int expected_item : expected_list) {
      pthread_t actual_item = list_.Front();
      list_.Dequeue();

      EXPECT_EQ(TestThread(expected_item), actual_item);
    }

    // The test list must now be empty.
    EXPECT_EQ(list_.Front(), PTHREAD_T_NULL);
  }

  // List under test.
  __pthread_list_t raw_list_ = {};
  QueueOperations list_;
};

TEST_F(QueueOperationsTest, Contains) {
  // Test with an empty list.
  EXPECT_FALSE(list_.Contains(TestThread(1)));

  // Test with items in the list, but not including the item we're looking for.
  list_.Enqueue(TestThread(2));
  list_.Enqueue(TestThread(3));
  EXPECT_FALSE(list_.Contains(TestThread(1)));

  // Test with the item of interest at the end.
  list_.Enqueue(TestThread(1));
  EXPECT_TRUE(list_.Contains(TestThread(1)));

  // Test with the item of interest in the middle.
  list_.Enqueue(TestThread(4));
  list_.Enqueue(TestThread(5));
  EXPECT_TRUE(list_.Contains(TestThread(1)));
}

TEST_F(QueueOperationsTest, ContainsFirst) {
  // Similar to the Contains tests, but ensures that it works when the target is
  // the first element of the list.
  list_.Enqueue(TestThread(1));
  list_.Enqueue(TestThread(2));
  list_.Enqueue(TestThread(3));
  list_.Enqueue(TestThread(4));
  EXPECT_TRUE(list_.Contains(TestThread(1)));
}

TEST_F(QueueOperationsTest, InsertLast) {
  // Ensure that insert_last does what it says.
  list_.Enqueue(TestThread(1));
  list_.Enqueue(TestThread(2));
  list_.Enqueue(TestThread(3));
  list_.Enqueue(TestThread(4));

  VerifyListContentsAndDelete({1, 2, 3, 4});
}

TEST_F(QueueOperationsTest, First) {
  // Ensure the first element of an empty list is the special NULL value.
  EXPECT_EQ(list_.Front(), PTHREAD_T_NULL);

  // When there's only one item on the list, make sure it appears first.
  list_.Enqueue(TestThread(1));
  EXPECT_EQ(list_.Front(), TestThread(1));

  // Ensure first changes as items are added to the end.
  list_.Enqueue(TestThread(2));
  list_.Enqueue(TestThread(3));
  list_.Enqueue(TestThread(4));
  EXPECT_EQ(list_.Front(), TestThread(1));

  // Delete items off the front and ensure the front changes.
  list_.Dequeue();
  EXPECT_EQ(list_.Front(), TestThread(2));
  list_.Dequeue();
  EXPECT_EQ(list_.Front(), TestThread(3));
  list_.Dequeue();
  EXPECT_EQ(list_.Front(), TestThread(4));
  list_.Dequeue();
  EXPECT_EQ(list_.Front(), PTHREAD_T_NULL);
}

TEST_F(QueueOperationsTest, Dequeue) {
  // Ensure that removing the first item from the list works.

  list_.Enqueue(TestThread(1));
  list_.Enqueue(TestThread(2));
  list_.Enqueue(TestThread(3));
  list_.Enqueue(TestThread(4));

  list_.Dequeue();
  list_.Dequeue();

  VerifyListContentsAndDelete({3, 4});
}

TEST_F(QueueOperationsTest, DequeueEmpty) {
  list_.Dequeue();
  list_.Dequeue();
  list_.Dequeue();
}

TEST_F(QueueOperationsTest, Remove) {
  // Ensure remove works if we're removing the first element.
  list_.Enqueue(TestThread(1));
  list_.Enqueue(TestThread(2));
  list_.Enqueue(TestThread(3));
  list_.Enqueue(TestThread(4));
  EXPECT_TRUE(list_.Remove(TestThread(1)));
  VerifyListContentsAndDelete({2, 3, 4});

  // Ensure remove works if we're removing a middle element.
  list_.Enqueue(TestThread(1));
  list_.Enqueue(TestThread(2));
  list_.Enqueue(TestThread(3));
  list_.Enqueue(TestThread(4));
  EXPECT_TRUE(list_.Remove(TestThread(2)));
  VerifyListContentsAndDelete({1, 3, 4});

  // Ensure remove works if we're removing the end element.
  list_.Enqueue(TestThread(1));
  list_.Enqueue(TestThread(2));
  list_.Enqueue(TestThread(3));
  list_.Enqueue(TestThread(4));
  EXPECT_TRUE(list_.Remove(TestThread(4)));
  VerifyListContentsAndDelete({1, 2, 3});

  // Ensure remove works on a 1-element list.
  list_.Enqueue(TestThread(1));
  EXPECT_TRUE(list_.Remove(TestThread(1)));
  VerifyListContentsAndDelete({});

  // Ensure remove works if we're removing an element not in the list.
  list_.Enqueue(TestThread(1));
  list_.Enqueue(TestThread(2));
  list_.Enqueue(TestThread(3));
  list_.Enqueue(TestThread(4));
  EXPECT_FALSE(list_.Remove(TestThread(5)));
  VerifyListContentsAndDelete({1, 2, 3, 4});
}

TEST_F(QueueOperationsTest, Clear) {
  // Ensure that draining the list works.
  list_.Enqueue(TestThread(1));
  list_.Enqueue(TestThread(2));
  list_.Enqueue(TestThread(3));
  list_.Enqueue(TestThread(4));

  list_.Clear();

  VerifyListContentsAndDelete({});
}

TEST_F(QueueOperationsTest, EndToEnd) {
  // "End-to-end" test of the complete life-cycle of inserting and removing an
  // item from a list.
  EXPECT_TRUE(list_.Empty());
  list_.Enqueue(TestThread(1));
  EXPECT_EQ(list_.Front(), TestThread(1));
  EXPECT_TRUE(list_.Contains(TestThread(1)));
  EXPECT_FALSE(list_.Empty());
  list_.Dequeue();
  EXPECT_FALSE(list_.Contains(TestThread(1)));
  EXPECT_TRUE(list_.Empty());
  VerifyListContentsAndDelete({});
}

// A helper class for testing pthread_cleanup_push and pthread_cleanup_pop. This
// class defines a cleanup function that takes a string as an argument; every
// time the cleanup function is called, that string is added to a "run log" that
// records which cleanup functions ran, and in which order. This makes it easy
// to compare what we think should run to what actually ran.
class PthreadCleanupTest : public Test {
 protected:
  // Log of callback runs, each of which is identified with a string.
  static std::vector<std::string> run_log_;

  // Cleanup function just casts its argument to a string and places it in the
  // run log.
  static void CleanupFunc(void *arg) { run_log_.emplace_back((char *)arg); }

  // Run |test_func| in a thread, wait for that thread to terminate, and check
  // that the run log of callbacks that we observed matches |expected_run_log|.
  void ExpectResult(const std::vector<std::string> &expected_run_log,
                    void *(*test_func)(void *)) {
    pthread_t pthread;
    run_log_.clear();
    ASSERT_EQ(pthread_create(&pthread, nullptr, test_func, nullptr), 0);
    ASSERT_EQ(pthread_join(pthread, nullptr), 0);
    EXPECT_EQ(run_log_, expected_run_log);
  }
};

std::vector<std::string> PthreadCleanupTest::run_log_;

TEST_F(PthreadCleanupTest, CleanupExecutedImplicitly) {
  // Basic cleanup test: return before any callbacks are popped, so they should
  // all run in stack order.
  ExpectResult({"c", "b", "a"}, [](void *) -> void * {
    pthread_cleanup_push(CleanupFunc, (void *)"a");
    pthread_cleanup_push(CleanupFunc, (void *)"b");
    pthread_cleanup_push(CleanupFunc, (void *)"c");
    return nullptr;
    pthread_cleanup_pop(0);
    pthread_cleanup_pop(0);
    pthread_cleanup_pop(0);
  });
}

TEST_F(PthreadCleanupTest, CleanupExecutedExplicitly) {
  // We explicitly pop each cleanup func with execute enabled. They should all
  // execute in stack order.
  ExpectResult({"c", "b", "a"}, [](void *) -> void * {
    pthread_cleanup_push(CleanupFunc, (void *)"a");
    pthread_cleanup_push(CleanupFunc, (void *)"b");
    pthread_cleanup_push(CleanupFunc, (void *)"c");
    pthread_cleanup_pop(1);
    pthread_cleanup_pop(1);
    pthread_cleanup_pop(1);
    return nullptr;
  });
}

TEST_F(PthreadCleanupTest, PartialPopWithoutExecution) {
  // C is popped before execution. Execution should only be B, A.
  ExpectResult({"b", "a"}, [](void *) -> void * {
    pthread_cleanup_push(CleanupFunc, (void *)"a");
    pthread_cleanup_push(CleanupFunc, (void *)"b");
    pthread_cleanup_push(CleanupFunc, (void *)"c");
    pthread_cleanup_pop(0);
    return nullptr;
    pthread_cleanup_pop(0);
    pthread_cleanup_pop(0);
  });
}

TEST_F(PthreadCleanupTest, PartialPopWithExecution) {
  // C and D are popped and executed before returning. The rest are executed
  // implicitly.
  ExpectResult({"d", "c", "b", "a"}, [](void *) -> void * {
    pthread_cleanup_push(CleanupFunc, (void *)"a");
    pthread_cleanup_push(CleanupFunc, (void *)"b");
    pthread_cleanup_push(CleanupFunc, (void *)"c");
    pthread_cleanup_push(CleanupFunc, (void *)"d");
    pthread_cleanup_pop(1);
    pthread_cleanup_pop(1);
    return nullptr;
    pthread_cleanup_pop(0);
    pthread_cleanup_pop(0);
  });
}

TEST_F(PthreadCleanupTest, PoppedWithoutExecuting) {
  // We explicitly pop each cleanup func with execute disabled. No cleanup
  // functions should run.
  ExpectResult({}, [](void *) -> void * {
    pthread_cleanup_push(CleanupFunc, (void *)"a");
    pthread_cleanup_push(CleanupFunc, (void *)"b");
    pthread_cleanup_push(CleanupFunc, (void *)"c");
    pthread_cleanup_pop(0);
    pthread_cleanup_pop(0);
    pthread_cleanup_pop(0);
    return nullptr;
  });
}

TEST_F(PthreadCleanupTest, PopAllExecuteSome) {
  // We explicitly pop each cleanup func with execute enabled for some and
  // disabled for others.
  ExpectResult({"c", "b"}, [](void *) -> void * {
    pthread_cleanup_push(CleanupFunc, (void *)"a");
    pthread_cleanup_push(CleanupFunc, (void *)"b");
    pthread_cleanup_push(CleanupFunc, (void *)"c");
    pthread_cleanup_push(CleanupFunc, (void *)"d");
    pthread_cleanup_pop(0);
    pthread_cleanup_pop(1);
    pthread_cleanup_pop(1);
    pthread_cleanup_pop(0);
    return nullptr;
  });
}

TEST_F(PthreadCleanupTest, NestedCleanup) {
  // Nest pushes and pops.
  ExpectResult({"e", "b", "a"}, [](void *) -> void * {
    pthread_cleanup_push(CleanupFunc, (void *)"a");
    pthread_cleanup_push(CleanupFunc, (void *)"b");
    pthread_cleanup_push(CleanupFunc, (void *)"c");

    pthread_cleanup_push(CleanupFunc, (void *)"d");
    pthread_cleanup_pop(0);  // pop d

    pthread_cleanup_push(CleanupFunc, (void *)"e");
    pthread_cleanup_pop(1);  // pop e and execute

    pthread_cleanup_pop(0);  // pop c
    return nullptr;
    pthread_cleanup_pop(0);  // pop b; executed implicitly
    pthread_cleanup_pop(0);  // pop a; executed implicitly
  });
}

}  // namespace
}  // namespace pthread_impl
}  // namespace asylo
