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
class PthreadListWrapperTest : public Test {
 protected:
  PthreadListWrapperTest() : list_(&raw_list_) {}

  // Destructively evaluates the list_ to ensure its items match what's passed
  // in as |expected_list|. list_ is empty after this function runs. If there is
  // a mismatch, reports a test error using EXPECT macros.
  void VerifyListContentsAndDelete(const std::vector<int>& expected_list) {
    for (const int expected_item : expected_list) {
      pthread_t actual_item = list_.Front();
      list_.Pop();

      EXPECT_EQ(TestThread(expected_item), actual_item);
    }

    // The test list must now be empty.
    EXPECT_EQ(list_.Front(), PTHREAD_T_NULL);
  }

  // List under test.
  __pthread_list_t raw_list_ = {};
  PthreadListWrapper list_;
};

TEST_F(PthreadListWrapperTest, Contains) {
  // Test with an empty list.
  EXPECT_FALSE(list_.Contains(TestThread(1)));

  // Test with items in the list, but not including the item we're looking for.
  list_.Push(TestThread(2));
  list_.Push(TestThread(3));
  EXPECT_FALSE(list_.Contains(TestThread(1)));

  // Test with the item of interest at the end.
  list_.Push(TestThread(1));
  EXPECT_TRUE(list_.Contains(TestThread(1)));

  // Test with the item of interest in the middle.
  list_.Push(TestThread(4));
  list_.Push(TestThread(5));
  EXPECT_TRUE(list_.Contains(TestThread(1)));
}

TEST_F(PthreadListWrapperTest, ContainsFirst) {
  // Similar to the Contains tests, but ensures that it works when the target is
  // the first element of the list.
  list_.Push(TestThread(1));
  list_.Push(TestThread(2));
  list_.Push(TestThread(3));
  list_.Push(TestThread(4));
  EXPECT_TRUE(list_.Contains(TestThread(1)));
}

TEST_F(PthreadListWrapperTest, InsertLast) {
  // Ensure that insert_last does what it says.
  list_.Push(TestThread(1));
  list_.Push(TestThread(2));
  list_.Push(TestThread(3));
  list_.Push(TestThread(4));

  VerifyListContentsAndDelete({1, 2, 3, 4});
}

TEST_F(PthreadListWrapperTest, First) {
  // Ensure the first element of an empty list is the special NULL value.
  EXPECT_EQ(list_.Front(), PTHREAD_T_NULL);

  // When there's only one item on the list, make sure it appears first.
  list_.Push(TestThread(1));
  EXPECT_EQ(list_.Front(), TestThread(1));

  // Ensure first changes as items are added to the end.
  list_.Push(TestThread(2));
  list_.Push(TestThread(3));
  list_.Push(TestThread(4));
  EXPECT_EQ(list_.Front(), TestThread(1));

  // Delete items off the front and ensure the front changes.
  list_.Pop();
  EXPECT_EQ(list_.Front(), TestThread(2));
  list_.Pop();
  EXPECT_EQ(list_.Front(), TestThread(3));
  list_.Pop();
  EXPECT_EQ(list_.Front(), TestThread(4));
  list_.Pop();
  EXPECT_EQ(list_.Front(), PTHREAD_T_NULL);
}

TEST_F(PthreadListWrapperTest, Pop) {
  // Ensure that removing the first item from the list works.

  list_.Push(TestThread(1));
  list_.Push(TestThread(2));
  list_.Push(TestThread(3));
  list_.Push(TestThread(4));

  list_.Pop();
  list_.Pop();

  VerifyListContentsAndDelete({3, 4});
}

TEST_F(PthreadListWrapperTest, PopEmptyAborts) {
  // Ensure that popping an empty list aborts.
  int fake_abort_called_n_times = 0;
  PthreadListWrapper list(&raw_list_, [&fake_abort_called_n_times]() {
    fake_abort_called_n_times++;
  });
  list.Pop();
  EXPECT_EQ(fake_abort_called_n_times, 1);
}

TEST_F(PthreadListWrapperTest, Remove) {
  // Ensure remove works if we're removing the first element.
  list_.Push(TestThread(1));
  list_.Push(TestThread(2));
  list_.Push(TestThread(3));
  list_.Push(TestThread(4));
  EXPECT_TRUE(list_.Remove(TestThread(1)));
  VerifyListContentsAndDelete({2, 3, 4});

  // Ensure remove works if we're removing a middle element.
  list_.Push(TestThread(1));
  list_.Push(TestThread(2));
  list_.Push(TestThread(3));
  list_.Push(TestThread(4));
  EXPECT_TRUE(list_.Remove(TestThread(2)));
  VerifyListContentsAndDelete({1, 3, 4});

  // Ensure remove works if we're removing the end element.
  list_.Push(TestThread(1));
  list_.Push(TestThread(2));
  list_.Push(TestThread(3));
  list_.Push(TestThread(4));
  EXPECT_TRUE(list_.Remove(TestThread(4)));
  VerifyListContentsAndDelete({1, 2, 3});

  // Ensure remove works on a 1-element list.
  list_.Push(TestThread(1));
  EXPECT_TRUE(list_.Remove(TestThread(1)));
  VerifyListContentsAndDelete({});

  // Ensure remove works if we're removing an element not in the list.
  list_.Push(TestThread(1));
  list_.Push(TestThread(2));
  list_.Push(TestThread(3));
  list_.Push(TestThread(4));
  EXPECT_FALSE(list_.Remove(TestThread(5)));
  VerifyListContentsAndDelete({1, 2, 3, 4});
}

TEST_F(PthreadListWrapperTest, ConstructWithNullListAborts) {
  // Ensure that creating a nullptr empty list aborts.
  int fake_abort_called_n_times = 0;
  PthreadListWrapper list(
      /*list=*/nullptr,
      [&fake_abort_called_n_times]() { fake_abort_called_n_times++; });
  EXPECT_EQ(fake_abort_called_n_times, 1);
}

TEST_F(PthreadListWrapperTest, Drain) {
  // Ensure that draining the list works.
  list_.Push(TestThread(1));
  list_.Push(TestThread(2));
  list_.Push(TestThread(3));
  list_.Push(TestThread(4));

  list_.Drain();

  VerifyListContentsAndDelete({});
}

TEST_F(PthreadListWrapperTest, EndToEnd) {
  // "End-to-end" test of the complete life-cycle of inserting and removing an
  // item from a list.
  EXPECT_TRUE(list_.Empty());
  list_.Push(TestThread(1));
  EXPECT_EQ(list_.Front(), TestThread(1));
  EXPECT_TRUE(list_.Contains(TestThread(1)));
  EXPECT_FALSE(list_.Empty());
  list_.Pop();
  EXPECT_FALSE(list_.Contains(TestThread(1)));
  EXPECT_TRUE(list_.Empty());
  VerifyListContentsAndDelete({});
}

}  // namespace
}  // namespace pthread_impl
}  // namespace asylo
