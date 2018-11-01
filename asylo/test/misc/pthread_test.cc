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
#include "asylo/platform/posix/pthread_impl.h"
#include "asylo/test/util/status_matchers.h"

namespace asylo {
namespace pthread_impl {
namespace {

pthread_t TestThread(uint64_t num) { return static_cast<pthread_t>(num); }

// Simple test fixture for pthread_list_* unit tests.
class PThreadListNodeTest : public ::testing::Test {
 protected:
  // Destructively evaluates the list_ to ensure its items match what's passed
  // in as |expected_list|. list_ is empty after this function runs. If there is
  // a mismatch, reports a test error using EXPECT macros.
  void VerifyListContents(const std::vector<int>& expected_list) {
    for (const int expected_item : expected_list) {
      pthread_t actual_item = pthread_list_first(list_);
      pthread_list_remove_first(&list_);

      EXPECT_EQ(TestThread(expected_item), actual_item);
    }

    // The test list must now be empty.
    EXPECT_EQ(pthread_list_first(list_), PTHREAD_T_NULL);
  }

  // List under test.
  __pthread_list_t list_ = {};
};

TEST_F(PThreadListNodeTest, Contains) {
  // Test with an empty list.
  EXPECT_FALSE(pthread_list_contains(list_, TestThread(1)));

  // Test with items in the list, but not including the item we're looking for.
  pthread_list_insert_last(&list_, TestThread(2));
  pthread_list_insert_last(&list_, TestThread(3));
  EXPECT_FALSE(pthread_list_contains(list_, TestThread(1)));

  // Test with the item of interest at the end.
  pthread_list_insert_last(&list_, TestThread(1));
  EXPECT_TRUE(pthread_list_contains(list_, TestThread(1)));

  // Test with the item of interest in the middle.
  pthread_list_insert_last(&list_, TestThread(4));
  pthread_list_insert_last(&list_, TestThread(5));
  EXPECT_TRUE(pthread_list_contains(list_, TestThread(1)));
}

TEST_F(PThreadListNodeTest, ContainsFirst) {
  // Similar to the Contains tests, but ensures that it works when the target is
  // the first element of the list.
  pthread_list_insert_last(&list_, TestThread(1));
  pthread_list_insert_last(&list_, TestThread(2));
  pthread_list_insert_last(&list_, TestThread(3));
  pthread_list_insert_last(&list_, TestThread(4));
  EXPECT_TRUE(pthread_list_contains(list_, TestThread(1)));
}

TEST_F(PThreadListNodeTest, InsertLast) {
  // Ensure that insert_last does what it says.
  pthread_list_insert_last(&list_, TestThread(1));
  pthread_list_insert_last(&list_, TestThread(2));
  pthread_list_insert_last(&list_, TestThread(3));
  pthread_list_insert_last(&list_, TestThread(4));

  VerifyListContents({1, 2, 3, 4});
}

TEST_F(PThreadListNodeTest, First) {
  // Ensure the first element of an empty list is the special NULL value.
  EXPECT_EQ(pthread_list_first(list_), PTHREAD_T_NULL);

  // When there's only one item on the list, make sure it appears first.
  pthread_list_insert_last(&list_, TestThread(1));
  EXPECT_EQ(pthread_list_first(list_), TestThread(1));

  // Ensure first changes as items are added to the end.
  pthread_list_insert_last(&list_, TestThread(2));
  pthread_list_insert_last(&list_, TestThread(3));
  pthread_list_insert_last(&list_, TestThread(4));
  EXPECT_EQ(pthread_list_first(list_), TestThread(1));

  // Delete items off the front and ensure the front changes.
  pthread_list_remove_first(&list_);
  EXPECT_EQ(pthread_list_first(list_), TestThread(2));
  pthread_list_remove_first(&list_);
  EXPECT_EQ(pthread_list_first(list_), TestThread(3));
  pthread_list_remove_first(&list_);
  EXPECT_EQ(pthread_list_first(list_), TestThread(4));
  pthread_list_remove_first(&list_);
  EXPECT_EQ(pthread_list_first(list_), PTHREAD_T_NULL);
}

TEST_F(PThreadListNodeTest, Remove) {
  // Ensure that removing the first item from the list works.

  pthread_list_insert_last(&list_, TestThread(1));
  pthread_list_insert_last(&list_, TestThread(2));
  pthread_list_insert_last(&list_, TestThread(3));
  pthread_list_insert_last(&list_, TestThread(4));

  pthread_list_remove_first(&list_);
  pthread_list_remove_first(&list_);

  VerifyListContents({3, 4});
}

TEST_F(PThreadListNodeTest, EndToEnd) {
  // "End-to-end" test of the complete life-cycle of inserting and removing an
  // item from a list.
  pthread_list_insert_last(&list_, TestThread(1));
  EXPECT_EQ(pthread_list_first(list_), TestThread(1));
  EXPECT_TRUE(pthread_list_contains(list_, TestThread(1)));
  pthread_list_remove_first(&list_);
  EXPECT_FALSE(pthread_list_contains(list_, TestThread(1)));
  VerifyListContents({});
}

}  // namespace
}  // namespace pthread_impl
}  // namespace asylo
