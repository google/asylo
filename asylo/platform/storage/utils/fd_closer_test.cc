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

#include "asylo/platform/storage/utils/fd_closer.h"

#include <gtest/gtest.h>

namespace asylo {
namespace platform {
namespace storage {

namespace {

static bool close_was_called = false;

class FdCloserTest : public ::testing::Test {
 public:
  FdCloserTest() { close_was_called = false; }
};

int close_test(int fd) {
  close_was_called = true;
  return 0;
}

TEST_F(FdCloserTest, FdCloserDestructorTest) {
  EXPECT_EQ(false, close_was_called);
  {
    FdCloser fd_closer(1, &close_test);
    EXPECT_EQ(1, fd_closer.get());
  }
  EXPECT_EQ(true, close_was_called);
}

TEST_F(FdCloserTest, FdCloserReleaseTest) {
  EXPECT_EQ(false, close_was_called);
  {
    FdCloser fd_closer(1, &close_test);
    EXPECT_EQ(1, fd_closer.get());
    int fd = fd_closer.release();
    EXPECT_EQ(1, fd);
    EXPECT_EQ(-1, fd_closer.get());
    EXPECT_EQ(false, close_was_called);
  }
  EXPECT_EQ(false, close_was_called);
}

TEST_F(FdCloserTest, FdCloserResetTest) {
  EXPECT_EQ(false, close_was_called);
  {
    FdCloser fd_closer(1, &close_test);
    EXPECT_EQ(1, fd_closer.get());
    EXPECT_TRUE(fd_closer.reset(2));
    EXPECT_EQ(true, close_was_called);
    EXPECT_EQ(2, fd_closer.get());
    close_was_called = false;
  }
  EXPECT_EQ(true, close_was_called);
}

TEST_F(FdCloserTest, FdCloserDefaultResetTest) {
  EXPECT_EQ(false, close_was_called);
  {
    FdCloser fd_closer(1, &close_test);
    EXPECT_EQ(1, fd_closer.get());
    EXPECT_TRUE(fd_closer.reset());
    EXPECT_EQ(true, close_was_called);
    EXPECT_EQ(-1, fd_closer.get());
    close_was_called = false;
  }
  EXPECT_EQ(false, close_was_called);
}

}  // namespace

}  // namespace storage
}  // namespace platform
}  // namespace asylo
