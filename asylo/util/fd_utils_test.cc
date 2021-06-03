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

#include "asylo/util/fd_utils.h"

#include <fcntl.h>
#include <poll.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <thread>
#include <utility>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/synchronization/barrier.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "asylo/test/util/status_matchers.h"

namespace asylo {
namespace {

using ::testing::Not;
using ::testing::StrEq;

// A matcher that matches an integer if it has all of the given bits set.
MATCHER_P(HasFlags, flags,
          absl::StrCat("does", negation ? " not" : "", " have the bits in ",
                       flags, " set")) {
  return (arg & flags) == flags;
}

// Test that ReadAllNoBlock() and WriteAllNoBlock() fail when asked to read from
// or write to blocking file descriptors.
TEST(FdUtilsTest, ReadAllNoBlockWriteAllNoBlockBlockingPipe) {
  constexpr char kData[] = "The quick brown fox jumps over the lazy dog!";

  Pipe pipe;
  ASYLO_ASSERT_OK_AND_ASSIGN(pipe, Pipe::CreatePipe());

  EXPECT_THAT(
      WriteAllNoBlock(pipe.write_fd(), kData),
      StatusIs(absl::StatusCode::kInvalidArgument,
               absl::StrCat("Cannot write to fd ", pipe.write_fd(),
                            " without blocking because ", pipe.write_fd(),
                            " is a blocking file descriptor")));
  EXPECT_THAT(
      ReadAllNoBlock(pipe.read_fd()),
      StatusIs(absl::StatusCode::kInvalidArgument,
               absl::StrCat("Cannot read from fd ", pipe.read_fd(),
                            " without blocking because ", pipe.read_fd(),
                            " is a blocking file descriptor")));
}

// Test that ReadAllNoBlock() can read bytes from a non-blocking pipe after
// those bytes are written with WriteAllNoBlock().
TEST(FdUtilsTest, ReadAllNoBlockWriteAllNoBlockNonBlockingPipe) {
  constexpr char kData[] = "The quick brown fox jumps over the lazy dog!";

  Pipe pipe;
  ASYLO_ASSERT_OK_AND_ASSIGN(pipe, Pipe::CreatePipe(O_NONBLOCK));

  auto write_result = WriteAllNoBlock(pipe.write_fd(), kData);
  ASYLO_EXPECT_OK(write_result);
  EXPECT_THAT(ReadAllNoBlock(pipe.read_fd()),
              IsOkAndHolds(StrEq({kData, write_result.value()})));
}

// Test that ReadAllNoBlock() can read bytes from a non-blocking pipe after
// those bytes are written with WriteAllNoBlock() in another thread.
TEST(FdUtilsTest, ReadAllNoBlockWriteAllNoBlockNonBlockingPipeMultithreaded) {
  constexpr char kData[] = "The quick brown fox jumps over the lazy dog!";

  Pipe pipe;
  ASYLO_ASSERT_OK_AND_ASSIGN(pipe, Pipe::CreatePipe(O_NONBLOCK));

  absl::Barrier barrier(2);
  std::string read_string;
  std::thread read_thread([&barrier, &pipe, &read_string] {
    barrier.Block();
    auto read_result = ReadAllNoBlock(pipe.read_fd());
    EXPECT_THAT(read_result, IsOk());
    read_string = std::move(read_result).value();
  });

  auto write_result = WriteAllNoBlock(pipe.write_fd(), kData);
  ASYLO_EXPECT_OK(write_result);
  barrier.Block();

  read_thread.join();
  EXPECT_THAT(read_string, StrEq({kData, write_result.value()}));
}

// Test that ReadAll() can read bytes from a blocking pipe after those bytes are
// written with WriteAll().
TEST(FdUtilsTest, ReadAllWriteAllBlockingPipe) {
  constexpr char kData[] = "The quick brown fox jumps over the lazy dog!";

  Pipe pipe;
  ASYLO_ASSERT_OK_AND_ASSIGN(pipe, Pipe::CreatePipe());

  ASYLO_EXPECT_OK(WriteAll(pipe.write_fd(), kData));
  ASYLO_ASSERT_OK(pipe.CloseWriteFd());
  EXPECT_THAT(ReadAll(pipe.read_fd()), IsOkAndHolds(kData));
}

// Test that ReadAll() can read bytes from a non-blocking pipe after those bytes
// are written with WriteAll().
TEST(FdUtilsTest, ReadAllWriteAllNonBlockingPipe) {
  constexpr char kData[] = "The quick brown fox jumps over the lazy dog!";

  Pipe pipe;
  ASYLO_ASSERT_OK_AND_ASSIGN(pipe, Pipe::CreatePipe(O_NONBLOCK));

  ASYLO_EXPECT_OK(WriteAll(pipe.write_fd(), kData));
  ASYLO_ASSERT_OK(pipe.CloseWriteFd());
  EXPECT_THAT(ReadAll(pipe.read_fd()), IsOkAndHolds(kData));
}

// Test that ReadAll() can read bytes from a blocking pipe after those bytes are
// written with WriteAll() in another thread.
TEST(FdUtilsTest, ReadAllWriteAllBlockingPipeMultithreaded) {
  constexpr char kData[] = "The quick brown fox jumps over the lazy dog!";

  Pipe pipe;
  ASYLO_ASSERT_OK_AND_ASSIGN(pipe, Pipe::CreatePipe());

  std::thread read_thread([kData, &pipe] {
    EXPECT_THAT(ReadAll(pipe.read_fd()), IsOkAndHolds(kData));
  });
  ASYLO_EXPECT_OK(WriteAll(pipe.write_fd(), kData));
  ASYLO_ASSERT_OK(pipe.CloseWriteFd());
  read_thread.join();
}

// Test that ReadAll() can read bytes from a non-blocking pipe after those bytes
// are written with WriteAll() in another thread.
TEST(FdUtilsTest, ReadAllWriteAllNonBlockingPipeMultithreaded) {
  constexpr char kData[] = "The quick brown fox jumps over the lazy dog!";

  Pipe pipe;
  ASYLO_ASSERT_OK_AND_ASSIGN(pipe, Pipe::CreatePipe(O_NONBLOCK));

  std::thread read_thread([kData, &pipe] {
    EXPECT_THAT(ReadAll(pipe.read_fd()), IsOkAndHolds(kData));
  });
  ASYLO_EXPECT_OK(WriteAll(pipe.write_fd(), kData));
  ASYLO_ASSERT_OK(pipe.CloseWriteFd());
  read_thread.join();
}

// Tests that changes to a file descriptor made with SetFdFlags() are visible
// from later GetFdFlags() calls.
TEST(FdUtilsTest, GetFdFlagsReflectsSetFdFlagsChanges) {
  Pipe pipe;
  ASYLO_ASSERT_OK_AND_ASSIGN(pipe, Pipe::CreatePipe());

  int flags;
  ASYLO_ASSERT_OK_AND_ASSIGN(flags, GetFdFlags(pipe.read_fd()));
  EXPECT_THAT(flags, Not(HasFlags(O_NONBLOCK)));

  ASYLO_EXPECT_OK(SetFdFlags(pipe.read_fd(), flags | O_NONBLOCK));

  ASYLO_ASSERT_OK_AND_ASSIGN(flags, GetFdFlags(pipe.read_fd()));
  EXPECT_THAT(flags, HasFlags(O_NONBLOCK));
}

// Tests that changes to a file descriptor made with AddFdFlags() and
// RemoveFdFlags() are visible from later GetFdFlags() calls.
TEST(FdUtilsTest, GetFdFlagsReflectsAddFdFlagsAndRemoveFdFlagsChanges) {
  Pipe pipe;
  ASYLO_ASSERT_OK_AND_ASSIGN(pipe, Pipe::CreatePipe());

  int flags;
  ASYLO_ASSERT_OK_AND_ASSIGN(flags, GetFdFlags(pipe.read_fd()));
  EXPECT_THAT(flags, Not(HasFlags(O_NONBLOCK)));

  ASYLO_EXPECT_OK(AddFdFlags(pipe.read_fd(), O_NONBLOCK));

  ASYLO_ASSERT_OK_AND_ASSIGN(flags, GetFdFlags(pipe.read_fd()));
  EXPECT_THAT(flags, HasFlags(O_NONBLOCK));

  ASYLO_EXPECT_OK(RemoveFdFlags(pipe.read_fd(), O_NONBLOCK));

  ASYLO_ASSERT_OK_AND_ASSIGN(flags, GetFdFlags(pipe.read_fd()));
  EXPECT_THAT(flags, Not(HasFlags(O_NONBLOCK)));
}

// Tests that WaitForEvents() blocks until the requested events occur.
TEST(FdUtilsTest, WaitForEventsBlocksUntilEventsOccur) {
  constexpr absl::Duration kWaitTime = absl::Milliseconds(2500);
  constexpr char kData[] = "The quick brown fox jumps over the lazy dog!";

  Pipe pipe;
  ASYLO_ASSERT_OK_AND_ASSIGN(pipe, Pipe::CreatePipe());

  std::thread write_thread([kWaitTime, kData, &pipe] {
    absl::SleepFor(kWaitTime);
    ASYLO_ASSERT_OK(WriteAll(pipe.write_fd(), kData));
  });

  EXPECT_THAT(WaitForEvents(pipe.read_fd(), POLLIN, 0),
              IsOkAndHolds(HasFlags(POLLIN)));
  write_thread.join();
}

}  // namespace
}  // namespace asylo
