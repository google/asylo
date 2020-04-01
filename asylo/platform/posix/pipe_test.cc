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

// This test checks the POSIX-compliance of Asylo's implementations of pipe(),
// pipe2(), and the F_(GET|SET)PIPE_SZ commands to fcntl(). It is run inside an
// enclave. It is also independently run on the host to confirm the test logic.

// For pipe2().
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif  // _GNU_SOURCE

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <bitset>
#include <cerrno>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <ostream>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/types/span.h"
#include "asylo/test/util/memory_matchers.h"
#include "asylo/util/cleanup.h"

namespace asylo {
namespace {

using ::testing::Eq;
using ::testing::Ge;
using ::testing::Gt;
using ::testing::Le;
using ::testing::Ne;

class BasePipeTest : public ::testing::Test {
 protected:
  void SetUp() override {
    int pipe_fds[2];
    ASSERT_THAT(CallPipe(pipe_fds), Eq(0)) << strerror(errno);
    read_fd_ = pipe_fds[0];
    write_fd_ = pipe_fds[1];

    int pipe_size = fcntl(write_fd_, F_GETPIPE_SZ, 0);
    ASSERT_THAT(pipe_size, Ne(-1)) << strerror(errno);

    small_data_ = {'f', 'o', 'o', 'b', 'a', 'r', '\0'};
    packet_data_ = TestBuffer(0, PIPE_BUF);
    pipe_capacity_data_ = TestBuffer(0xff, pipe_size);
    large_data_ = TestBuffer(0xaa, pipe_size * 2);
  }

  void TearDown() override {
    ASSERT_THAT(close(read_fd_), Eq(0)) << strerror(errno);
    ASSERT_THAT(close(write_fd_), Eq(0)) << strerror(errno);
  }

  // Returns non-periodic test data of length |length|, using to |modifier| to
  // distinguish the data from data returned by other invocations of this
  // function.
  std::vector<uint8_t> TestBuffer(uint8_t modifier, size_t length) {
    std::vector<uint8_t> buffer(length);
    for (int i = 0; i < buffer.size(); ++i) {
      buffer[i] = modifier ^ std::bitset<8 * sizeof(i)>(i).count();
    }
    return buffer;
  }

  // As pipe(), but may call pipe2() with flags instead.
  virtual int CallPipe(int pipe_fds[2]) = 0;

  // Attempts to enlarge the pipe. Updates |pipe_size_| and
  // |pipe_capacity_data_| and returns true if the operation succeeds.
  // Otherwise, returns false.
  bool EnlargePipe() {
    constexpr char kMaxPipeSizeFile[] = "/proc/sys/fs/pipe-max-size";

    std::ifstream max_pipe_size_file(kMaxPipeSizeFile);
    int max_pipe_size;
    max_pipe_size_file >> max_pipe_size;
    EXPECT_THAT(pipe_capacity_data_.size(), Le(max_pipe_size));
    if (pipe_capacity_data_.size() == max_pipe_size) {
      return false;
    }

    int fcntl_result = fcntl(write_fd_, F_SETPIPE_SZ, max_pipe_size);
    if (fcntl_result < 0) {
      EXPECT_THAT(fcntl_result, Eq(-1));
      EXPECT_THAT(errno, Eq(EPERM)) << strerror(errno);
      return false;
    }

    EXPECT_THAT(fcntl_result, Eq(max_pipe_size));
    pipe_capacity_data_ = TestBuffer(0x24, fcntl_result);
    return fcntl_result;
  }

  // The read end of the pipe.
  int read_fd_;

  // The write end of the pipe.
  int write_fd_;

  // Test data that should fit within a default-sized pipe's buffer without
  // filling it.
  std::vector<uint8_t> small_data_;

  // Test data that should take up an entire O_DIRECT pipe packet.
  std::vector<uint8_t> packet_data_;

  // Test data that should fill an empty default-sized pipe's buffer
  // without overflowing.
  std::vector<uint8_t> pipe_capacity_data_;

  // Test data that should exceed a default-sized pipe's buffer.
  std::vector<uint8_t> large_data_;
};

class PipeTest : public BasePipeTest {
 public:
  int CallPipe(int pipe_fds[2]) override { return pipe(pipe_fds); }
};

template <int kPipe2Flags>
class Pipe2Test : public BasePipeTest {
 public:
  int CallPipe(int pipe_fds[2]) override {
    return pipe2(pipe_fds, kPipe2Flags);
  }
};

template <typename T>
using AllPipeVarietiesTest = T;
using PipeTestFixtures = ::testing::Types<
    PipeTest, Pipe2Test<0>, Pipe2Test<O_CLOEXEC>, Pipe2Test<O_DIRECT>,
    Pipe2Test<O_NONBLOCK>, Pipe2Test<O_CLOEXEC | O_DIRECT>,
    Pipe2Test<O_CLOEXEC | O_NONBLOCK>, Pipe2Test<O_DIRECT | O_NONBLOCK>,
    Pipe2Test<O_CLOEXEC | O_DIRECT | O_NONBLOCK>>;
TYPED_TEST_SUITE(AllPipeVarietiesTest, PipeTestFixtures);

using CloexecPipeTest = Pipe2Test<O_CLOEXEC>;
using DirectPipeTest = Pipe2Test<O_DIRECT>;
using NonblockPipeTest = Pipe2Test<O_NONBLOCK>;

// Tests that pipe() populates the pipe_fds array with two distinct, non-
// negative file descriptors.
TYPED_TEST(AllPipeVarietiesTest, PipeGivesValidFileDescriptorPairs) {
  EXPECT_THAT(this->read_fd_, Ge(0));
  EXPECT_THAT(this->write_fd_, Ge(0));
  EXPECT_THAT(this->read_fd_, Ne(this->write_fd_));
}

// Tests that the file descriptors returned by pipe() refer to FIFO files.
TYPED_TEST(AllPipeVarietiesTest, PipeFdsAreFifos) {
  struct stat statbuf;
  ASSERT_THAT(fstat(this->read_fd_, &statbuf), Eq(0)) << strerror(errno);
  EXPECT_TRUE(S_ISFIFO(statbuf.st_mode));

  ASSERT_THAT(fstat(this->write_fd_, &statbuf), Eq(0)) << strerror(errno);
  EXPECT_TRUE(S_ISFIFO(statbuf.st_mode));
}

// Tests that small writes to an open pipe succeed.
TYPED_TEST(AllPipeVarietiesTest, SmallWritingToOpenPipesSucceeds) {
  EXPECT_THAT(write(this->write_fd_, this->small_data_.data(),
                    this->small_data_.size()),
              Ge(0))
      << strerror(errno);
}

// Tests that PIPE_BUF-sized writes to an open pipe succeed.
TYPED_TEST(AllPipeVarietiesTest, CapacitySizedWritingToOpenPipesSucceeds) {
  EXPECT_THAT(write(this->write_fd_, this->pipe_capacity_data_.data(),
                    this->pipe_capacity_data_.size()),
              Ge(0))
      << strerror(errno);
}

// Tests that reads from an open, non-empty pipe succeed when using small data.
TYPED_TEST(AllPipeVarietiesTest,
           ReadingFromOpenNonEmptyPipesSucceedsWithSmallData) {
  ASSERT_THAT(write(this->write_fd_, this->small_data_.data(),
                    this->small_data_.size()),
              Ge(0))
      << strerror(errno);

  std::vector<uint8_t> read_buf(this->small_data_.size());

  ssize_t read_result = read(this->read_fd_, read_buf.data(), read_buf.size());
  ASSERT_THAT(read_result, Gt(0));
  EXPECT_THAT(read_buf.data(), MemEq(this->small_data_.data(), read_result));
}

// Tests that reads from an open, non-empty pipe succeed when using medium data.
TYPED_TEST(AllPipeVarietiesTest,
           ReadingFromOpenNonEmptyPipesSucceedsWithCapacitySizedData) {
  ASSERT_THAT(write(this->write_fd_, this->pipe_capacity_data_.data(),
                    this->pipe_capacity_data_.size()),
              Ge(0))
      << strerror(errno);

  std::vector<uint8_t> read_buf(this->pipe_capacity_data_.size());

  ssize_t read_result = read(this->read_fd_, read_buf.data(), read_buf.size());
  ASSERT_THAT(read_result, Gt(0));
  EXPECT_THAT(read_buf.data(),
              MemEq(this->pipe_capacity_data_.data(), read_result));
}

// Tests that reads from an open, non-empty pipe succeed when using medium data,
// but only reading part of the written data.
TYPED_TEST(AllPipeVarietiesTest,
           ReadingFromOpenNonEmptyPipesSucceedsWhenReadingPartOfWrittenData) {
  ASSERT_THAT(write(this->write_fd_, this->pipe_capacity_data_.data(),
                    this->pipe_capacity_data_.size()),
              Ge(0))
      << strerror(errno);

  std::vector<uint8_t> read_buf(this->pipe_capacity_data_.size() / 2);

  ssize_t read_result = read(this->read_fd_, read_buf.data(), read_buf.size());
  ASSERT_THAT(read_result, Gt(0));
  EXPECT_THAT(read_buf.data(),
              MemEq(this->pipe_capacity_data_.data(), read_result));
}

// Tests that pipe2() fails with EINVAL if given any flags outside of O_CLOEXEC
// | O_DIRECT | O_NONBLOCK.
TEST(FixturelessPipeTest, Pipe2RejectsUnknownFlags) {
  constexpr int kBadFlags = 0xf & ~(O_CLOEXEC | O_DIRECT | O_NONBLOCK);

  int pipe_fds[2];
  EXPECT_THAT(pipe2(pipe_fds, O_DIRECT | kBadFlags), Eq(-1));
  EXPECT_THAT(errno, Eq(EINVAL));
}

// Tests that many pipes can be opened.
TEST(FixturelessPipeTest, ManyPipesCanBeOpened) {
  constexpr int kNumPipes = 500;

  std::vector<std::array<int, 2>> pipes;
  pipes.reserve(kNumPipes);
  for (int i = 0; i < kNumPipes; ++i) {
    pipes.emplace_back();
    ASSERT_THAT(pipe(pipes.back().data()), Eq(0))
        << strerror(errno) << " at pipe " << i;
  }

  for (int i = 0; i < kNumPipes; ++i) {
    EXPECT_THAT(close(pipes[i][0]), Eq(0))
        << strerror(errno) << " at pipe " << i;
    EXPECT_THAT(close(pipes[i][1]), Eq(0))
        << strerror(errno) << " at pipe " << i;
  }
}

// Tests that O_CLOEXEC pipes have the FD_CLOEXEC file descriptor flag set.
TEST_F(CloexecPipeTest, OCloexecPipesHaveFdCloexecFlagSet) {
  int fd_flags = fcntl(read_fd_, F_GETFD, 0);
  ASSERT_THAT(fd_flags, Ne(-1)) << strerror(errno);
  EXPECT_TRUE(fd_flags & FD_CLOEXEC);

  fd_flags = fcntl(write_fd_, F_GETFD, 0);
  ASSERT_THAT(fd_flags, Ne(-1)) << strerror(errno);
  EXPECT_TRUE(fd_flags & FD_CLOEXEC);
}

// Tests that the writing file descriptor of an O_DIRECT pipe has O_DIRECT set
// in its file status flags.
TEST_F(DirectPipeTest, WriteFdOnODirectPipeHasODirectFlagSet) {
  int fd_flags = fcntl(write_fd_, F_GETFL, 0);
  ASSERT_THAT(fd_flags, Ne(-1)) << strerror(errno);
  EXPECT_TRUE(fd_flags & O_DIRECT);
}

// Tests that writes of greater than PIPE_BUF bytes to non-blocking O_DIRECT
// pipes succeed.
using DirectNonblockPipeTest = Pipe2Test<O_DIRECT | O_NONBLOCK>;
TEST_F(DirectNonblockPipeTest,
       LargeWritesToODirectPipesSucceedAndWriteOnlyPipeBufBytes) {
  EXPECT_THAT(write(write_fd_, large_data_.data(), large_data_.size()),
              Eq(pipe_capacity_data_.size()))
      << strerror(errno);
}

// Tests that reads of less than PIPE_BUF bytes from O_DIRECT pipes succeed and
// discard the rest of the packet they read from.
TEST_F(DirectPipeTest,
       SmallReadsFromODirectPipesSucceedAndDiscardRestOfPacket) {
  std::vector<uint8_t> read_buf(PIPE_BUF / 2);
  ASSERT_THAT(write(write_fd_, packet_data_.data(), packet_data_.size()),
              Eq(PIPE_BUF))
      << strerror(errno);
  ASSERT_THAT(read(read_fd_, read_buf.data(), PIPE_BUF / 2), Eq(PIPE_BUF / 2));
  EXPECT_THAT(read_buf.data(), MemEq(packet_data_.data(), PIPE_BUF / 2));

  ASSERT_THAT(write(write_fd_, packet_data_.data(), packet_data_.size()),
              Eq(PIPE_BUF))
      << strerror(errno);
  ASSERT_THAT(read(read_fd_, read_buf.data(), PIPE_BUF / 2), Eq(PIPE_BUF / 2));
  EXPECT_THAT(read_buf.data(), MemEq(packet_data_.data(), PIPE_BUF / 2));
}

// Tests that reads of PIPE_BUF bytes from O_DIRECT pipes succeed.
TEST_F(DirectPipeTest, PipeBufSizedReadsFromODirectPipesSucceed) {
  ASSERT_THAT(write(write_fd_, packet_data_.data(), packet_data_.size()),
              Eq(PIPE_BUF))
      << strerror(errno);

  std::vector<uint8_t> read_buf(PIPE_BUF);

  ASSERT_THAT(read(read_fd_, read_buf.data(), PIPE_BUF), Eq(PIPE_BUF));
  EXPECT_THAT(read_buf.data(), MemEq(packet_data_.data(), PIPE_BUF));
}

// Tests that reads of greater than PIPE_BUF bytes from O_DIRECT pipes succeed
// but only read PIPE_BUF bytes.
TEST_F(DirectPipeTest,
       LargeReadsFromODirectPipesSucceedButOnlyReadPipeBufBytes) {
  if (PIPE_BUF < pipe_capacity_data_.size()) {
    ASSERT_THAT(write(write_fd_, packet_data_.data(), packet_data_.size()),
                Eq(PIPE_BUF))
        << strerror(errno);
    ASSERT_THAT(write(write_fd_, pipe_capacity_data_.data(),
                      pipe_capacity_data_.size() - PIPE_BUF),
                Eq(pipe_capacity_data_.size() - PIPE_BUF))
        << strerror(errno);

    std::vector<uint8_t> read_buf(pipe_capacity_data_.size());

    ASSERT_THAT(read(read_fd_, read_buf.data(), read_buf.size()), Eq(PIPE_BUF));
    EXPECT_THAT(read_buf.data(), MemEq(packet_data_.data(), PIPE_BUF));
  }
}

// Tests that non-blocking pipes have the O_NONBLOCK file status flag set.
TEST_F(NonblockPipeTest, NonBlockingPipesHaveONonblockFileStatusFlag) {
  int fd_flags = fcntl(read_fd_, F_GETFL, 0);
  ASSERT_THAT(fd_flags, Ne(-1)) << strerror(errno);
  EXPECT_TRUE(fd_flags & O_NONBLOCK);

  fd_flags = fcntl(write_fd_, F_GETFL, 0);
  ASSERT_THAT(fd_flags, Ne(-1)) << strerror(errno);
  EXPECT_TRUE(fd_flags & O_NONBLOCK);
}

// Tests that medium-sized writes to a non-blocking pipe succeed.
TEST_F(NonblockPipeTest, CapacitySizedWritesToNonBlockingPipesSucceed) {
  EXPECT_THAT(
      write(write_fd_, pipe_capacity_data_.data(), pipe_capacity_data_.size()),
      Eq(pipe_capacity_data_.size()))
      << strerror(errno);
}

// Tests that writes to a full non-blocking pipe fail with EAGAIN.
TEST_F(NonblockPipeTest, LargeWritesToNonBlockingPipesFailWithEAgain) {
  ASSERT_THAT(
      write(write_fd_, pipe_capacity_data_.data(), pipe_capacity_data_.size()),
      Eq(pipe_capacity_data_.size()))
      << strerror(errno);

  ASSERT_THAT(write(write_fd_, small_data_.data(), small_data_.size()), Eq(-1));
  EXPECT_THAT(errno, Eq(EAGAIN));
}

// Tests that reads from an empty non-blocking pipe fail with EAGAIN.
TEST_F(NonblockPipeTest, ReadsFromEmptyNonBlockingPipesFailWithEAgain) {
  uint8_t read_val;
  ASSERT_THAT(read(read_fd_, &read_val, 1), Eq(-1));
  EXPECT_THAT(errno, Eq(EAGAIN));
}

// Tests that medium-sized reads from a full non-blocking pipe succeed.
TEST_F(NonblockPipeTest, CapacitySizedReadsFromFullNonBlockingPipesSucceed) {
  ASSERT_THAT(
      write(write_fd_, pipe_capacity_data_.data(), pipe_capacity_data_.size()),
      Eq(pipe_capacity_data_.size()))
      << strerror(errno);

  std::vector<uint8_t> read_buf(pipe_capacity_data_.size());

  ASSERT_THAT(read(read_fd_, read_buf.data(), read_buf.size()),
              Eq(read_buf.size()))
      << strerror(errno);
  EXPECT_THAT(read_buf.data(),
              MemEq(pipe_capacity_data_.data(), pipe_capacity_data_.size()));
}

// Tests that large-sized reads from a full non-blocking pipe fail with EAGAIN.
TEST_F(NonblockPipeTest, LargeReadsFromFullNonBlockingPipesSucceed) {
  ASSERT_THAT(
      write(write_fd_, pipe_capacity_data_.data(), pipe_capacity_data_.size()),
      Eq(pipe_capacity_data_.size()))
      << strerror(errno);

  std::vector<uint8_t> read_buf(large_data_.size());

  ASSERT_THAT(read(read_fd_, read_buf.data(), read_buf.size()),
              Eq(pipe_capacity_data_.size()))
      << strerror(errno);
  EXPECT_THAT(read_buf.data(),
              MemEq(pipe_capacity_data_.data(), pipe_capacity_data_.size()));
}

// Tests that updates to the size of a pipe are visible when the size is read.
TEST_F(PipeTest, FcntlFSetpipeSzChangesPipeSize) {
  if (EnlargePipe()) {
    int new_pipe_size = fcntl(write_fd_, F_GETPIPE_SZ, 0);
    ASSERT_THAT(new_pipe_size, Ne(-1)) << strerror(errno);
    EXPECT_THAT(new_pipe_size, Eq(pipe_capacity_data_.size()));
  }
}

// Tests that a resized pipe fills up when a number of bytes equal to its new
// size have been written.
TEST_F(NonblockPipeTest, ResizedPipesHaveSmallerCapacity) {
  if (EnlargePipe()) {
    ASSERT_THAT(write(write_fd_, pipe_capacity_data_.data(),
                      pipe_capacity_data_.size()),
                Eq(pipe_capacity_data_.size()))
        << strerror(errno);
    ASSERT_THAT(write(write_fd_, small_data_.data(), small_data_.size()),
                Eq(-1));
    EXPECT_THAT(errno, Eq(EAGAIN));
  }
}

// Tests that fcntl() cannot shrink a pipe's size below the number of bytes
// currently in it.
TEST_F(PipeTest, FcntlCannotShrinkPipeBelowCurrentlyHeldBytes) {
  // Pipes cannot be made smaller than one memory page.
  constexpr int kMinimumPipeSize = 4096;

  if (EnlargePipe()) {
    ASSERT_THAT(write(write_fd_, pipe_capacity_data_.data(),
                      pipe_capacity_data_.size()),
                Eq(pipe_capacity_data_.size()))
        << strerror(errno);

    ASSERT_THAT(fcntl(write_fd_, F_SETPIPE_SZ, kMinimumPipeSize), Eq(-1));
    EXPECT_THAT(errno, Eq(EBUSY));
  }
}

}  // namespace
}  // namespace asylo
