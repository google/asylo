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
#include <cstdint>
#include <cstring>
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
using ::testing::Ne;

// The default size of a pipe. This is 16 pages on Linux, and currently the same
// in Asylo.
constexpr size_t kDefaultPipeSize = 16 * 4096;

// Pipes cannot be made smaller than one memory page.
constexpr int kSmallPipeSize = 4096;

class PipeTest : public ::testing::Test {
 public:
  PipeTest()
      : small_data_({'f', 'o', 'o', 'b', 'a', 'r', '\0'}),
        packet_data_(PIPE_BUF),
        medium_data_(kDefaultPipeSize),
        large_data_(4 * kDefaultPipeSize) {
    for (int i = 0; i < packet_data_.size(); ++i) {
      packet_data_[i] = std::bitset<8 * sizeof(i)>(i).count();
    }

    for (int i = 0; i < medium_data_.size(); ++i) {
      medium_data_[i] = ~std::bitset<8 * sizeof(i)>(i).count();
    }

    for (int i = 0; i < large_data_.size(); ++i) {
      large_data_[i] = 0xaa ^ std::bitset<8 * sizeof(i)>(i).count();
    }
  }

 protected:
  // Test data that should fit within a default-sized pipe's buffer without
  // filling it.
  std::vector<uint8_t> small_data_;

  // Test data that should take up an entire O_DIRECT pipe packet.
  std::vector<uint8_t> packet_data_;

  // Test data that should fill an empty default-sized pipe's buffer
  // without overflowing.
  std::vector<uint8_t> medium_data_;

  // Test data that should exceed a default-sized pipe's buffer.
  std::vector<uint8_t> large_data_;
};

// Tests that pipe() populates the pipe_fds array with two distinct, non-
// negative file descriptors.
TEST_F(PipeTest, PipeGivesValidFileDescriptorPairs) {
  int pipe_fds[2];
  ASSERT_THAT(pipe(pipe_fds), Eq(0)) << strerror(errno);
  int read_fd = pipe_fds[0];
  int write_fd = pipe_fds[1];
  Cleanup close_read(
      [read_fd] { ASSERT_THAT(close(read_fd), Eq(0)) << strerror(errno); });
  Cleanup close_write(
      [write_fd] { ASSERT_THAT(close(write_fd), Eq(0)) << strerror(errno); });

  EXPECT_THAT(read_fd, Ge(0));
  EXPECT_THAT(write_fd, Ge(0));
  EXPECT_THAT(read_fd, Ne(write_fd));
}

// Tests that pipe2() populates the pipe_fds array with two distinct, non-
// negative file descriptors.
TEST_F(PipeTest, Pipe2GivesValidFileDescriptorPairs) {
  int pipe_fds[2];
  ASSERT_THAT(pipe2(pipe_fds, 0), Eq(0)) << strerror(errno);
  int read_fd = pipe_fds[0];
  int write_fd = pipe_fds[1];
  Cleanup close_read(
      [read_fd] { ASSERT_THAT(close(read_fd), Eq(0)) << strerror(errno); });
  Cleanup close_write(
      [write_fd] { ASSERT_THAT(close(write_fd), Eq(0)) << strerror(errno); });

  EXPECT_THAT(read_fd, Ge(0));
  EXPECT_THAT(write_fd, Ge(0));
  EXPECT_THAT(read_fd, Ne(write_fd));
}

// Tests that the file descriptors returned by pipe() refer to FIFO files.
TEST_F(PipeTest, PipeFdsAreFifos) {
  int pipe_fds[2];
  ASSERT_THAT(pipe(pipe_fds), Eq(0)) << strerror(errno);
  int read_fd = pipe_fds[0];
  int write_fd = pipe_fds[1];
  Cleanup close_read(
      [read_fd] { ASSERT_THAT(close(read_fd), Eq(0)) << strerror(errno); });
  Cleanup close_write(
      [write_fd] { ASSERT_THAT(close(write_fd), Eq(0)) << strerror(errno); });

  struct stat statbuf;
  ASSERT_THAT(fstat(read_fd, &statbuf), Eq(0)) << strerror(errno);
  EXPECT_TRUE(S_ISFIFO(statbuf.st_mode));

  ASSERT_THAT(fstat(write_fd, &statbuf), Eq(0)) << strerror(errno);
  EXPECT_TRUE(S_ISFIFO(statbuf.st_mode));
}

// Tests that the file descriptors returned by pipe2() refer to FIFO files.
TEST_F(PipeTest, Pipe2FdsAreFifos) {
  int pipe_fds[2];
  ASSERT_THAT(pipe2(pipe_fds, 0), Eq(0)) << strerror(errno);
  int read_fd = pipe_fds[0];
  int write_fd = pipe_fds[1];
  Cleanup close_read(
      [read_fd] { ASSERT_THAT(close(read_fd), Eq(0)) << strerror(errno); });
  Cleanup close_write(
      [write_fd] { ASSERT_THAT(close(write_fd), Eq(0)) << strerror(errno); });

  struct stat statbuf;
  ASSERT_THAT(fstat(read_fd, &statbuf), Eq(0)) << strerror(errno);
  EXPECT_TRUE(S_ISFIFO(statbuf.st_mode));

  ASSERT_THAT(fstat(write_fd, &statbuf), Eq(0)) << strerror(errno);
  EXPECT_TRUE(S_ISFIFO(statbuf.st_mode));
}

// Tests that small writes to an open pipe succeed.
TEST_F(PipeTest, SmallWritingToOpenPipesSucceeds) {
  int pipe_fds[2];
  ASSERT_THAT(pipe(pipe_fds), Eq(0)) << strerror(errno);
  int read_fd = pipe_fds[0];
  int write_fd = pipe_fds[1];
  Cleanup close_read(
      [read_fd] { ASSERT_THAT(close(read_fd), Eq(0)) << strerror(errno); });
  Cleanup close_write(
      [write_fd] { ASSERT_THAT(close(write_fd), Eq(0)) << strerror(errno); });

  EXPECT_THAT(write(write_fd, small_data_.data(), small_data_.size()), Ge(0))
      << strerror(errno);
}

// Tests that PIPE_BUF-sized writes to an open pipe succeed.
TEST_F(PipeTest, MediumWritingToOpenPipesSucceeds) {
  int pipe_fds[2];
  ASSERT_THAT(pipe(pipe_fds), Eq(0)) << strerror(errno);
  int read_fd = pipe_fds[0];
  int write_fd = pipe_fds[1];
  Cleanup close_read(
      [read_fd] { ASSERT_THAT(close(read_fd), Eq(0)) << strerror(errno); });
  Cleanup close_write(
      [write_fd] { ASSERT_THAT(close(write_fd), Eq(0)) << strerror(errno); });

  EXPECT_THAT(write(write_fd, medium_data_.data(), medium_data_.size()), Ge(0))
      << strerror(errno);
}

// Tests that small writes to an open pipe2() pipe succeed.
TEST_F(PipeTest, SmallWritingToOpenPipe2PipesSucceeds) {
  int pipe_fds[2];
  ASSERT_THAT(pipe2(pipe_fds, 0), Eq(0)) << strerror(errno);
  int read_fd = pipe_fds[0];
  int write_fd = pipe_fds[1];
  Cleanup close_read(
      [read_fd] { ASSERT_THAT(close(read_fd), Eq(0)) << strerror(errno); });
  Cleanup close_write(
      [write_fd] { ASSERT_THAT(close(write_fd), Eq(0)) << strerror(errno); });

  EXPECT_THAT(write(write_fd, small_data_.data(), small_data_.size()), Ge(0))
      << strerror(errno);
}

// Tests that medium writes to an open pipe2() pipe succeed.
TEST_F(PipeTest, MediumWritingToOpenPipe2PipesSucceeds) {
  int pipe_fds[2];
  ASSERT_THAT(pipe2(pipe_fds, 0), Eq(0)) << strerror(errno);
  int read_fd = pipe_fds[0];
  int write_fd = pipe_fds[1];
  Cleanup close_read(
      [read_fd] { ASSERT_THAT(close(read_fd), Eq(0)) << strerror(errno); });
  Cleanup close_write(
      [write_fd] { ASSERT_THAT(close(write_fd), Eq(0)) << strerror(errno); });

  EXPECT_THAT(write(write_fd, medium_data_.data(), medium_data_.size()), Ge(0))
      << strerror(errno);
}

// Tests that reads from an open, non-empty pipe succeed when using small data.
TEST_F(PipeTest, ReadingFromOpenNonEmptyPipesSucceedsWithSmallData) {
  int pipe_fds[2];
  ASSERT_THAT(pipe(pipe_fds), Eq(0)) << strerror(errno);
  int read_fd = pipe_fds[0];
  int write_fd = pipe_fds[1];
  Cleanup close_read(
      [read_fd] { ASSERT_THAT(close(read_fd), Eq(0)) << strerror(errno); });
  Cleanup close_write(
      [write_fd] { ASSERT_THAT(close(write_fd), Eq(0)) << strerror(errno); });

  ASSERT_THAT(write(write_fd, small_data_.data(), small_data_.size()), Ge(0))
      << strerror(errno);

  std::vector<uint8_t> read_buf(small_data_.size());

  ssize_t read_result = read(read_fd, read_buf.data(), read_buf.size());
  ASSERT_THAT(read_result, Gt(0));
  EXPECT_THAT(read_buf.data(), MemEq(small_data_.data(), read_result));
}

// Tests that reads from an open, non-empty pipe2() pipe succeed when using
// small data.
TEST_F(PipeTest, ReadingFromOpenNonEmptyPipe2PipesSucceedsWithSmallData) {
  int pipe_fds[2];
  ASSERT_THAT(pipe2(pipe_fds, 0), Eq(0)) << strerror(errno);
  int read_fd = pipe_fds[0];
  int write_fd = pipe_fds[1];
  Cleanup close_read(
      [read_fd] { ASSERT_THAT(close(read_fd), Eq(0)) << strerror(errno); });
  Cleanup close_write(
      [write_fd] { ASSERT_THAT(close(write_fd), Eq(0)) << strerror(errno); });

  ASSERT_THAT(write(write_fd, small_data_.data(), small_data_.size()), Ge(0))
      << strerror(errno);

  std::vector<uint8_t> read_buf(small_data_.size());

  ssize_t read_result = read(read_fd, read_buf.data(), read_buf.size());
  ASSERT_THAT(read_result, Gt(0));
  EXPECT_THAT(read_buf.data(), MemEq(small_data_.data(), read_result));
}

// Tests that reads from an open, non-empty pipe succeed when using medium data.
TEST_F(PipeTest, ReadingFromOpenNonEmptyPipesSucceedsWithMediumData) {
  int pipe_fds[2];
  ASSERT_THAT(pipe(pipe_fds), Eq(0)) << strerror(errno);
  int read_fd = pipe_fds[0];
  int write_fd = pipe_fds[1];
  Cleanup close_read(
      [read_fd] { ASSERT_THAT(close(read_fd), Eq(0)) << strerror(errno); });
  Cleanup close_write(
      [write_fd] { ASSERT_THAT(close(write_fd), Eq(0)) << strerror(errno); });

  ASSERT_THAT(write(write_fd, medium_data_.data(), medium_data_.size()), Ge(0))
      << strerror(errno);

  std::vector<uint8_t> read_buf(medium_data_.size());

  ssize_t read_result = read(read_fd, read_buf.data(), read_buf.size());
  ASSERT_THAT(read_result, Gt(0));
  EXPECT_THAT(read_buf.data(), MemEq(medium_data_.data(), read_result));
}

// Tests that reads from an open, non-empty pipe2() pipe succeed when using
// medium data.
TEST_F(PipeTest, ReadingFromOpenNonEmptyPipe2PipesSucceedsWithMediumData) {
  int pipe_fds[2];
  ASSERT_THAT(pipe2(pipe_fds, 0), Eq(0)) << strerror(errno);
  int read_fd = pipe_fds[0];
  int write_fd = pipe_fds[1];
  Cleanup close_read(
      [read_fd] { ASSERT_THAT(close(read_fd), Eq(0)) << strerror(errno); });
  Cleanup close_write(
      [write_fd] { ASSERT_THAT(close(write_fd), Eq(0)) << strerror(errno); });

  ASSERT_THAT(write(write_fd, medium_data_.data(), medium_data_.size()), Ge(0))
      << strerror(errno);

  std::vector<uint8_t> read_buf(medium_data_.size());

  ssize_t read_result = read(read_fd, read_buf.data(), read_buf.size());
  ASSERT_THAT(read_result, Gt(0));
  EXPECT_THAT(read_buf.data(), MemEq(medium_data_.data(), read_result));
}

// Tests that reads from an open, non-empty pipe succeed when using medium data,
// but only reading part of the written data.
TEST_F(PipeTest,
       ReadingFromOpenNonEmptyPipesSucceedsWhenReadingPartOfWrittenData) {
  int pipe_fds[2];
  ASSERT_THAT(pipe(pipe_fds), Eq(0)) << strerror(errno);
  int read_fd = pipe_fds[0];
  int write_fd = pipe_fds[1];
  Cleanup close_read(
      [read_fd] { ASSERT_THAT(close(read_fd), Eq(0)) << strerror(errno); });
  Cleanup close_write(
      [write_fd] { ASSERT_THAT(close(write_fd), Eq(0)) << strerror(errno); });

  ASSERT_THAT(write(write_fd, medium_data_.data(), medium_data_.size()), Ge(0))
      << strerror(errno);

  std::vector<uint8_t> read_buf(medium_data_.size() / 2);

  ssize_t read_result = read(read_fd, read_buf.data(), read_buf.size());
  ASSERT_THAT(read_result, Gt(0));
  EXPECT_THAT(read_buf.data(), MemEq(medium_data_.data(), read_result));
}

// Tests that reads from an open, non-empty pipe2() pipe succeed when using
// medium data, but only reading part of the written data.
TEST_F(PipeTest,
       ReadingFromOpenNonEmptyPipe2PipesSucceedsWhenReadingPartOfWrittenData) {
  int pipe_fds[2];
  ASSERT_THAT(pipe2(pipe_fds, 0), Eq(0)) << strerror(errno);
  int read_fd = pipe_fds[0];
  int write_fd = pipe_fds[1];
  Cleanup close_read(
      [read_fd] { ASSERT_THAT(close(read_fd), Eq(0)) << strerror(errno); });
  Cleanup close_write(
      [write_fd] { ASSERT_THAT(close(write_fd), Eq(0)) << strerror(errno); });

  ASSERT_THAT(write(write_fd, medium_data_.data(), medium_data_.size()), Ge(0))
      << strerror(errno);

  std::vector<uint8_t> read_buf(medium_data_.size() / 2);

  ssize_t read_result = read(read_fd, read_buf.data(), read_buf.size());
  ASSERT_THAT(read_result, Gt(0));
  EXPECT_THAT(read_buf.data(), MemEq(medium_data_.data(), read_result));
}

// Tests that pipe2() fails with EINVAL if given any flags outside of O_CLOEXEC
// | O_DIRECT | O_NONBLOCK.
TEST_F(PipeTest, Pipe2RejectsUnknownFlags) {
  constexpr int kBadFlags = 0xf & ~(O_CLOEXEC | O_DIRECT | O_NONBLOCK);

  int pipe_fds[2];
  EXPECT_THAT(pipe2(pipe_fds, O_DIRECT | kBadFlags), Eq(-1));
  EXPECT_THAT(errno, Eq(EINVAL));
}

// Tests that many pipes can be opened.
TEST_F(PipeTest, ManyPipesCanBeOpened) {
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

// Tests that O_CLOEXEC pipes behave like any other pipe. Inside enclaves,
// O_CLOEXEC is a meaningless flags, since enclaves do not support exec().
TEST_F(PipeTest, OCloexecPipesAreNormalPipes) {
  int pipe_fds[2];
  ASSERT_THAT(pipe2(pipe_fds, O_CLOEXEC), Eq(0)) << strerror(errno);
  int read_fd = pipe_fds[0];
  int write_fd = pipe_fds[1];
  Cleanup close_read(
      [read_fd] { ASSERT_THAT(close(read_fd), Eq(0)) << strerror(errno); });
  Cleanup close_write(
      [write_fd] { ASSERT_THAT(close(write_fd), Eq(0)) << strerror(errno); });

  EXPECT_THAT(write(write_fd, medium_data_.data(), medium_data_.size()), Ge(0))
      << strerror(errno);

  std::vector<uint8_t> read_buf(medium_data_.size());

  ssize_t read_result = read(read_fd, read_buf.data(), medium_data_.size());
  ASSERT_THAT(read_result, Ge(0)) << strerror(errno);
  EXPECT_THAT(read_buf.data(), MemEq(medium_data_.data(), read_result));
}

// Tests that O_CLOEXEC pipes have the FD_CLOEXEC file descriptor flag set.
TEST_F(PipeTest, OCloexecPipesHaveFdCloexecFlagSet) {
  int pipe_fds[2];
  ASSERT_THAT(pipe2(pipe_fds, O_CLOEXEC), Eq(0)) << strerror(errno);
  int read_fd = pipe_fds[0];
  int write_fd = pipe_fds[1];
  Cleanup close_read(
      [read_fd] { ASSERT_THAT(close(read_fd), Eq(0)) << strerror(errno); });
  Cleanup close_write(
      [write_fd] { ASSERT_THAT(close(write_fd), Eq(0)) << strerror(errno); });

  int fd_flags = fcntl(read_fd, F_GETFD, 0);
  ASSERT_THAT(fd_flags, Ne(-1)) << strerror(errno);
  EXPECT_TRUE(fd_flags & FD_CLOEXEC);

  fd_flags = fcntl(write_fd, F_GETFD, 0);
  ASSERT_THAT(fd_flags, Ne(-1)) << strerror(errno);
  EXPECT_TRUE(fd_flags & FD_CLOEXEC);
}

// Tests that pipe2(..., O_DIRECT) returns two distinct, valid file descriptors.
TEST_F(PipeTest, Pipe2WithODirectGivesDistinctValidFileDescriptors) {
  int pipe_fds[2];
  ASSERT_THAT(pipe2(pipe_fds, O_DIRECT), Eq(0)) << strerror(errno);
  int read_fd = pipe_fds[0];
  int write_fd = pipe_fds[1];
  EXPECT_THAT(read_fd, Ge(0));
  EXPECT_THAT(write_fd, Ge(0));
  EXPECT_THAT(read_fd, Ne(write_fd));

  ASSERT_THAT(close(read_fd), Eq(0)) << strerror(errno);
  ASSERT_THAT(close(write_fd), Eq(0)) << strerror(errno);
}

// Tests that the writing file descriptor of an O_DIRECT pipe has O_DIRECT set
// in its file status flags.
TEST_F(PipeTest, WriteFdOnODirectPipeHasODirectFlagSet) {
  int pipe_fds[2];
  ASSERT_THAT(pipe2(pipe_fds, O_DIRECT), Eq(0)) << strerror(errno);
  int read_fd = pipe_fds[0];
  int write_fd = pipe_fds[1];
  Cleanup close_read(
      [read_fd] { ASSERT_THAT(close(read_fd), Eq(0)) << strerror(errno); });
  Cleanup close_write(
      [write_fd] { ASSERT_THAT(close(write_fd), Eq(0)) << strerror(errno); });

  int fd_flags = fcntl(write_fd, F_GETFL, 0);
  ASSERT_THAT(fd_flags, Ne(-1)) << strerror(errno);
  EXPECT_TRUE(fd_flags & O_DIRECT);
}

// Tests that writes of less than PIPE_BUF bytes to O_DIRECT pipes succeed and
// write all provided data.
TEST_F(PipeTest, SmallWritesToODirectPipesSucceedAndWriteAllData) {
  int pipe_fds[2];
  ASSERT_THAT(pipe2(pipe_fds, O_DIRECT), Eq(0)) << strerror(errno);
  int read_fd = pipe_fds[0];
  int write_fd = pipe_fds[1];
  Cleanup close_read(
      [read_fd] { ASSERT_THAT(close(read_fd), Eq(0)) << strerror(errno); });
  Cleanup close_write(
      [write_fd] { ASSERT_THAT(close(write_fd), Eq(0)) << strerror(errno); });

  EXPECT_THAT(write(write_fd, small_data_.data(), small_data_.size()),
              Eq(small_data_.size()))
      << strerror(errno);
}

// Tests that writes of PIPE_BUF bytes to O_DIRECT pipes succeed and write all
// provided data.
TEST_F(PipeTest, MediumWritesToODirectPipesSucceedAndWriteAllData) {
  int pipe_fds[2];
  ASSERT_THAT(pipe2(pipe_fds, O_DIRECT), Eq(0)) << strerror(errno);
  int read_fd = pipe_fds[0];
  int write_fd = pipe_fds[1];
  Cleanup close_read(
      [read_fd] { ASSERT_THAT(close(read_fd), Eq(0)) << strerror(errno); });
  Cleanup close_write(
      [write_fd] { ASSERT_THAT(close(write_fd), Eq(0)) << strerror(errno); });

  EXPECT_THAT(write(write_fd, medium_data_.data(), medium_data_.size()),
              Eq(medium_data_.size()))
      << strerror(errno);
}

// Tests that writes of greater than PIPE_BUF bytes to non-blocking O_DIRECT
// pipes succeed.
TEST_F(PipeTest, LargeWritesToODirectPipesSucceedAndWriteOnlyPipeBufBytes) {
  int pipe_fds[2];
  ASSERT_EQ(pipe2(pipe_fds, O_DIRECT | O_NONBLOCK), 0) << strerror(errno);
  int read_fd = pipe_fds[0];
  int write_fd = pipe_fds[1];
  Cleanup close_read(
      [read_fd] { ASSERT_THAT(close(read_fd), Eq(0)) << strerror(errno); });
  Cleanup close_write(
      [write_fd] { ASSERT_THAT(close(write_fd), Eq(0)) << strerror(errno); });

  EXPECT_THAT(write(write_fd, large_data_.data(), large_data_.size()),
              Eq(kDefaultPipeSize))
      << strerror(errno);
}

// Tests that reads of less than PIPE_BUF bytes from O_DIRECT pipes succeed and
// discard the rest of the packet they read from.
TEST_F(PipeTest, SmallReadsFromODirectPipesSucceedAndDiscardRestOfPacket) {
  int pipe_fds[2];
  ASSERT_THAT(pipe2(pipe_fds, O_DIRECT), Eq(0)) << strerror(errno);
  int read_fd = pipe_fds[0];
  int write_fd = pipe_fds[1];
  Cleanup close_read(
      [read_fd] { ASSERT_THAT(close(read_fd), Eq(0)) << strerror(errno); });
  Cleanup close_write(
      [write_fd] { ASSERT_THAT(close(write_fd), Eq(0)) << strerror(errno); });

  ASSERT_THAT(write(write_fd, packet_data_.data(), packet_data_.size()),
              Eq(PIPE_BUF))
      << strerror(errno);
  ASSERT_THAT(write(write_fd, packet_data_.data(), packet_data_.size()),
              Eq(PIPE_BUF))
      << strerror(errno);

  std::vector<uint8_t> read_buf(PIPE_BUF / 2);

  ASSERT_THAT(read(read_fd, read_buf.data(), PIPE_BUF / 2), Eq(PIPE_BUF / 2));
  EXPECT_THAT(read_buf.data(), MemEq(packet_data_.data(), PIPE_BUF / 2));

  ASSERT_THAT(read(read_fd, read_buf.data(), PIPE_BUF / 2), Eq(PIPE_BUF / 2));
  EXPECT_THAT(read_buf.data(), MemEq(packet_data_.data(), PIPE_BUF / 2));
}

// Tests that reads of PIPE_BUF bytes from O_DIRECT pipes succeed.
TEST_F(PipeTest, PipeBufSizedReadsFromODirectPipesSucceed) {
  int pipe_fds[2];
  ASSERT_THAT(pipe2(pipe_fds, O_DIRECT), Eq(0)) << strerror(errno);
  int read_fd = pipe_fds[0];
  int write_fd = pipe_fds[1];
  Cleanup close_read(
      [read_fd] { ASSERT_THAT(close(read_fd), Eq(0)) << strerror(errno); });
  Cleanup close_write(
      [write_fd] { ASSERT_THAT(close(write_fd), Eq(0)) << strerror(errno); });

  ASSERT_THAT(write(write_fd, packet_data_.data(), packet_data_.size()),
              Eq(PIPE_BUF))
      << strerror(errno);

  std::vector<uint8_t> read_buf(PIPE_BUF);

  ASSERT_THAT(read(read_fd, read_buf.data(), PIPE_BUF), Eq(PIPE_BUF));
  EXPECT_THAT(read_buf.data(), MemEq(packet_data_.data(), PIPE_BUF));
}

// Tests that reads of greater than PIPE_BUF bytes from O_DIRECT pipes succeed
// but only read PIPE_BUF bytes.
TEST_F(PipeTest, LargeReadsFromODirectPipesSucceedButOnlyReadPipeBufBytes) {
  int pipe_fds[2];
  ASSERT_THAT(pipe2(pipe_fds, O_DIRECT), Eq(0)) << strerror(errno);
  int read_fd = pipe_fds[0];
  int write_fd = pipe_fds[1];
  Cleanup close_read(
      [read_fd] { ASSERT_THAT(close(read_fd), Eq(0)) << strerror(errno); });
  Cleanup close_write(
      [write_fd] { ASSERT_THAT(close(write_fd), Eq(0)) << strerror(errno); });

  ASSERT_THAT(write(write_fd, packet_data_.data(), packet_data_.size()),
              Eq(PIPE_BUF))
      << strerror(errno);
  ASSERT_THAT(write(write_fd, packet_data_.data(), packet_data_.size()),
              Eq(PIPE_BUF))
      << strerror(errno);

  std::vector<uint8_t> read_buf(medium_data_.size());

  ASSERT_THAT(read(read_fd, read_buf.data(), read_buf.size()), Eq(PIPE_BUF));
  EXPECT_THAT(read_buf.data(), MemEq(packet_data_.data(), PIPE_BUF));
}

// Tests that non-blocking pipes have the O_NONBLOCK file status flag set.
TEST_F(PipeTest, NonBlockingPipesHaveONonblockFileStatusFlag) {
  int pipe_fds[2];
  ASSERT_THAT(pipe2(pipe_fds, O_NONBLOCK), Eq(0)) << strerror(errno);
  int read_fd = pipe_fds[0];
  int write_fd = pipe_fds[1];
  Cleanup close_read(
      [read_fd] { ASSERT_THAT(close(read_fd), Eq(0)) << strerror(errno); });
  Cleanup close_write(
      [write_fd] { ASSERT_THAT(close(write_fd), Eq(0)) << strerror(errno); });

  int fd_flags = fcntl(read_fd, F_GETFL, 0);
  ASSERT_THAT(fd_flags, Ne(-1)) << strerror(errno);
  EXPECT_TRUE(fd_flags & O_NONBLOCK);

  fd_flags = fcntl(write_fd, F_GETFL, 0);
  ASSERT_THAT(fd_flags, Ne(-1)) << strerror(errno);
  EXPECT_TRUE(fd_flags & O_NONBLOCK);
}

// Tests that medium-sized writes to a non-blocking pipe succeed.
TEST_F(PipeTest, MediumWritesToNonBlockingPipesSucceed) {
  int pipe_fds[2];
  ASSERT_THAT(pipe2(pipe_fds, O_NONBLOCK), Eq(0)) << strerror(errno);
  int read_fd = pipe_fds[0];
  int write_fd = pipe_fds[1];
  Cleanup close_read(
      [read_fd] { ASSERT_THAT(close(read_fd), Eq(0)) << strerror(errno); });
  Cleanup close_write(
      [write_fd] { ASSERT_THAT(close(write_fd), Eq(0)) << strerror(errno); });

  EXPECT_THAT(write(write_fd, medium_data_.data(), medium_data_.size()),
              Eq(medium_data_.size()))
      << strerror(errno);
}

// Tests that writes to a full non-blocking pipe fail with EAGAIN.
TEST_F(PipeTest, LargeWritesToNonBlockingPipesFailWithEAgain) {
  int pipe_fds[2];
  ASSERT_THAT(pipe2(pipe_fds, O_NONBLOCK), Eq(0)) << strerror(errno);
  int read_fd = pipe_fds[0];
  int write_fd = pipe_fds[1];
  Cleanup close_read(
      [read_fd] { ASSERT_THAT(close(read_fd), Eq(0)) << strerror(errno); });
  Cleanup close_write(
      [write_fd] { ASSERT_THAT(close(write_fd), Eq(0)) << strerror(errno); });

  ASSERT_THAT(write(write_fd, medium_data_.data(), medium_data_.size()),
              Eq(medium_data_.size()))
      << strerror(errno);

  ASSERT_THAT(write(write_fd, small_data_.data(), small_data_.size()), Eq(-1));
  EXPECT_THAT(errno, Eq(EAGAIN));
}

// Tests that reads from an empty non-blocking pipe fail with EAGAIN.
TEST_F(PipeTest, ReadsFromEmptyNonBlockingPipesFailWithEAgain) {
  int pipe_fds[2];
  ASSERT_THAT(pipe2(pipe_fds, O_NONBLOCK), Eq(0)) << strerror(errno);
  int read_fd = pipe_fds[0];
  int write_fd = pipe_fds[1];
  Cleanup close_read(
      [read_fd] { ASSERT_THAT(close(read_fd), Eq(0)) << strerror(errno); });
  Cleanup close_write(
      [write_fd] { ASSERT_THAT(close(write_fd), Eq(0)) << strerror(errno); });

  uint8_t read_val;
  ASSERT_THAT(read(read_fd, &read_val, 1), Eq(-1));
  EXPECT_THAT(errno, Eq(EAGAIN));
}

// Tests that medium-sized reads from a full non-blocking pipe succeed.
TEST_F(PipeTest, MediumReadsFromFullNonBlockingPipesSucceed) {
  int pipe_fds[2];
  ASSERT_THAT(pipe2(pipe_fds, O_NONBLOCK), Eq(0)) << strerror(errno);
  int read_fd = pipe_fds[0];
  int write_fd = pipe_fds[1];
  Cleanup close_read(
      [read_fd] { ASSERT_THAT(close(read_fd), Eq(0)) << strerror(errno); });
  Cleanup close_write(
      [write_fd] { ASSERT_THAT(close(write_fd), Eq(0)) << strerror(errno); });

  ASSERT_THAT(write(write_fd, medium_data_.data(), medium_data_.size()),
              Eq(medium_data_.size()))
      << strerror(errno);

  std::vector<uint8_t> read_buf(medium_data_.size());

  ASSERT_THAT(read(read_fd, read_buf.data(), read_buf.size()),
              Eq(read_buf.size()))
      << strerror(errno);
  EXPECT_THAT(read_buf.data(), MemEq(medium_data_.data(), medium_data_.size()));
}

// Tests that large-sized reads from a full non-blocking pipe fail with EAGAIN.
TEST_F(PipeTest, LargeReadsFromFullNonBlockingPipesSucceed) {
  int pipe_fds[2];
  ASSERT_THAT(pipe2(pipe_fds, O_NONBLOCK), Eq(0)) << strerror(errno);
  int read_fd = pipe_fds[0];
  int write_fd = pipe_fds[1];
  Cleanup close_read(
      [read_fd] { ASSERT_THAT(close(read_fd), Eq(0)) << strerror(errno); });
  Cleanup close_write(
      [write_fd] { ASSERT_THAT(close(write_fd), Eq(0)) << strerror(errno); });

  ASSERT_THAT(write(write_fd, medium_data_.data(), medium_data_.size()),
              Eq(medium_data_.size()))
      << strerror(errno);

  std::vector<uint8_t> read_buf(large_data_.size());

  ASSERT_THAT(read(read_fd, read_buf.data(), read_buf.size()),
              Eq(medium_data_.size()))
      << strerror(errno);
  EXPECT_THAT(read_buf.data(), MemEq(medium_data_.data(), medium_data_.size()));
}

// Tests that updates to the size of a pipe are visible when the size is read.
TEST_F(PipeTest, FcntlFSetpipeSzChangesPipeSize) {
  int pipe_fds[2];
  ASSERT_THAT(pipe(pipe_fds), Eq(0)) << strerror(errno);
  int read_fd = pipe_fds[0];
  int write_fd = pipe_fds[1];
  Cleanup close_read(
      [read_fd] { ASSERT_THAT(close(read_fd), Eq(0)) << strerror(errno); });
  Cleanup close_write(
      [write_fd] { ASSERT_THAT(close(write_fd), Eq(0)) << strerror(errno); });

  int pipe_size = fcntl(write_fd, F_GETPIPE_SZ, 0);
  ASSERT_THAT(pipe_size, Ne(-1)) << strerror(errno);
  EXPECT_THAT(pipe_size, Eq(kDefaultPipeSize));

  ASSERT_THAT(fcntl(write_fd, F_SETPIPE_SZ, kSmallPipeSize), Eq(kSmallPipeSize))
      << strerror(errno);

  pipe_size = fcntl(write_fd, F_GETPIPE_SZ, 0);
  ASSERT_THAT(pipe_size, Ne(-1)) << strerror(errno);
  EXPECT_THAT(pipe_size, Eq(kSmallPipeSize));
}

// Tests that a resized pipe fills up when a number of bytes equal to its new
// size have been written.
TEST_F(PipeTest, ResizedPipesHaveSmallerCapacity) {
  int pipe_fds[2];
  ASSERT_THAT(pipe2(pipe_fds, O_NONBLOCK), Eq(0)) << strerror(errno);
  int read_fd = pipe_fds[0];
  int write_fd = pipe_fds[1];
  Cleanup close_read(
      [read_fd] { ASSERT_THAT(close(read_fd), Eq(0)) << strerror(errno); });
  Cleanup close_write(
      [write_fd] { ASSERT_THAT(close(write_fd), Eq(0)) << strerror(errno); });

  ASSERT_THAT(fcntl(write_fd, F_SETPIPE_SZ, kSmallPipeSize), Eq(kSmallPipeSize))
      << strerror(errno);

  ASSERT_THAT(write(write_fd, medium_data_.data(), kSmallPipeSize),
              Eq(kSmallPipeSize))
      << strerror(errno);
  ASSERT_THAT(write(write_fd, small_data_.data(), small_data_.size()), Eq(-1));
  EXPECT_THAT(errno, Eq(EAGAIN));
}

// Tests that fcntl() cannot shrink a pipe's size below the number of bytes
// currently in it.
TEST_F(PipeTest, FcntlCannotShrinkPipeBelowCurrentlyHeldBytes) {
  int pipe_fds[2];
  ASSERT_THAT(pipe(pipe_fds), Eq(0)) << strerror(errno);
  int read_fd = pipe_fds[0];
  int write_fd = pipe_fds[1];
  Cleanup close_read(
      [read_fd] { ASSERT_THAT(close(read_fd), Eq(0)) << strerror(errno); });
  Cleanup close_write(
      [write_fd] { ASSERT_THAT(close(write_fd), Eq(0)) << strerror(errno); });

  ASSERT_THAT(write(write_fd, medium_data_.data(), medium_data_.size()),
              Eq(medium_data_.size()))
      << strerror(errno);

  ASSERT_THAT(fcntl(write_fd, F_SETPIPE_SZ, kSmallPipeSize), Eq(-1));
  EXPECT_THAT(errno, Eq(EBUSY));
}

}  // namespace
}  // namespace asylo
