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

#include <sys/select.h>

#include <algorithm>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "asylo/platform/storage/utils/fd_closer.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/posix_errors.h"

namespace asylo {
namespace {

constexpr const char *kMessage = "Pipe message";
constexpr int kRead = 0;
constexpr int kWrite = 1;

class SelectTest : public ::testing::Test {
 protected:
  Status WriteToFile(int fd, const char *message) {
    size_t bytes_left = strlen(message);
    while (bytes_left > 0) {
      ssize_t bytes_written = write(fd, message, bytes_left);
      if (bytes_written < 0) {
        return LastPosixError("write failed");
      }
      bytes_left -= bytes_written;
    }
    return absl::OkStatus();
  }

  void RunSelectTest(bool is_read_test) {
    ASSERT_EQ(pipe(fd_pairs_), 0);
    platform::storage::FdCloser fd_closer_read(fd_pairs_[0]);
    platform::storage::FdCloser fd_closer_write(fd_pairs_[1]);
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(fd_pairs_[kRead], &fds);
    FD_SET(fd_pairs_[kWrite], &fds);

    struct timeval timeout;
    timeout.tv_sec = 3;
    timeout.tv_usec = 0;
    int nfds = std::max(fd_pairs_[kRead], fd_pairs_[kWrite]) + 1;

    if (is_read_test) {
      // Write to the write end to make sure the other end is ready to read.
      ASSERT_THAT(WriteToFile(fd_pairs_[kWrite], kMessage), IsOk());
      ASSERT_EQ(select(nfds, &fds, /*writefds=*/nullptr, /*exceptfds=*/nullptr,
                       &timeout),
                1);
      // For read, confirm that the returned |fds| contains the read fd, but not
      // the write fd.
      EXPECT_TRUE(FD_ISSET(fd_pairs_[kRead], &fds));
      EXPECT_FALSE(FD_ISSET(fd_pairs_[kWrite], &fds));
    } else {
      ASSERT_EQ(select(nfds, /*readfds=*/nullptr, &fds, /*exceptfds=*/nullptr,
                       &timeout),
                1);
      // For write, confirm that the returned |fds| contains the write fd, but
      // not the read fd.
      EXPECT_TRUE(FD_ISSET(fd_pairs_[kWrite], &fds));
      EXPECT_FALSE(FD_ISSET(fd_pairs_[kRead], &fds));
    }
  }

 private:
  int fd_pairs_[2];
};

TEST_F(SelectTest, Read) { RunSelectTest(true); }

TEST_F(SelectTest, Write) { RunSelectTest(false); }

}  // namespace
}  // namespace asylo
