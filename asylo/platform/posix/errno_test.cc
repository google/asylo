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

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/flags/flag.h"
#include "asylo/platform/storage/utils/fd_closer.h"
#include "asylo/test/util/test_flags.h"

namespace asylo {
namespace {

constexpr char accessible_directory[] = "/tmp";
constexpr char file_path[] = "/errno_test";
constexpr char bad_file_path[] = "/errno_test/disallowed";
constexpr char empty_path[] = "";

void CheckHostErrno(const char *path, int expected_errno) {
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  platform::storage::FdCloser fd_closer(fd);
  EXPECT_EQ(fd, -1);
  EXPECT_EQ(errno, expected_errno);
}

TEST(EnclaveErrnoTest, ENOTDIRTest) {
  // Create a regular file.
  std::string path = absl::GetFlag(FLAGS_test_tmpdir) + file_path;
  int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
  ASSERT_NE(fd, -1);
  ASSERT_EQ(close(fd), 0);

  // Try to create a file treating the earlier file as a directory.
  path = absl::GetFlag(FLAGS_test_tmpdir) + bad_file_path;
  CheckHostErrno(path.c_str(), ENOTDIR);
}

TEST(EnclaveErrnoTest, ENOENTTest) { CheckHostErrno(empty_path, ENOENT); }

TEST(EnclaveErrnoTest, EISDIRTest) {
  CheckHostErrno(accessible_directory, EISDIR);
}

}  // namespace
}  // namespace asylo
