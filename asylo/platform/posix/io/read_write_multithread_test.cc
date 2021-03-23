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

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include <future>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/flags/flag.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/synchronization/mutex.h"
#include "asylo/platform/common/memory.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/test/util/test_flags.h"
#include "asylo/util/cleanup.h"
#include "asylo/util/posix_errors.h"
#include "asylo/util/status.h"

namespace asylo {
namespace {

// Controls the number of threads |LaunchThreads()| creates.
constexpr int kNumThreads = 9;

// Generates a random alpha-numeric string.
std::string GenerateRandomString() {
  constexpr int res_len = 10;
  std::string alpha_num =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890";
  std::string res;
  for (int i = 0; i < res_len; ++i) {
    res.push_back(alpha_num[rand() % alpha_num.size()]);
  }
  return res;
}

Status GenerateErrorStatusFromErrno(const char *message, const char *path) {
  return LastPosixError(absl::StrCat(message, ":", path));
}

// Writes to and reads from a file, checking that the file includes expected
// results.
// This returns Status because gtest assertions are not thread-safe on all
// platforms.
Status WriteRead(const char *path) {
  // Generate a random string so that each thread writes a different message.
  std::string message = GenerateRandomString();
  if (!path || !*path || message.empty()) {
    return PosixError(ENOMSG, "File path or message is empty");
  }

  int fd = open(path, O_CREAT | O_RDWR | O_APPEND, 0644);
  if (fd < 0) {
    return GenerateErrorStatusFromErrno("Failed to open file", path);
  }
  ssize_t rc = write(fd, message.c_str(), message.size());
  if (rc != message.size()) {
    return GenerateErrorStatusFromErrno("Failed to write to file", path);
  }
  if (close(fd) != 0) {
    return GenerateErrorStatusFromErrno("Failed to close file", path);
  }
  fd = open(path, O_CREAT | O_RDWR | O_APPEND, 0664);
  if (fd < 0) {
    return GenerateErrorStatusFromErrno("Failed to open file", path);
  }

  char buf[1024];
  rc = read(fd, buf, sizeof(buf));
  if (rc == -1) {
    return GenerateErrorStatusFromErrno("Failed to read from file", path);
  }
  if (rc >= sizeof(buf) || rc < message.size()) {
    return PosixError(
        EFAULT,
        absl::StrCat("Unexpected number of bytes read from file:", path));
  }
  if (!strstr(buf, message.c_str())) {
    return PosixError(EFAULT,
                      absl::StrCat("Unexpected message read from file:", path));
  }
  if (close(fd) != 0) {
    return GenerateErrorStatusFromErrno("Failed to close file", path);
  }
  return absl::OkStatus();
}

TEST(ReadWriteMultiThreadTest, MultiThreadTest) {
  // Assign random file name, to avoid potential conflict with other runs
  // on the same machine, current or prior.
  MallocUniquePtr<char> test_file(
      tempnam(absl::GetFlag(FLAGS_test_tmpdir).c_str(), "MRWT"));
  Cleanup remove_file([&test_file] { remove(test_file.get()); });

  // Creates kNumThreads that run the given |WriteRead| and waits for all
  // threads to join.
  std::vector<std::future<Status>> futures;

  for (int i = 0; i < kNumThreads; ++i) {
    futures.push_back(
        std::async(std::launch::async, &WriteRead, test_file.get()));
  }

  for (auto &result : futures) {
    EXPECT_THAT(result.get(), IsOk());
  }
}

}  // namespace
}  // namespace asylo
