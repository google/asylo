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
#include <openssl/rand.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <string>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/flags/flag.h"
#include "absl/strings/str_cat.h"
#include "asylo/util/logging.h"
#include "asylo/platform/common/memory.h"
#include "asylo/secure_storage.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/test/util/test_flags.h"
#include "asylo/util/cleansing_types.h"
#include "asylo/util/status.h"

namespace asylo {
namespace {

constexpr size_t kKeyLength = 32;
constexpr size_t kBlockLength = 128;

const char *kUntrustedTestText = "Lorem ipsum dolor sit amet...\n";
const char *kSecureTestText =
    "Nor again is there anyone who loves or pursues or desires to obtain pain "
    "of itself, ... but occasionally circumstances occur ...";

class ReadWriteTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // Assign random file name, to avoid potential conflict with other runs
    // on the same machine, current or prior.
    test_file_.reset(tempnam(absl::GetFlag(FLAGS_test_tmpdir).c_str(), "RWT"));
  }

  void TearDown() override {
    if (test_file_) {
      remove(test_file_.get());
    }
  }

  asylo::MallocUniquePtr<char> test_file_;
};

TEST_F(ReadWriteTest, FileDescriptorOrderingTest) {
  int fd1 = open(test_file_.get(), O_CREAT | O_RDWR, 0644);
  int fd2 = open(test_file_.get(), O_CREAT | O_RDWR, 0644);
  int fd3 = open(test_file_.get(), O_CREAT | O_RDWR, 0644);

  // Check that file descriptors are increasing by one.
  EXPECT_EQ(fd2, fd1 + 1);
  EXPECT_EQ(fd3, fd2 + 1);

  // Check that file descriptors are reused.
  close(fd1);
  close(fd2);
  close(fd3);
  EXPECT_EQ(open(test_file_.get(), O_CREAT | O_RDWR, 0644), fd1);
  EXPECT_EQ(open(test_file_.get(), O_CREAT | O_RDWR, 0644), fd2);
  EXPECT_EQ(open(test_file_.get(), O_CREAT | O_RDWR, 0644), fd3);
}

TEST_F(ReadWriteTest, ReadWriteUntrustedTest) {
  // Check that we can open a file for writing.
  int fd = open(test_file_.get(), O_CREAT | O_RDWR, 0644);
  ASSERT_GE(fd, 0);

  // Check that writing to the file succeeds.
  size_t rc = write(fd, kUntrustedTestText, strlen(kUntrustedTestText));
  EXPECT_EQ(rc, strlen(kUntrustedTestText));

  // Check that closing the file succeeds.
  EXPECT_EQ(close(fd), 0);

  // Check that we can reopen the file for reading.
  fd = open(test_file_.get(), O_RDONLY);
  ASSERT_GE(fd, 0);

  // Check that we can read back what we wrote.
  char buf1[1024];
  rc = read(fd, buf1, strlen(kUntrustedTestText));
  ASSERT_LT(rc, sizeof(buf1));
  EXPECT_EQ(rc, strlen(kUntrustedTestText));
  buf1[rc] = '\0';
  EXPECT_EQ(strcmp(buf1, kUntrustedTestText), 0);

  // Test lseek.
  off_t offset = 10;
  ASSERT_NE(lseek(fd, offset, SEEK_SET), -1);
  char buf2[1024];
  rc = read(fd, buf2, strlen(kUntrustedTestText) - offset);
  ASSERT_LT(rc, sizeof(buf2));
  EXPECT_EQ(rc, strlen(kUntrustedTestText) - offset);
  buf2[rc] = '\0';
  EXPECT_EQ(strcmp(buf2, kUntrustedTestText + offset), 0);

  EXPECT_EQ(fsync(fd), 0);

  // Check that closing the file succeeds.
  EXPECT_EQ(close(fd), 0);
}

TEST_F(ReadWriteTest, ReadWriteSecureTest) {
  // Generate secure key.
  CleansingVector<uint8_t> secure_key;
  secure_key.resize(kKeyLength);
  ASSERT_EQ(RAND_bytes(secure_key.data(), secure_key.size()), 1)
      << "RAND_bytes() failed";

  struct key_info ioctl_param;
  ioctl_param.length = secure_key.size();
  ioctl_param.data = secure_key.data();

  // Check that we can open a file for writing.
  int fd = open(test_file_.get(), O_CREAT | O_RDWR | O_SECURE, 0644);
  ASSERT_GE(fd, 0);

  EXPECT_EQ(ioctl(fd, ENCLAVE_STORAGE_SET_KEY, &ioctl_param), 0);

  // Check that writing to the file succeeds.
  size_t rc = write(fd, kSecureTestText, strlen(kSecureTestText));
  EXPECT_EQ(rc, strlen(kSecureTestText));

  // Check that closing the file succeeds.
  EXPECT_EQ(close(fd), 0);

  // Check that we can reopen the file for reading.
  fd = open(test_file_.get(), O_RDONLY | O_SECURE);
  ASSERT_GE(fd, 0);

  EXPECT_EQ(ioctl(fd, ENCLAVE_STORAGE_SET_KEY, &ioctl_param), 0);

  // Check that we can read back what we wrote.
  char buf1[1024];
  rc = read(fd, buf1, strlen(kSecureTestText));
  ASSERT_LT(rc, sizeof(buf1));
  EXPECT_EQ(rc, strlen(kSecureTestText));
  buf1[rc] = '\0';
  EXPECT_EQ(strncmp(buf1, kSecureTestText, kBlockLength), 0);

  // Test lseek.
  ASSERT_NE(lseek(fd, 0, SEEK_SET), -1);
  char buf2[1024];
  rc = read(fd, buf2, strlen(kSecureTestText));
  ASSERT_LT(rc, sizeof(buf2));
  EXPECT_EQ(rc, strlen(kSecureTestText));
  buf2[rc] = '\0';
  EXPECT_EQ(strncmp(buf2, kSecureTestText, kBlockLength), 0);

  EXPECT_EQ(fsync(fd), 0);

  // Check that closing the file succeeds.
  EXPECT_EQ(close(fd), 0);
}

}  // namespace
}  // namespace asylo
