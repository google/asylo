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

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/rand.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/flags/flag.h"
#include "absl/strings/str_cat.h"
#include "asylo/platform/primitives/random_bytes.h"
#include "asylo/platform/storage/utils/fd_closer.h"
#include "asylo/test/util/test_flags.h"

namespace asylo {
namespace {

using ::testing::IsNull;

// Tests changing working directory.
TEST(CwdTest, SimpleChange) {
  char buf[PATH_MAX];
  EXPECT_EQ(chdir("/tmp"), 0);
  EXPECT_STREQ(getcwd(buf, sizeof(buf)), "/tmp");
  EXPECT_EQ(chdir("/usr"), 0);
  EXPECT_STREQ(getcwd(buf, sizeof(buf)), "/usr");
}

// Tests changing working directory relative to current working directory.
TEST(CwdTest, RelativeChange) {
  char buf[PATH_MAX];
  EXPECT_EQ(chdir("/tmp"), 0);
  EXPECT_STREQ(getcwd(buf, sizeof(buf)), "/tmp");
  EXPECT_EQ(chdir("../usr"), 0);
  EXPECT_STREQ(getcwd(buf, sizeof(buf)), "/usr");
}

// Tests changing working directory using absolute path with '..'.
TEST(CwdTest, AbsoluteBackChange) {
  char buf[PATH_MAX];
  EXPECT_EQ(chdir("/tmp"), 0);
  EXPECT_STREQ(getcwd(buf, sizeof(buf)), "/tmp");
  EXPECT_EQ(chdir("/etc/../usr"), 0);
  EXPECT_STREQ(getcwd(buf, sizeof(buf)), "/usr");
}

// Tests changing working directory using relative path with '..'.
TEST(CwdTest, RelativeBackChange) {
  char buf[PATH_MAX];
  EXPECT_EQ(chdir("/tmp"), 0);
  EXPECT_STREQ(getcwd(buf, sizeof(buf)), "/tmp");
  EXPECT_EQ(chdir("../etc/../usr"), 0);
  EXPECT_STREQ(getcwd(buf, sizeof(buf)), "/usr");
}

// Tests changing working directory across different virtual path handlers.
TEST(CwdTest, CrossHandlerChange) {
  char buf[PATH_MAX];
  EXPECT_EQ(chdir("/tmp"), 0);
  EXPECT_STREQ(getcwd(buf, sizeof(buf)), "/tmp");
  EXPECT_EQ(chdir("../dev/random"), -1);
  EXPECT_EQ(errno, EACCES);
  EXPECT_STREQ(getcwd(buf, sizeof(buf)), "/tmp");
}

// Tests changing a working directory using a path that tries back past root.
TEST(CwdTest, PastRootChange) {
  char buf[PATH_MAX];
  EXPECT_EQ(chdir("/tmp"), 0);
  EXPECT_STREQ(getcwd(buf, sizeof(buf)), "/tmp");
  EXPECT_EQ(chdir("/../../"), 0);
  EXPECT_STREQ(getcwd(buf, sizeof(buf)), "/");
}

// Tests changing a working directory to an empty path.
TEST(CwdTest, EmptyChange) {
  char buf[PATH_MAX];
  EXPECT_EQ(chdir("/tmp"), 0);
  EXPECT_STREQ(getcwd(buf, sizeof(buf)), "/tmp");
  EXPECT_EQ(chdir(""), -1);
  EXPECT_EQ(errno, ENOENT);
  EXPECT_STREQ(getcwd(buf, sizeof(buf)), "/tmp");
}

// Tests opening a file using a relative path that crosses to a different path
// handler.
TEST(CwdTest, CrossHandlerResolve) {
  EXPECT_EQ(chdir("/tmp"), 0);
  EXPECT_EQ(open("../dev/random", O_RDONLY), -1);
  EXPECT_EQ(errno, EACCES);
}

// Tests opening a file and canonicalizing a path using an empty string.
TEST(CwdTest, EmptyResolve) {
  EXPECT_EQ(open("", O_RDONLY), -1);
  EXPECT_EQ(errno, ENOENT);

  char buf[PATH_MAX];
  EXPECT_THAT(realpath("", buf), IsNull());
  EXPECT_EQ(errno, ENOENT);
}

// Tests that relative path leads to same file as expected absolute path.
TEST(CwdTest, RelativeAbsoluteResolve) {
  // Set up the file to read, using an absolute path.
  uint8_t data[32];
  ASSERT_EQ(RAND_bytes(data, sizeof(data)), 1);
  int fd =
      open(absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/cwdtest").c_str(),
           O_RDWR | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);
  ASSERT_NE(fd, -1);
  asylo::platform::storage::FdCloser fd_closer(fd);
  ASSERT_NE(write(fd, data, sizeof(data)), -1);

  // Change to a sibling directory and use a relative path to access.
  EXPECT_EQ(
      chdir(absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/foo").c_str()), 0);
  fd = open("../cwdtest", O_RDONLY);
  ASSERT_NE(fd, -1);
  fd_closer.reset(fd);
  uint8_t result[32];
  ASSERT_NE(read(fd, result, sizeof(result)), -1);
  EXPECT_EQ(std::string(&data[0], &data[sizeof(data)]),
            std::string(&result[0], &result[sizeof(result)]));
}

// Tests matching a VirtualPathHandler when the prefix is obfuscated.
TEST(CwdTest, SplitHandlerResolve) {
  int fd = open("/dev/notrandom/../urandom", O_RDONLY);
  ASSERT_NE(fd, -1);
  asylo::platform::storage::FdCloser fd_closer(fd);

  // Make sure it didn't get the /dev/urandom from the host.
  #ifdef RNDINENCLAVE
  EXPECT_EQ(ioctl(fd, RNDINENCLAVE), 0);
  #endif
}

// Tests matching a VirtualPathHandler when the prefix is present, but backed up
// over.
TEST(CwdTest, SplitBackHandlerResolve) {
  int fd = open("/dev/random/../urandom", O_RDONLY);
  ASSERT_NE(fd, -1);
  asylo::platform::storage::FdCloser fd_closer(fd);

  #ifdef RNDINENCLAVE
  EXPECT_EQ(ioctl(fd, RNDINENCLAVE), 0);
  #endif

  // Make sure it matched urandom instead of random.
  constexpr unsigned int urandom_major = 1;
  constexpr unsigned int urandom_minor = 9;
  struct stat st;
  EXPECT_EQ(fstat(fd, &st), 0);
  EXPECT_EQ(st.st_rdev, makedev(urandom_major, urandom_minor));
}

}  // namespace
}  // namespace asylo
