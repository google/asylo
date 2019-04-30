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

#include "asylo/platform/storage/utils/untrusted_file.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/platform/storage/utils/fd_closer.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/test/util/test_flags.h"

namespace asylo {
namespace {

// Create and open an empty temporary file, returning a file descriptor.
int CreateEmptyFile(absl::string_view basename) {
  std::string path = absl::StrCat(FLAGS_test_tmpdir, "/", basename);
  int result = open(path.c_str(), O_CREAT | O_EXCL | O_RDWR, S_IRUSR | S_IWUSR);
  CHECK_NE(result, -1) << "Could not create temporary file: " << path;
  return result;
}

TEST(UntrustedFileTest, WriteRead) {
  int fd = CreateEmptyFile("write_read.tmp");
  platform::storage::FdCloser closer(fd);

  UntrustedFile file(fd);
  EXPECT_THAT(file.Size(), IsOkAndHolds(0));

  constexpr int kCount = 1024;
  for (int i = 0; i < kCount; i++) {
    ASYLO_EXPECT_OK(file.Write(&i, i * sizeof(int), sizeof(int)));
  }

  ASYLO_EXPECT_OK(file.Sync());

  for (int i = 0; i < kCount; i++) {
    int record;
    ASYLO_EXPECT_OK(file.Read(&record, i * sizeof(int), sizeof(int)));
    EXPECT_EQ(record, i);
  }

  EXPECT_EQ(file.Size().ValueOrDie(), kCount * sizeof(int));
}

TEST(UntrustedFileTest, WriteHoles) {
  int fd = CreateEmptyFile("write_holes.tmp");
  asylo::platform::storage::FdCloser closer(fd);

  UntrustedFile file(fd);
  EXPECT_EQ(file.Size().ValueOrDie(), 0);
  constexpr int kCount = 1024;
  constexpr int kBlockSize = 256;

  // Write a byte every kBlockSize bytes.
  for (int i = 0; i < kCount; i++) {
    uint8_t ch = i % 256;
    ASYLO_EXPECT_OK(file.Write(&ch, i * kBlockSize, sizeof(uint8_t)));
  }

  for (int i = 0; i < kCount - 1; i++) {
    uint8_t buf[kBlockSize];
    // Ensure the first byte of the block was written correctly.
    ASYLO_EXPECT_OK(file.Read(buf, i * kBlockSize, kBlockSize));
    EXPECT_EQ(buf[0], i % 256);
    // Ensure the rest of the block is filled with zeros.
    for (int j = 1; j < kBlockSize; j++) {
      EXPECT_EQ(buf[j], 0);
    }
  }
}

}  // namespace
}  // namespace asylo
