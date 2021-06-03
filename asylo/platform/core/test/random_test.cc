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
#include <unistd.h>

#include <algorithm>
#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "asylo/util/logging.h"
#include "asylo/platform/storage/utils/fd_closer.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace {

StatusOr<std::string> ReadRandomBytes(const char *path, size_t read_bytes,
                                      size_t align_bytes) {
  int fd = open(path, O_RDONLY, 0);
  if (fd < 0) {
    return absl::InternalError(absl::StrCat("Failed to open path ", path));
  }
  platform::storage::FdCloser fd_closer(fd);
  uint8_t buf[128] = {};
  if (read_bytes > sizeof(buf) - 16) {
    return absl::InternalError(
        absl::StrCat("Invalid length requested: ", read_bytes));
  }
  if (align_bytes > 16) {
    return absl::InternalError(
        absl::StrCat("Invalid alignment requested: ", align_bytes));
  }
  size_t count = 0;
  while (count < read_bytes) {
    ssize_t status = read(fd, &buf[align_bytes + count], read_bytes - count);
    if (status < 0) {
      return absl::InternalError(
          absl::StrCat("Cannot read ", path, " (", strerror(errno), ")"));
    }
    count += status;
  }
  if (count != read_bytes) {
    return absl::InternalError(absl::StrCat("Incorrect read amount (", count,
                                            " != ", read_bytes, ")"));
  }

  // If reading unaligned (start or end), return the unread part so the test can
  // verify we didn't overrun.
  size_t return_bytes = (align_bytes + read_bytes + sizeof(uint64_t) - 1) /
                        sizeof(uint64_t) * sizeof(uint64_t);

  return std::string(&buf[0], &buf[return_bytes]);
}

StatusOr<std::string> ReadRandomBytesFromBoringSSL(size_t read_bytes) {
  uint8_t buf[128] = {};
  if (read_bytes > sizeof(buf)) {
    return absl::InternalError("Invalid number of bytes read");
  }
  if (!RAND_bytes(buf, read_bytes)) {
    return absl::InternalError("Cannot read random bytes");
  }
  return std::string(&buf[0], &buf[read_bytes]);
}

TEST(DevicesTest, RandomHandlerTest) {
  for (const char *path : {"/dev/random", "/dev/urandom"}) {
    for (size_t read_bytes = 1; read_bytes <= 32; ++read_bytes) {
      for (size_t align_bytes = 0; align_bytes < sizeof(uint64_t);
           ++align_bytes) {
        // Get random bytes.
        auto result1_or_error = ReadRandomBytes(path, read_bytes, align_bytes);
        ASYLO_ASSERT_OK(result1_or_error);
        std::string result1 = result1_or_error.value();
        // Get random bytes again.
        auto result2_or_error = ReadRandomBytes(path, read_bytes, align_bytes);
        ASYLO_ASSERT_OK(result2_or_error);
        std::string result2 = result2_or_error.value();

        // Check that we got different results (since it's random).
        // Skip if read_bytes less than 6 bytes; too likely to match by chance.
        if (read_bytes >= 6) {
          EXPECT_NE(result1, result2);
        }

        // Check that we got the expected number of bytes.
        size_t total = (read_bytes + align_bytes + sizeof(uint64_t) - 1) /
                       sizeof(uint64_t) * sizeof(uint64_t);
        EXPECT_EQ(result1.length(), total);
        EXPECT_EQ(result2.length(), total);

        // If we read unaligned, make sure we didn't overrun the intended
        // buffers.
        if (align_bytes) {
          EXPECT_EQ(result1.substr(0, align_bytes),
                    std::string(align_bytes, 0));
          EXPECT_EQ(result2.substr(0, align_bytes),
                    std::string(align_bytes, 0));
        }
        size_t extra = total - align_bytes - read_bytes;
        if (extra) {
          EXPECT_EQ(result1.substr(result1.size() - extra),
                    std::string(extra, 0));
          EXPECT_EQ(result2.substr(result2.size() - extra),
                    std::string(extra, 0));
        }
      }
    }
  }
}

TEST(BoringSSLTest, RandomHandlerTest) {
  int read_bytes = 16;
  // Read bytes from Boring SSL.
  auto result1_or_error = ReadRandomBytesFromBoringSSL(read_bytes);
  ASYLO_ASSERT_OK(result1_or_error);
  std::string result1 = result1_or_error.value();

  // Read bytes from Boring SSL again.
  auto result2_or_error = ReadRandomBytesFromBoringSSL(read_bytes);
  ASYLO_ASSERT_OK(result2_or_error);
  std::string result2 = result2_or_error.value();

  // Check that we got different results (since it's random).
  EXPECT_NE(result1, result2);

  // Check that we got the expected number of bytes.
  EXPECT_EQ(result1.length(), read_bytes);
  EXPECT_EQ(result2.length(), read_bytes);
}

}  // namespace
}  // namespace asylo
