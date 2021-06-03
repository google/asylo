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

#include "asylo/util/file_mapping.h"

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/flags/flag.h"
#include "absl/strings/string_view.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status.h"

ABSL_FLAG(std::string, test_file, "", "Location of test data file");

namespace asylo {
namespace {

// Text to overwrite part of the buffer with in tests of copy-on-write
// semantics.
constexpr char kReplaceText[] = "Merol";

class FileMappingTest : public ::testing::Test {
 public:
  void SetUp() override {
    std::ifstream test_file_stream(absl::GetFlag(FLAGS_test_file));
    std::stringstream file_string_stream;
    file_string_stream << test_file_stream.rdbuf();
    expected_file_contents_ = file_string_stream.str();
  }

 protected:
  std::string expected_file_contents_;
};

// Tests that default-constructed FileMapping objects don't cause crashes.
TEST(FileMappingFixturelessTest, DefaultConstructedMappingDoesntCrash) {
  FileMapping empty;
}

// Tests that a mapped file buffer has the same size and contents as the backing
// file.
TEST_F(FileMappingTest, MapsFileSuccessfully) {
  auto from_file_result =
      FileMapping::CreateFromFile(absl::GetFlag(FLAGS_test_file));
  ASSERT_THAT(from_file_result, IsOk());

  FileMapping mapping = std::move(from_file_result.value());
  EXPECT_EQ(mapping.buffer().size(), expected_file_contents_.size());
  EXPECT_EQ(memcmp(mapping.buffer().data(), expected_file_contents_.data(),
                   mapping.buffer().size()),
            0);
}

// Tests that updates to a mapped file buffer do not propagate to the original
// file, but are still visible in memory.
TEST_F(FileMappingTest, MapExhibitsCopyOnWriteSemantics) {
  // Open one mapping of the file and check that it has the expected contents.
  auto outer_from_file_result =
      FileMapping::CreateFromFile(absl::GetFlag(FLAGS_test_file));
  ASSERT_THAT(outer_from_file_result, IsOk());

  FileMapping outer_mapping = std::move(outer_from_file_result.value());
  ASSERT_EQ(outer_mapping.buffer().size(), expected_file_contents_.size());
  ASSERT_EQ(
      memcmp(outer_mapping.buffer().data(), expected_file_contents_.data(),
             outer_mapping.buffer().size()),
      0);

  // Modify the buffer.
  std::copy(kReplaceText, kReplaceText + strlen(kReplaceText),
            outer_mapping.buffer().data());

  {
    // Open another mapping of the same file.
    auto inner_from_file_result =
        FileMapping::CreateFromFile(absl::GetFlag(FLAGS_test_file));
    ASSERT_THAT(inner_from_file_result, IsOk());

    // Check that the new mapping has the same contents as the original file.
    FileMapping inner_mapping = std::move(inner_from_file_result.value());
    EXPECT_EQ(inner_mapping.buffer().size(), expected_file_contents_.size());
    EXPECT_EQ(
        memcmp(inner_mapping.buffer().data(), expected_file_contents_.data(),
               inner_mapping.buffer().size()),
        0);
  }

  // Check that the first mapping's buffer still has the modified contents.
  EXPECT_EQ(strncmp(reinterpret_cast<char *>(outer_mapping.buffer().data()),
                    kReplaceText, strlen(kReplaceText)),
            0);
}

}  // namespace
}  // namespace asylo
