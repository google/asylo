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

#include <cstring>
#include <memory>
#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/base/macros.h"
#include "asylo/platform/primitives/primitive_status.h"

namespace asylo {
namespace primitives {
namespace {

using ::testing::Eq;
using ::testing::StrEq;

std::string MakeTestString(size_t size) {
  std::string buffer;
  for (int i = 0; i < size; i++) {
    buffer.push_back('a' + i % 26);
  }
  return buffer;
}

TEST(PrimitiveStatusTest, PrimitiveStatusFromLengthAndSize) {
  const std::string kBuffer = MakeTestString(256);

  // Construct a PrimitiveStatus from a size and length, and ensure that null
  // termination is handled correctly.
  for (int i = 0; i < kBuffer.size(); i++) {
    for (int j = i; j < kBuffer.size(); j++) {
      const char *data = kBuffer.data() + i;
      size_t length = j - i;
      PrimitiveStatus status{0, data, length};
      EXPECT_THAT(status.error_message(), Eq(kBuffer.substr(i, length)));
    }
  }
}

TEST(PrimitiveStatusTest, MessageTooLarge) {
  // PrimitiveStatus can only fit kMessageMax-1 characters, because it must
  // account for the nul terminator.
  const std::string kMessage = MakeTestString(PrimitiveStatus::kMessageMax);
  PrimitiveStatus status{0, kMessage};
  EXPECT_THAT(status.error_message(),
              Eq(kMessage.substr(0, PrimitiveStatus::kMessageMax - 1)));
}

TEST(PrimitiveStatusTest, CopyConstruction) {
  const std::string kMessage = "Lorem ipsum";
  PrimitiveStatus original{0, kMessage};
  PrimitiveStatus copy{original};

  EXPECT_THAT(original.error_code(), Eq(copy.error_code()));
  EXPECT_THAT(original.error_message(), StrEq(copy.error_message()));
}

TEST(PrimitiveStatusTest, Asignment) {
  const std::string kMessage = "This is a test message";
  PrimitiveStatus original{0, kMessage};
  PrimitiveStatus copy{-1};

  copy = original;
  EXPECT_THAT(original.error_code(), Eq(copy.error_code()));
  EXPECT_THAT(original.error_message(), StrEq(copy.error_message()));
}

}  // namespace
}  // namespace primitives
}  // namespace asylo
