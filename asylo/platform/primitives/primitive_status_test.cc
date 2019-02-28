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

TEST(PrimitiveStatusTest, PrimitiveStatusFromLengthAndSize) {
  std::string buffer;
  for (int i = 0; i < 256; i++) {
    buffer.push_back('a' + i % 26);
  }

  // Construct a PrimitiveStatus from a size and length, and ensure that null
  // termination is handled correctly.
  for (int i = 0; i < buffer.size(); i++) {
    for (int j = i; j < buffer.size(); j++) {
      const char *data = buffer.data() + i;
      size_t length = j - i;
      PrimitiveStatus status{0, data, length};
      EXPECT_THAT(status.error_message(), Eq(buffer.substr(i, length)));
    }
  }
}

}  // namespace
}  // namespace primitives
}  // namespace asylo
