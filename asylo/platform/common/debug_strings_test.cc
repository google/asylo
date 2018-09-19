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

#include "asylo/platform/common/debug_strings.h"
#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace asylo {
namespace {

using ::testing::Eq;
using ::testing::StrEq;

TEST(DebugStringsTest, Null) {
  EXPECT_THAT(buffer_to_hex_string(nullptr, 0), StrEq("null"));
}

TEST(DebugStringsTest, ZeroLength) {
  char buffer[] = "abc";
  EXPECT_THAT(buffer_to_hex_string(static_cast<const void *>(buffer), 0),
              StrEq("[]"));
}

TEST(DebugStringsTest, NegativeLength) {
  char buffer[] = "abc";
  EXPECT_THAT(buffer_to_hex_string(static_cast<const void *>(buffer), -4),
              StrEq("[ERROR: negative length -4]"));
}

TEST(DebugStringsTest, SingletonNullBuffer) {
  uint8_t buffer[] = {0};
  ASSERT_THAT(sizeof(buffer), Eq(1));
  EXPECT_THAT(buffer_to_hex_string(static_cast<const void *>(buffer), 1),
              StrEq("[0x00]"));
}

TEST(DebugStringsTest, NonemptyBufferDecimalDigits) {
  char buffer[] = "ABC";
  ASSERT_THAT(sizeof(buffer), Eq(4));
  EXPECT_THAT(buffer_to_hex_string(static_cast<const void *>(buffer), 4),
              StrEq("[0x41424300]"));
}

TEST(DebugStringsTest, NonemptyBufferHighDigits) {
  char buffer[] = "[-]";
  ASSERT_THAT(sizeof(buffer), Eq(4));
  EXPECT_THAT(buffer_to_hex_string(static_cast<const void *>(buffer), 4),
              StrEq("[0x5B2D5D00]"));
}

TEST(DebugStringsTest, NonemptyNullBuffer) {
  uint8_t buffer[] = {0, 0, 0, 0};
  ASSERT_THAT(sizeof(buffer), Eq(4));
  EXPECT_THAT(buffer_to_hex_string(static_cast<const void *>(buffer), 4),
              StrEq("[0x00000000]"));
}

}  // namespace
}  // namespace asylo
