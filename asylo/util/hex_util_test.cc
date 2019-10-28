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

#include "asylo/util/hex_util.h"

#include <endian.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using ::testing::Eq;
using ::testing::StrEq;

namespace asylo {
namespace {

TEST(IsHexEncodedTest, NonHexStringReturnsFalse) {
  EXPECT_FALSE(IsHexEncoded("non hex string"));
}

TEST(IsHexEncoded, OddCharStringReturnsFalse) {
  EXPECT_FALSE(IsHexEncoded("123"));
}

TEST(IsHexEncodedTest, HexStringReturnsTrue) {
  EXPECT_TRUE(IsHexEncoded("1234567890ABCDEFabcdef"));
}

TEST(Uint16ToLeHexStringTest, Success) {
  EXPECT_EQ(Uint16ToLittleEndianHexString(le16toh(0x1234)), "3412");
  EXPECT_EQ(Uint16ToLittleEndianHexString(le16toh(0xabcd)), "cdab");
  EXPECT_EQ(Uint16ToLittleEndianHexString(le16toh(0x12)), "1200");
}

TEST(BufferToDebugHexString, Null) {
  EXPECT_THAT(BufferToDebugHexString(nullptr, 0), StrEq("null"));
}

TEST(BufferToDebugHexString, ZeroLength) {
  char buffer[] = "abc";
  EXPECT_THAT(BufferToDebugHexString(static_cast<const void*>(buffer), 0),
              StrEq("[]"));
}

TEST(BufferToDebugHexString, NegativeLength) {
  char buffer[] = "abc";
  EXPECT_THAT(BufferToDebugHexString(static_cast<const void*>(buffer), -4),
              StrEq("[ERROR: negative length -4]"));
}

TEST(BufferToDebugHexString, SingletonNullBuffer) {
  uint8_t buffer[] = {0};
  ASSERT_THAT(sizeof(buffer), Eq(1));
  EXPECT_THAT(BufferToDebugHexString(static_cast<const void*>(buffer), 1),
              StrEq("[0x00]"));
}

TEST(BufferToDebugHexString, NonemptyBufferDecimalDigits) {
  char buffer[] = "ABC";
  ASSERT_THAT(sizeof(buffer), Eq(4));
  EXPECT_THAT(BufferToDebugHexString(static_cast<const void*>(buffer), 4),
              StrEq("[0x41424300]"));
}

TEST(BufferToDebugHexString, NonemptyBufferHighDigits) {
  char buffer[] = "[-]";
  ASSERT_THAT(sizeof(buffer), Eq(4));
  EXPECT_THAT(BufferToDebugHexString(static_cast<const void*>(buffer), 4),
              StrEq("[0x5b2d5d00]"));
}

TEST(BufferToDebugHexString, NonemptyNullBuffer) {
  uint8_t buffer[] = {0, 0, 0, 0};
  ASSERT_THAT(sizeof(buffer), Eq(4));
  EXPECT_THAT(BufferToDebugHexString(static_cast<const void*>(buffer), 4),
              StrEq("[0x00000000]"));
}

}  // namespace
}  // namespace asylo
