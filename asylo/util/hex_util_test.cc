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

}  // namespace
}  // namespace asylo
