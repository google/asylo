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

#include <byteswap.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace asylo {
namespace {

TEST(ByteSwapTest, Swaps) {
  EXPECT_EQ(bswap_16(0x1234), 0x3412);
  EXPECT_EQ(bswap_32(0x12345678), 0x78563412);
  EXPECT_EQ(bswap_64(0x1234567890abcdef), 0xefcdab9078563412);
}

}  // namespace
}  // namespace asylo
