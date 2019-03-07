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

using ::testing::Eq;

TEST(ByteSwapTest, Swaps) {
  // Binding bswap uses outside the macro uses avoids gcc errors, e.g.,
  // "error: statement-expressions are not allowed outside functions nor in
  //  template-argument lists"
  auto swap1 = bswap_16(0x1234);
  EXPECT_THAT(swap1, Eq(0x3412));
  auto swap2 = bswap_32(0x12345678);
  EXPECT_THAT(swap2, Eq(0x78563412));
  auto swap3 = bswap_64(0x1234567890abcdef);
  EXPECT_THAT(swap3, Eq(0xefcdab9078563412));
}

}  // namespace
}  // namespace asylo
