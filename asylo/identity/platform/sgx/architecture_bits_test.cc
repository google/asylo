/*
 *
 * Copyright 2020 Asylo authors
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

#include "asylo/identity/platform/sgx/architecture_bits.h"

#include <bitset>
#include <cstddef>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace asylo {
namespace sgx {

// Ensure kValidAttributeFlagsBitmask is consistent with kAllAttributeBits.
TEST(ArchitecturalBitsTest, AttributesFlagBitmaskCorrect) {
  std::bitset<64> bitmask(kValidAttributeFlagsBitmask);
  std::bitset<64> expected;

  // Bits 0-63 are ATTRIBUTES flag bits.
  for (AttributeBit bit : kAllAttributeBits) {
    size_t bit_position = static_cast<size_t>(bit);
    if (bit_position < kNumAttributeFlagBits) {
      expected.set(bit_position);
    }
  }

  EXPECT_EQ(bitmask, expected);
}

// Ensure kValidAttributeXfrmBitmask is consistent with kAllAttributeBits.
TEST(ArchitecturalBitsTest, AttributesXfrmBitmaskCorrect) {
  std::bitset<64> bitmask(kValidAttributeXfrmBitmask);
  std::bitset<64> expected;

  // Bits 64-128 are ATTRIBUTES XFRM bits.
  for (AttributeBit bit : kAllAttributeBits) {
    size_t bit_position = static_cast<size_t>(bit);
    if (bit_position >= kNumAttributeFlagBits) {
      expected.set(bit_position - kNumAttributeFlagBits);
    }
  }

  EXPECT_EQ(bitmask, expected);
}

// Ensure kValidMiscselectBitmask is consistent with kAllMiscselectBits.
TEST(ArchitecturalBitstest, MiscselectBitmaskCorrect) {
  std::bitset<32> bitmask(kValidMiscselectBitmask);
  std::bitset<32> expected;

  for (MiscselectBit bit : kAllMiscselectBits) {
    size_t bit_position = static_cast<size_t>(bit);
    expected.set(bit_position);
  }

  EXPECT_EQ(bitmask, expected);
}

}  // namespace sgx
}  // namespace asylo
