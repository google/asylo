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

#include "asylo/identity/util/bit_vector_128_util.h"

#include <gtest/gtest.h>
#include "asylo/identity/util/bit_vector_128.pb.h"

namespace asylo {
namespace {

constexpr uint64_t kConstVal1 = 0x12345678;
constexpr uint64_t kConstVal2 = 0x87654321;
constexpr uint64_t kZero = 0x0;

// A test fixture is used to ensure naming correctness and future
// expandability.
class BitVector128Test : public ::testing::Test {
 protected:
};

TEST_F(BitVector128Test, EqualityOperatorPositive) {
  BitVector128 left, right;
  left.set_high(kConstVal1);
  left.set_low(kConstVal2);
  right.set_high(kConstVal1);
  right.set_low(kConstVal2);
  EXPECT_TRUE(left == right);
}

TEST_F(BitVector128Test, EqualityOperatorNegative) {
  BitVector128 left, right;
  left.set_high(kConstVal1);
  left.set_low(kConstVal2);
  EXPECT_FALSE(left == right);
}

TEST_F(BitVector128Test, InequalityOperatorNegative) {
  BitVector128 left, right;
  left.set_high(kConstVal1);
  left.set_low(kConstVal2);
  right.set_high(kConstVal1);
  right.set_low(kConstVal2);
  EXPECT_FALSE(left != right);
}

TEST_F(BitVector128Test, InequalityOperatorPositive) {
  BitVector128 left, right;
  left.set_low(kConstVal2);
  right.set_high(kConstVal1);
  EXPECT_TRUE(left != right);
}

TEST_F(BitVector128Test, BitwiseAndCorrectness1) {
  BitVector128 left, right, result;
  left.set_high(kConstVal1);
  left.set_low(kConstVal2);
  EXPECT_TRUE((left & right) == result);
}

TEST_F(BitVector128Test, BitwiseAndCorrectness2) {
  BitVector128 left, right, result;
  left.set_high(kConstVal1);
  left.set_low(kConstVal2);
  right.set_high(kConstVal1);
  right.set_low(kConstVal2);
  result.set_high(kConstVal1);
  result.set_low(kConstVal2);
  EXPECT_TRUE((left & right) == result);
}

TEST_F(BitVector128Test, BitwiseAndCorrectness3) {
  BitVector128 left, right, result;
  left.set_high(kConstVal1);
  left.set_low(kConstVal2);
  right.set_high(kConstVal1);
  result.set_high(kConstVal1);
  EXPECT_TRUE((left & right) == result);
}

TEST_F(BitVector128Test, BitwiseAndCorrectness4) {
  BitVector128 left, right, result;
  left.set_low(kConstVal2);
  right.set_high(kConstVal1);
  EXPECT_TRUE((left & right) == result);
}

TEST_F(BitVector128Test, BitwiseAndCorrectness5) {
  BitVector128 left, right, result;
  right.set_high(kConstVal1);
  EXPECT_TRUE((left & right) == result);
}

TEST_F(BitVector128Test, BitwiseAndCorrectness6) {
  BitVector128 left, right, result;
  left.set_low(kZero);
  right.set_high(kZero);
  result.set_high(kZero);
  EXPECT_TRUE((left & right) == result);
}

}  // namespace
}  // namespace asylo
