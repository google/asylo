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

#include "asylo/identity/sgx/attributes_util.h"

#include <gtest/gtest.h>
#include "asylo/identity/sgx/attributes.pb.h"

namespace asylo {
namespace sgx {
namespace {

constexpr uint64_t kConstVal1 = 0x12345678;
constexpr uint64_t kConstVal2 = 0x87654321;
constexpr uint64_t kZero = 0x0;

// A test fixture is used to ensure naming correctness and future
// expandability.
class AttributesTest : public ::testing::Test {
 protected:
};

TEST_F(AttributesTest, EqualityOperatorPositive) {
  Attributes left, right;
  left.set_xfrm(kConstVal1);
  left.set_flags(kConstVal2);
  right.set_xfrm(kConstVal1);
  right.set_flags(kConstVal2);
  EXPECT_TRUE(left == right);
}

TEST_F(AttributesTest, EqualityOperatorNegative) {
  Attributes left, right;
  left.set_xfrm(kConstVal1);
  left.set_flags(kConstVal2);
  EXPECT_FALSE(left == right);
}

TEST_F(AttributesTest, InequalityOperatorNegative) {
  Attributes left, right;
  left.set_xfrm(kConstVal1);
  left.set_flags(kConstVal2);
  right.set_xfrm(kConstVal1);
  right.set_flags(kConstVal2);
  EXPECT_FALSE(left != right);
}

TEST_F(AttributesTest, InequalityOperatorPositive) {
  Attributes left, right;
  left.set_flags(kConstVal2);
  right.set_xfrm(kConstVal1);
  EXPECT_TRUE(left != right);
}

TEST_F(AttributesTest, BitwiseAndCorrectness1) {
  Attributes left, right, result;
  left.set_xfrm(kConstVal1);
  left.set_flags(kConstVal2);
  EXPECT_TRUE((left & right) == result);
}

TEST_F(AttributesTest, BitwiseAndCorrectness2) {
  Attributes left, right, result;
  left.set_xfrm(kConstVal1);
  left.set_flags(kConstVal2);
  right.set_xfrm(kConstVal1);
  right.set_flags(kConstVal2);
  result.set_xfrm(kConstVal1);
  result.set_flags(kConstVal2);
  EXPECT_TRUE((left & right) == result);
}

TEST_F(AttributesTest, BitwiseAndCorrectness3) {
  Attributes left, right, result;
  left.set_xfrm(kConstVal1);
  left.set_flags(kConstVal2);
  right.set_xfrm(kConstVal1);
  result.set_xfrm(kConstVal1);
  EXPECT_TRUE((left & right) == result);
}

TEST_F(AttributesTest, BitwiseAndCorrectness4) {
  Attributes left, right, result;
  left.set_flags(kConstVal2);
  right.set_xfrm(kConstVal1);
  EXPECT_TRUE((left & right) == result);
}

TEST_F(AttributesTest, BitwiseAndCorrectness5) {
  Attributes left, right, result;
  right.set_xfrm(kConstVal1);
  EXPECT_TRUE((left & right) == result);
}

TEST_F(AttributesTest, BitwiseAndCorrectness6) {
  Attributes left, right, result;
  left.set_flags(kZero);
  right.set_xfrm(kZero);
  result.set_xfrm(kZero);
  EXPECT_TRUE((left & right) == result);
}

}  // namespace
}  // namespace sgx
}  // namespace asylo
