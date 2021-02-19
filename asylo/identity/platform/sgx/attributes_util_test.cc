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

#include "asylo/identity/platform/sgx/attributes_util.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/status/status.h"
#include "asylo/identity/platform/sgx/architecture_bits.h"
#include "asylo/identity/platform/sgx/attributes.pb.h"
#include "asylo/test/util/status_matchers.h"

namespace asylo {
namespace sgx {
namespace {

using ::testing::Contains;
using ::testing::Eq;

constexpr uint64_t kConstVal1 = 0x12345678;
constexpr uint64_t kConstVal2 = 0x87654321;
constexpr uint64_t kZero = 0x0;
constexpr uint64_t kAllF = ~kZero;
constexpr AttributeBit kBadAttribute = static_cast<AttributeBit>(129);

class AttributesTest : public ::testing::Test {
 protected:
  // Names of bits in the order in which they are defined in kAllAttributeBits.
  const std::vector<std::string> attribute_names_ = {
      "INIT",   "DEBUG",  "MODE64BIT", "PROVISIONKEY", "INITTOKENKEY",
      "KSS",    "FPU",    "SSE",       "AVX",          "BNDREG",
      "BNDCSR", "OPMASK", "ZMM_HI256", "HI16_ZMM",     "PKRU"};
};

TEST_F(AttributesTest, EqualityOperatorPositive) {
  Attributes lhs;
  Attributes rhs;
  lhs.set_xfrm(kConstVal1);
  lhs.set_flags(kConstVal2);
  rhs.set_xfrm(kConstVal1);
  rhs.set_flags(kConstVal2);
  EXPECT_TRUE(lhs == rhs);
}

TEST_F(AttributesTest, EqualityOperatorNegative) {
  Attributes lhs;
  Attributes rhs;
  lhs.set_xfrm(kConstVal1);
  lhs.set_flags(kConstVal2);
  EXPECT_FALSE(lhs == rhs);
}

TEST_F(AttributesTest, InequalityOperatorNegative) {
  Attributes lhs;
  Attributes rhs;
  lhs.set_xfrm(kConstVal1);
  lhs.set_flags(kConstVal2);
  rhs.set_xfrm(kConstVal1);
  rhs.set_flags(kConstVal2);
  EXPECT_FALSE(lhs != rhs);
}

TEST_F(AttributesTest, InequalityOperatorPositive) {
  Attributes lhs;
  Attributes rhs;
  lhs.set_flags(kConstVal2);
  rhs.set_xfrm(kConstVal1);
  EXPECT_TRUE(lhs != rhs);
}

TEST_F(AttributesTest, BitwiseAndCorrectness1) {
  Attributes lhs;
  Attributes rhs;
  Attributes result;
  lhs.set_xfrm(kConstVal1);
  lhs.set_flags(kConstVal2);
  EXPECT_TRUE((lhs & rhs) == result);
}

TEST_F(AttributesTest, BitwiseAndCorrectness2) {
  Attributes lhs;
  Attributes rhs;
  Attributes result;
  lhs.set_xfrm(kConstVal1);
  lhs.set_flags(kConstVal2);
  rhs.set_xfrm(kConstVal1);
  rhs.set_flags(kConstVal2);
  result.set_xfrm(kConstVal1);
  result.set_flags(kConstVal2);
  EXPECT_TRUE((lhs & rhs) == result);
}

TEST_F(AttributesTest, BitwiseAndCorrectness3) {
  Attributes lhs;
  Attributes rhs;
  Attributes result;
  lhs.set_xfrm(kConstVal1);
  lhs.set_flags(kConstVal2);
  rhs.set_xfrm(kConstVal1);
  result.set_xfrm(kConstVal1);
  EXPECT_TRUE((lhs & rhs) == result);
}

TEST_F(AttributesTest, BitwiseAndCorrectness4) {
  Attributes lhs;
  Attributes rhs;
  Attributes result;
  lhs.set_flags(kConstVal2);
  rhs.set_xfrm(kConstVal1);
  EXPECT_TRUE((lhs & rhs) == result);
}

TEST_F(AttributesTest, BitwiseAndCorrectness5) {
  Attributes lhs;
  Attributes rhs;
  Attributes result;
  rhs.set_xfrm(kConstVal1);
  EXPECT_TRUE((lhs & rhs) == result);
}

TEST_F(AttributesTest, BitwiseAndCorrectness6) {
  Attributes lhs;
  Attributes rhs;
  Attributes result;
  lhs.set_flags(kZero);
  rhs.set_xfrm(kZero);
  result.set_xfrm(kZero);
  EXPECT_TRUE((lhs & rhs) == result);
}

TEST_F(AttributesTest, DefaultAttributesAllBitsUnset) {
  Attributes attributes;
  for (AttributeBit bit : kAllAttributeBits) {
    EXPECT_THAT(IsAttributeBitSet(bit, attributes), IsOkAndHolds(false));
  }
}

TEST_F(AttributesTest, AllSetAttributesAllBitsSet) {
  Attributes attributes;
  attributes.set_flags(kAllF);
  attributes.set_xfrm(kAllF);

  for (AttributeBit bit : kAllAttributeBits) {
    EXPECT_THAT(IsAttributeBitSet(bit, attributes), IsOkAndHolds(true));
  }
}

TEST_F(AttributesTest, SetAndClearValidAttributeBits) {
  Attributes attributes;
  for (AttributeBit bit : kAllAttributeBits) {
    EXPECT_THAT(SetAttributeBit(bit, &attributes), IsOk());
    EXPECT_THAT(IsAttributeBitSet(bit, attributes), IsOkAndHolds(true));
    EXPECT_THAT(ClearAttributeBit(bit, &attributes), IsOk());
    EXPECT_THAT(IsAttributeBitSet(bit, attributes), IsOkAndHolds(false));
  }
}

TEST_F(AttributesTest, SetInvalidAttributeBit) {
  Attributes attributes;
  EXPECT_THAT(SetAttributeBit(kBadAttribute, &attributes),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(AttributesTest, ClearInvalidAttributeBit) {
  Attributes attributes;
  EXPECT_THAT(ClearAttributeBit(kBadAttribute, &attributes),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(AttributesTest, TestInvalidAttributeBit) {
  Attributes attributes;
  EXPECT_THAT(IsAttributeBitSet(kBadAttribute, attributes),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(AttributesTest, GetPrintableAttributeListFromSet) {
  std::vector<absl::string_view> printable_list;
  Attributes attributes;

  int i = 0;
  for (AttributeBit bit : kAllAttributeBits) {
    SetAttributeBit(bit, &attributes);
    printable_list = GetPrintableAttributeList(attributes);
    EXPECT_EQ(printable_list.size(), i + 1);
    EXPECT_THAT(printable_list, Contains(Eq(attribute_names_[i])));
    ++i;
  }
}

}  // namespace
}  // namespace sgx
}  // namespace asylo
