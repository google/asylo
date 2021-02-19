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

#include "asylo/identity/platform/sgx/miscselect_util.h"

#include <cstdint>

#include <gtest/gtest.h>
#include "absl/status/status.h"
#include "asylo/identity/platform/sgx/architecture_bits.h"
#include "asylo/identity/platform/sgx/miscselect.pb.h"
#include "asylo/test/util/status_matchers.h"

namespace asylo {
namespace sgx {
namespace {

constexpr uint32_t kConstVal1 = 0x12345678;
constexpr uint32_t kConstVal2 = 0x87654321;
constexpr uint32_t kZero = 0x0;
constexpr uint32_t kAllF = ~kZero;
constexpr MiscselectBit bad_miscselect_ = static_cast<MiscselectBit>(33);

TEST(MiscselectUtilTest, EqualityOperatorPositive) {
  Miscselect lhs;
  Miscselect rhs;
  lhs.set_value(kConstVal1);
  rhs.set_value(kConstVal1);
  EXPECT_TRUE(lhs == rhs);
}

TEST(MiscselectUtilTest, EqualityOperatorNegative) {
  Miscselect lhs;
  Miscselect rhs;
  lhs.set_value(kConstVal1);
  rhs.set_value(kConstVal2);
  EXPECT_FALSE(lhs == rhs);
}

TEST(MiscselectUtilTest, InequalityOperatorNegative) {
  Miscselect lhs;
  Miscselect rhs;
  lhs.set_value(kConstVal1);
  rhs.set_value(kConstVal1);
  EXPECT_FALSE(lhs != rhs);
}

TEST(MiscselectUtilTest, InequalityOperatorPositive) {
  Miscselect lhs;
  Miscselect rhs;
  lhs.set_value(kConstVal1);
  rhs.set_value(kConstVal2);
  EXPECT_TRUE(lhs != rhs);
}

TEST(MiscselectUtilTest, DefaultAllBitsUnset) {
  Miscselect miscselect;

  for (MiscselectBit bit : kAllMiscselectBits) {
    EXPECT_THAT(IsMiscselectBitSet(bit, miscselect), IsOkAndHolds(false));
    EXPECT_THAT(IsMiscselectBitSet(bit, miscselect.value()),
                IsOkAndHolds(false));
  }
}

TEST(MiscselectUtilTest, AllSetMiscselectAllBitsSet) {
  Miscselect miscselect;
  miscselect.set_value(kAllF);

  for (MiscselectBit bit : kAllMiscselectBits) {
    EXPECT_THAT(IsMiscselectBitSet(bit, miscselect), IsOkAndHolds(true));
    EXPECT_THAT(IsMiscselectBitSet(bit, miscselect.value()),
                IsOkAndHolds(true));
  }
}

TEST(MiscselectUtilTest, SetAndClearValidMiscselectBits) {
  uint32_t miscselect = 0;
  for (MiscselectBit bit : kAllMiscselectBits) {
    EXPECT_THAT(SetMiscselectBit(bit, &miscselect), IsOk());
    EXPECT_THAT(IsMiscselectBitSet(bit, miscselect), IsOkAndHolds(true));
    EXPECT_THAT(ClearMiscselectBit(bit, &miscselect), IsOk());
    EXPECT_THAT(IsMiscselectBitSet(bit, miscselect), IsOkAndHolds(false));
  }
}

TEST(MiscselectUtilTest, SetAndClearValidMiscselectProtoBits) {
  Miscselect miscselect;
  for (MiscselectBit bit : kAllMiscselectBits) {
    EXPECT_THAT(SetMiscselectBit(bit, &miscselect), IsOk());
    EXPECT_THAT(IsMiscselectBitSet(bit, miscselect), IsOkAndHolds(true));
    EXPECT_THAT(ClearMiscselectBit(bit, &miscselect), IsOk());
    EXPECT_THAT(IsMiscselectBitSet(bit, miscselect), IsOkAndHolds(false));
  }
}

TEST(MiscselectUtilTest, SetInvalidMiscselectBit) {
  uint32_t miscselect = 0;
  EXPECT_THAT(SetMiscselectBit(bad_miscselect_, &miscselect),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(MiscselectUtilTest, SetInvalidMiscselectProtoBit) {
  Miscselect miscselect;
  EXPECT_THAT(SetMiscselectBit(bad_miscselect_, &miscselect),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(MiscselectUtilTest, ClearInvalidMiscselectBit) {
  uint32_t miscselect = 0;
  EXPECT_THAT(ClearMiscselectBit(bad_miscselect_, &miscselect),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(MiscselectUtilTest, ClearInvalidMiscselectProtoBit) {
  Miscselect miscselect;
  EXPECT_THAT(ClearMiscselectBit(bad_miscselect_, &miscselect),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(MiscselectUtilTest, TestInvalidMiscselectBit) {
  uint32_t miscselect = 0;
  EXPECT_THAT(IsMiscselectBitSet(bad_miscselect_, miscselect),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(MiscselectUtilTest, TestInvalidMiscselectProtoBit) {
  Miscselect miscselect;
  EXPECT_THAT(IsMiscselectBitSet(bad_miscselect_, miscselect),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace
}  // namespace sgx
}  // namespace asylo
