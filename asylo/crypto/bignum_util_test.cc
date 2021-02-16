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

#include "asylo/crypto/bignum_util.h"

#include <openssl/base.h>
#include <openssl/bn.h>

#include <cstdint>
#include <limits>
#include <type_traits>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/types/span.h"
#include "asylo/test/util/integral_type_test_data.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status.h"

namespace asylo {
namespace {

using ::testing::ElementsAreArray;
using ::testing::Pair;
using ::testing::Test;

constexpr uint8_t kBytes[] = {84,  104, 101, 115, 101, 32,  118, 105, 111, 108,
                              101, 110, 116, 32,  100, 101, 108, 105, 103, 104,
                              116, 115, 32,  104, 97,  118, 101, 32,  118, 105,
                              111, 108, 101, 110, 116, 32,  101, 110, 100, 115};
constexpr uint8_t kBytesWithZerosPrepended[] = {
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   84,
    104, 101, 115, 101, 32,  118, 105, 111, 108, 101, 110, 116, 32,
    100, 101, 108, 105, 103, 104, 116, 115, 32,  104, 97,  118, 101,
    32,  118, 105, 111, 108, 101, 110, 116, 32,  101, 110, 100, 115};
constexpr uint8_t kBytesWithZerosAppended[] = {
    84,  104, 101, 115, 101, 32,  118, 105, 111, 108, 101, 110, 116, 32,  100,
    101, 108, 105, 103, 104, 116, 115, 32,  104, 97,  118, 101, 32,  118, 105,
    111, 108, 101, 110, 116, 32,  101, 110, 100, 115, 0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0};

TEST(BignumUtilTest, BigEndianRoundtrip) {
  bssl::UniquePtr<BIGNUM> bignum;
  ASYLO_ASSERT_OK_AND_ASSIGN(bignum,
                             BignumFromBigEndianBytes(absl::MakeSpan(kBytes)));
  EXPECT_THAT(BigEndianBytesFromBignum(*bignum),
              IsOkAndHolds(Pair(Sign::kPositive, ElementsAreArray(kBytes))));
}

TEST(BignumUtilTest, BigEndianNegativeRoundtrip) {
  bssl::UniquePtr<BIGNUM> bignum;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      bignum,
      BignumFromBigEndianBytes(absl::MakeSpan(kBytes), Sign::kNegative));
  EXPECT_THAT(BigEndianBytesFromBignum(*bignum),
              IsOkAndHolds(Pair(Sign::kNegative, ElementsAreArray(kBytes))));
}

TEST(BignumUtilTest, BigEndianLeadingZeroesAreStripped) {
  bssl::UniquePtr<BIGNUM> bignum;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      bignum,
      BignumFromBigEndianBytes(absl::MakeSpan(kBytesWithZerosPrepended)));
  EXPECT_THAT(BigEndianBytesFromBignum(*bignum),
              IsOkAndHolds(Pair(Sign::kPositive, ElementsAreArray(kBytes))));
}

TEST(BignumUtilTest, BigEndianZeroPadded) {
  bssl::UniquePtr<BIGNUM> bignum;
  ASYLO_ASSERT_OK_AND_ASSIGN(bignum,
                             BignumFromBigEndianBytes(absl::MakeSpan(kBytes)));
  EXPECT_THAT(
      PaddedBigEndianBytesFromBignum(*bignum, sizeof(kBytesWithZerosPrepended)),
      IsOkAndHolds(
          Pair(Sign::kPositive, ElementsAreArray(kBytesWithZerosPrepended))));
}

TEST(BignumUtilTest, BigEndianNegativeZeroPadded) {
  bssl::UniquePtr<BIGNUM> bignum;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      bignum,
      BignumFromBigEndianBytes(absl::MakeSpan(kBytes), Sign::kNegative));
  EXPECT_THAT(
      PaddedBigEndianBytesFromBignum(*bignum, sizeof(kBytesWithZerosPrepended)),
      IsOkAndHolds(
          Pair(Sign::kNegative, ElementsAreArray(kBytesWithZerosPrepended))));
}

TEST(BignumUtilTest, LittleEndianRoundtrip) {
  bssl::UniquePtr<BIGNUM> bignum;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      bignum, BignumFromLittleEndianBytes(absl::MakeSpan(kBytes)));
  EXPECT_THAT(LittleEndianBytesFromBignum(*bignum),
              IsOkAndHolds(Pair(Sign::kPositive, ElementsAreArray(kBytes))));
}

TEST(BignumUtilTest, LittleEndianNegativeRoundtrip) {
  bssl::UniquePtr<BIGNUM> bignum;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      bignum,
      BignumFromLittleEndianBytes(absl::MakeSpan(kBytes), Sign::kNegative));
  EXPECT_THAT(LittleEndianBytesFromBignum(*bignum),
              IsOkAndHolds(Pair(Sign::kNegative, ElementsAreArray(kBytes))));
}

TEST(BignumUtilTest, LittleEndianLeadingZeroesAreStripped) {
  bssl::UniquePtr<BIGNUM> bignum;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      bignum,
      BignumFromLittleEndianBytes(absl::MakeSpan(kBytesWithZerosAppended)));
  EXPECT_THAT(LittleEndianBytesFromBignum(*bignum),
              IsOkAndHolds(Pair(Sign::kPositive, ElementsAreArray(kBytes))));
}

TEST(BignumUtilTest, LittleEndianZeroPadded) {
  bssl::UniquePtr<BIGNUM> bignum;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      bignum, BignumFromLittleEndianBytes(absl::MakeSpan(kBytes)));
  EXPECT_THAT(PaddedLittleEndianBytesFromBignum(
                  *bignum, sizeof(kBytesWithZerosAppended)),
              IsOkAndHolds(Pair(Sign::kPositive,
                                ElementsAreArray(kBytesWithZerosAppended))));
}

TEST(BignumUtilTest, LittleEndianNegativeZeroPadded) {
  bssl::UniquePtr<BIGNUM> bignum;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      bignum,
      BignumFromLittleEndianBytes(absl::MakeSpan(kBytes), Sign::kNegative));
  EXPECT_THAT(PaddedLittleEndianBytesFromBignum(
                  *bignum, sizeof(kBytesWithZerosAppended)),
              IsOkAndHolds(Pair(Sign::kNegative,
                                ElementsAreArray(kBytesWithZerosAppended))));
}

// A test fixture for conversions between BIGNUM and IntT.
template <typename IntT>
class BignumUtilIntegerTest : public Test {};
TYPED_TEST_SUITE(BignumUtilIntegerTest, IntegralTypes);

TYPED_TEST(BignumUtilIntegerTest, IntegerRoundtrip) {
  for (TypeParam value : IntegralTypeTestData<TypeParam>::kValues) {
    bssl::UniquePtr<BIGNUM> bignum;
    ASYLO_ASSERT_OK_AND_ASSIGN(bignum, BignumFromInteger(value));
    EXPECT_THAT(IntegerFromBignum<TypeParam>(*bignum), IsOkAndHolds(value));
  }
}

TYPED_TEST(BignumUtilIntegerTest, IntegerFromBignumFailsIfBignumIsOutOfRange) {
  bssl::UniquePtr<BIGNUM> bignum;
  ASYLO_ASSERT_OK_AND_ASSIGN(bignum,
                             BignumFromBigEndianBytes(absl::MakeSpan(kBytes)));
  EXPECT_THAT(IntegerFromBignum<TypeParam>(*bignum),
              StatusIs(absl::StatusCode::kOutOfRange));

  ASYLO_ASSERT_OK_AND_ASSIGN(
      bignum,
      BignumFromBigEndianBytes(absl::MakeSpan(kBytes), Sign::kNegative));
  EXPECT_THAT(IntegerFromBignum<TypeParam>(*bignum),
              StatusIs(absl::StatusCode::kOutOfRange));
}

}  // namespace
}  // namespace asylo
