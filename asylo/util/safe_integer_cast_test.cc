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

#include "asylo/util/safe_integer_cast.h"

#include <cstdint>
#include <limits>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/types/optional.h"

namespace asylo {
namespace {

using ::testing::Eq;
using ::testing::Optional;

TEST(SafeIntegerCastTest, UnsignedToLargerUnsigned) {
  EXPECT_THAT((SafeIntegerCast<uint16_t, uint8_t>(0)),
              Optional(static_cast<uint16_t>(0)));
  EXPECT_THAT(
      (SafeIntegerCast<uint16_t, uint8_t>(std::numeric_limits<uint8_t>::max())),
      Optional(static_cast<uint16_t>(std::numeric_limits<uint8_t>::max())));
}

TEST(SafeIntegerCastTest, UnsignedToSameUnsigned) {
  EXPECT_THAT((SafeIntegerCast<uint16_t, uint16_t>(0)),
              Optional(static_cast<uint16_t>(0)));
  EXPECT_THAT((SafeIntegerCast<uint16_t, uint16_t>(
                  std::numeric_limits<uint16_t>::max())),
              Optional(std::numeric_limits<uint16_t>::max()));
}

TEST(SafeIntegerCastTest, UnsignedToSmallerUnsigned) {
  EXPECT_THAT((SafeIntegerCast<uint16_t, uint32_t>(0)),
              Optional(static_cast<uint16_t>(0)));
  EXPECT_THAT((SafeIntegerCast<uint16_t, uint32_t>(
                  std::numeric_limits<uint16_t>::max())),
              Optional(std::numeric_limits<uint16_t>::max()));
  EXPECT_THAT((SafeIntegerCast<uint16_t, uint32_t>(
                  static_cast<uint32_t>(std::numeric_limits<uint16_t>::max()) +
                  static_cast<uint32_t>(1))),
              Eq(absl::nullopt));
  EXPECT_THAT(SafeIntegerCast<uint16_t>(std::numeric_limits<uint32_t>::max()),
              Eq(absl::nullopt));
}

TEST(SafeIntegerCastTest, UnsignedToLargerSigned) {
  EXPECT_THAT((SafeIntegerCast<int16_t, uint8_t>(0)),
              Optional(static_cast<int16_t>(0)));
  EXPECT_THAT(
      (SafeIntegerCast<int16_t, uint8_t>(std::numeric_limits<uint8_t>::max())),
      Optional(static_cast<int16_t>(std::numeric_limits<uint8_t>::max())));
}

TEST(SafeIntegerCastTest, UnsignedToSameSizedSigned) {
  EXPECT_THAT((SafeIntegerCast<int16_t, uint16_t>(0)),
              Optional(static_cast<int16_t>(0)));
  EXPECT_THAT(
      (SafeIntegerCast<int16_t, uint16_t>(std::numeric_limits<int16_t>::max())),
      Optional(std::numeric_limits<int16_t>::max()));
  EXPECT_THAT((SafeIntegerCast<int16_t, uint16_t>(
                  static_cast<uint16_t>(std::numeric_limits<int16_t>::max()) +
                  static_cast<uint16_t>(1))),
              Eq(absl::nullopt));
  EXPECT_THAT((SafeIntegerCast<int16_t, uint16_t>(
                  std::numeric_limits<uint16_t>::max())),
              Eq(absl::nullopt));
}

TEST(SafeIntegerCastTest, UnsignedToSmallerSigned) {
  EXPECT_THAT((SafeIntegerCast<int16_t, uint32_t>(0)),
              Optional(static_cast<int16_t>(0)));
  EXPECT_THAT(
      (SafeIntegerCast<int16_t, uint32_t>(std::numeric_limits<int16_t>::max())),
      Optional(std::numeric_limits<int16_t>::max()));
  EXPECT_THAT((SafeIntegerCast<int16_t, uint32_t>(
                  static_cast<uint32_t>(std::numeric_limits<int16_t>::max()) +
                  static_cast<uint32_t>(1))),
              Eq(absl::nullopt));
  EXPECT_THAT((SafeIntegerCast<int16_t, uint32_t>(
                  std::numeric_limits<uint32_t>::max())),
              Eq(absl::nullopt));
}

TEST(SafeIntegerCastTest, SignedToLargerUnsigned) {
  EXPECT_THAT(
      (SafeIntegerCast<uint16_t, int8_t>(std::numeric_limits<int8_t>::min())),
      Eq(absl::nullopt));
  EXPECT_THAT((SafeIntegerCast<uint16_t, int8_t>(-1)), Eq(absl::nullopt));
  EXPECT_THAT((SafeIntegerCast<uint16_t, int8_t>(0)),
              Optional(static_cast<uint16_t>(0)));
  EXPECT_THAT(
      (SafeIntegerCast<uint16_t, int8_t>(std::numeric_limits<int8_t>::max())),
      Optional(static_cast<uint16_t>(std::numeric_limits<int8_t>::max())));
}

TEST(SafeIntegerCastTest, SignedToSameSizedUnsigned) {
  EXPECT_THAT(
      (SafeIntegerCast<uint16_t, int16_t>(std::numeric_limits<int16_t>::min())),
      Eq(absl::nullopt));
  EXPECT_THAT((SafeIntegerCast<uint16_t, int16_t>(-1)), Eq(absl::nullopt));
  EXPECT_THAT((SafeIntegerCast<uint16_t, int16_t>(0)),
              Optional(static_cast<uint16_t>(0)));
  EXPECT_THAT(
      (SafeIntegerCast<uint16_t, int16_t>(std::numeric_limits<int16_t>::max())),
      Optional(static_cast<uint16_t>(std::numeric_limits<int16_t>::max())));
}

TEST(SafeIntegerCastTest, SignedToSmallerUnsigned) {
  EXPECT_THAT(
      (SafeIntegerCast<uint16_t, int32_t>(std::numeric_limits<int32_t>::min())),
      Eq(absl::nullopt));
  EXPECT_THAT((SafeIntegerCast<uint16_t, int32_t>(-1)), Eq(absl::nullopt));
  EXPECT_THAT((SafeIntegerCast<uint16_t, int32_t>(0)),
              Optional(static_cast<uint16_t>(0)));
  EXPECT_THAT((SafeIntegerCast<uint16_t, int32_t>(
                  std::numeric_limits<uint16_t>::max())),
              Optional(std::numeric_limits<uint16_t>::max()));
  EXPECT_THAT((SafeIntegerCast<uint16_t, int32_t>(
                  static_cast<int32_t>(std::numeric_limits<uint16_t>::max()) +
                  static_cast<int32_t>(1))),
              Eq(absl::nullopt));
  EXPECT_THAT(
      (SafeIntegerCast<uint16_t, int32_t>(std::numeric_limits<int32_t>::max())),
      Eq(absl::nullopt));
}

TEST(SafeIntegerCastTest, SignedToLargerSigned) {
  EXPECT_THAT(
      (SafeIntegerCast<int16_t, int8_t>(std::numeric_limits<int8_t>::min())),
      Optional(static_cast<int16_t>(std::numeric_limits<int8_t>::min())));
  EXPECT_THAT((SafeIntegerCast<int16_t, int8_t>(-1)),
              Optional(static_cast<int16_t>(-1)));
  EXPECT_THAT((SafeIntegerCast<int16_t, int8_t>(0)),
              Optional(static_cast<int16_t>(0)));
  EXPECT_THAT(
      (SafeIntegerCast<int16_t, int8_t>(std::numeric_limits<int8_t>::max())),
      Optional(static_cast<int16_t>(std::numeric_limits<int8_t>::max())));
}

TEST(SafeIntegerCastTest, SignedToSameSigned) {
  EXPECT_THAT(
      (SafeIntegerCast<int16_t, int16_t>(std::numeric_limits<int16_t>::min())),
      Optional(std::numeric_limits<int16_t>::min()));
  EXPECT_THAT((SafeIntegerCast<int16_t, int16_t>(-1)),
              Optional(static_cast<int16_t>(-1)));
  EXPECT_THAT((SafeIntegerCast<int16_t, int16_t>(0)),
              Optional(static_cast<int16_t>(0)));
  EXPECT_THAT(
      (SafeIntegerCast<int16_t, int16_t>(std::numeric_limits<int16_t>::max())),
      Optional(std::numeric_limits<int16_t>::max()));
}

TEST(SafeIntegerCastTest, SignedToSmallerSigned) {
  EXPECT_THAT(
      (SafeIntegerCast<int16_t, int32_t>(std::numeric_limits<int32_t>::min())),
      Eq(absl::nullopt));
  EXPECT_THAT((SafeIntegerCast<int16_t, int32_t>(
                  static_cast<int32_t>(std::numeric_limits<int16_t>::min()) -
                  static_cast<int32_t>(1))),
              Eq(absl::nullopt));
  EXPECT_THAT(
      (SafeIntegerCast<int16_t, int32_t>(std::numeric_limits<int16_t>::min())),
      Optional(std::numeric_limits<int16_t>::min()));
  EXPECT_THAT((SafeIntegerCast<int16_t, int32_t>(-1)),
              Optional(static_cast<int16_t>(-1)));
  EXPECT_THAT((SafeIntegerCast<int16_t, int32_t>(0)),
              Optional(static_cast<int16_t>(0)));
  EXPECT_THAT(
      (SafeIntegerCast<int16_t, int32_t>(std::numeric_limits<int16_t>::max())),
      Optional(std::numeric_limits<int16_t>::max()));
  EXPECT_THAT((SafeIntegerCast<int16_t, int32_t>(
                  static_cast<int32_t>(std::numeric_limits<int16_t>::max()) +
                  static_cast<int32_t>(1))),
              Eq(absl::nullopt));
  EXPECT_THAT(
      (SafeIntegerCast<int16_t, int32_t>(std::numeric_limits<int32_t>::max())),
      Eq(absl::nullopt));
}

}  // namespace
}  // namespace asylo
