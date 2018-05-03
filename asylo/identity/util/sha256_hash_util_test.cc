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

#include "asylo/identity/util/sha256_hash_util.h"

#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/identity/util/sha256_hash.pb.h"

namespace asylo {
namespace {

constexpr char kHashBin1[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                              0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                              0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                              0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
constexpr char kHashBin2[] = {0x0a, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                              0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                              0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                              0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
constexpr char kHashHex1[] =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
constexpr char kHashHexShort[] =
    "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

// A test fixture is used to ensure naming correctness and future
// expandability.
class Sha256HashUtilTest : public ::testing::Test {
 protected:
  Sha256HashUtilTest() {}
};

TEST_F(Sha256HashUtilTest, SuccessfulConversionFromHexString) {
  Sha256HashProto h;

  EXPECT_TRUE(Sha256HashFromHexString(kHashHex1, &h));
  EXPECT_EQ(h.hash(), std::string(kHashBin1, sizeof(kHashBin1)));
}

TEST_F(Sha256HashUtilTest, UnsuccessfulConversionFromHexString) {
  Sha256HashProto h;

  EXPECT_FALSE(Sha256HashFromHexString(kHashHexShort, &h));
}

TEST_F(Sha256HashUtilTest, ConversionToHexString) {
  Sha256HashProto h;
  h.set_hash(kHashBin1, sizeof(kHashBin1));
  std::string str;

  Sha256HashToHexString(h, &str);
  EXPECT_EQ(str, std::string(kHashHex1));
}

TEST_F(Sha256HashUtilTest, EqualityOperatorPositive) {
  Sha256HashProto h1, h2;
  h1.set_hash(kHashBin1, sizeof(kHashBin1));
  h2.set_hash(kHashBin1, sizeof(kHashBin1));

  EXPECT_TRUE(h1 == h2);
}

TEST_F(Sha256HashUtilTest, EqualityOperatorNegative) {
  Sha256HashProto h1, h2;
  h1.set_hash(kHashBin1, sizeof(kHashBin1));
  h2.set_hash(kHashBin2, sizeof(kHashBin2));

  EXPECT_FALSE(h1 == h2);
}

TEST_F(Sha256HashUtilTest, InequalityOperatorNegative) {
  Sha256HashProto h1, h2;
  h1.set_hash(kHashBin1, sizeof(kHashBin1));
  h2.set_hash(kHashBin1, sizeof(kHashBin1));

  EXPECT_FALSE(h1 != h2);
}

TEST_F(Sha256HashUtilTest, InequalityOperatorPositive) {
  Sha256HashProto h1, h2;
  h1.set_hash(kHashBin1, sizeof(kHashBin1));
  h2.set_hash(kHashBin2, sizeof(kHashBin2));

  EXPECT_TRUE(h1 != h2);
}

}  // namespace
}  // namespace asylo
