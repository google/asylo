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

#include "asylo/crypto/util/trivial_object_util.h"

#include <cctype>
#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/container/flat_hash_set.h"
#include "asylo/crypto/util/bytes.h"
#include "asylo/test/util/status_matchers.h"

namespace asylo {
namespace {

using ::testing::Not;

// A trivial structure consisting of trivial members.
struct TrivialStructure {
  UnsafeBytes<24> foo;
  uint64_t bar;
  uint8_t baz[10];
};

// An equality operator is provided for EXPECT_EQ statements.
bool operator==(const TrivialStructure &first, const TrivialStructure &second) {
  return memcmp(&first, &second, sizeof(first)) == 0;
}

// A test fixture is used for naming consistency and future extensibility.
template <typename T>
class TypedTrivialObjectUtilTest : public ::testing::Test {};
typedef ::testing::Types<UnsafeBytes<16>, UnsafeBytes<32>, TrivialStructure,
                         uint64_t>
    MyTypes;
TYPED_TEST_SUITE(TypedTrivialObjectUtilTest, MyTypes);

// Rough coherence check on TrivialRandomObject. This test generates
// 32 different values and expects no collisions. Since the smallest
// trivial-object size is 64 bits, the probability of this test failing
// is O(2^-55), if the entropy source is doing what it is supposed to do!
TYPED_TEST(TypedTrivialObjectUtilTest, Random) {
  absl::flat_hash_set<std::string> set;
  for (int i = 0; i < 16; i++) {
    TypeParam obj = TrivialRandomObject<TypeParam>();
    std::string str = ConvertTrivialObjectToHexString(obj);
    EXPECT_TRUE(set.emplace(str).second);

    RandomFillTrivialObject(&obj);
    str = ConvertTrivialObjectToHexString(obj);
    EXPECT_TRUE(set.emplace(str).second);

    for (auto &c : str) {
      c = std::tolower(c);
    }
    TypeParam obj2;
    ASYLO_ASSERT_OK(SetTrivialObjectFromHexString<TypeParam>(str, &obj2));
    EXPECT_EQ(obj, obj2);

    for (auto &c : str) {
      c = std::toupper(c);
    }
    ASYLO_ASSERT_OK(SetTrivialObjectFromHexString<TypeParam>(str, &obj2));
    EXPECT_EQ(obj, obj2);
  }
}

// Test the correctness of TrivialZeroObject.
TYPED_TEST(TypedTrivialObjectUtilTest, Zero) {
  TypeParam obj = TrivialZeroObject<TypeParam>();
  const uint8_t *ptr = reinterpret_cast<const uint8_t *>(&obj);
  for (int i = 0; i < sizeof(obj); i++) {
    EXPECT_EQ(ptr[i], 0);
  }
  std::string str = ConvertTrivialObjectToHexString(obj);
  for (auto c : str) {
    EXPECT_EQ(c, '0');
  }
  TypeParam obj2;
  ASYLO_ASSERT_OK(SetTrivialObjectFromHexString<TypeParam>(str, &obj2));
  EXPECT_EQ(obj, obj2);
}

// Test the correctness of TrivialOnesObject.
TYPED_TEST(TypedTrivialObjectUtilTest, Ones) {
  TypeParam obj = TrivialOnesObject<TypeParam>();
  const uint8_t *ptr = reinterpret_cast<const uint8_t *>(&obj);
  for (int i = 0; i < sizeof(obj); i++) {
    EXPECT_EQ(ptr[i], 0xff);
  }

  std::string str = ConvertTrivialObjectToHexString(obj);
  for (auto &c : str) {
    c = std::tolower(c);
    EXPECT_EQ(c, 'f');
  }
  TypeParam obj2;
  ASYLO_ASSERT_OK(SetTrivialObjectFromHexString<TypeParam>(str, &obj2));
  EXPECT_EQ(obj, obj2);

  for (auto &c : str) {
    c = std::toupper(c);
    EXPECT_EQ(c, 'F');
  }
  ASYLO_ASSERT_OK(SetTrivialObjectFromHexString<TypeParam>(str, &obj2));
  EXPECT_EQ(obj, obj2);
}

// Test the correctness of conversion of to and from a binary string.
TYPED_TEST(TypedTrivialObjectUtilTest, BinaryStringConversions) {
  TypeParam obj1 = TrivialRandomObject<TypeParam>();

  std::string str = ConvertTrivialObjectToBinaryString(obj1);
  ASSERT_EQ(str.size(), sizeof(obj1));

  TypeParam obj2;
  ASYLO_ASSERT_OK(SetTrivialObjectFromBinaryString(str, &obj2));
  EXPECT_EQ(obj1, obj2);

  str.push_back('a');
  EXPECT_THAT(SetTrivialObjectFromBinaryString(str, &obj2), Not(IsOk()));
}

}  // namespace
}  // namespace asylo
