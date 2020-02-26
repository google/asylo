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

#include "asylo/crypto/util/bytes.h"

#include <algorithm>
#include <type_traits>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/crypto/util/trivial_object_util.h"

namespace asylo {
namespace {

constexpr size_t kSize = 11;  // Size of 11 is chosen as it is not an integer
                              // multiple of any of the "nice" sizes (4 or 8).
constexpr uint8_t kValue1[kSize] = {'a', 'b', 'c', 'd', 'e', 'f',
                                    'g', 'h', 'i', 'j', 'k'};
constexpr uint8_t kValue2[kSize] = {'a', 'b', 'c', 'd', 'e', 'f',
                                    'g', 'i', 'i', 'j', 'k'};
constexpr uint8_t kValue3[kSize] = {'a', 'a', 'a', 'a', 'a', 'a',
                                    'a', 'a', 'a', 'a', 'a'};

constexpr size_t kLargeSize = 13;
constexpr uint8_t kLargeValue[kLargeSize] = {'a', 'b', 'c', 'd', 'e', 'f', 'g',
                                             'h', 'i', 'j', 'k', 'l', 'm'};

// A typed test fixture is used for tests that require a single type object.
template <typename T>
class TypedBytesTest : public ::testing::Test {
 public:
};

typedef ::testing::Types<SafeBytes<kSize>, UnsafeBytes<kSize>> MyTypes;
TYPED_TEST_SUITE(TypedBytesTest, MyTypes);

TYPED_TEST(TypedBytesTest, EqualityOperatorPositive1) {
  TypeParam bytes1(kValue1);
  TypeParam bytes2(kValue1);

  EXPECT_TRUE(bytes1 == bytes2);
}

TYPED_TEST(TypedBytesTest, EqualityOperatorNegative2) {
  TypeParam bytes1(kValue1);
  TypeParam bytes2(kValue2);

  EXPECT_FALSE(bytes1 == bytes2);
}

TYPED_TEST(TypedBytesTest, InequalityOperatorNegative1) {
  TypeParam bytes1(kValue1, kSize);
  TypeParam bytes2(kValue1);

  EXPECT_FALSE(bytes1 != bytes2);
}

TYPED_TEST(TypedBytesTest, InequalityOperatorPositive2) {
  TypeParam bytes1(kValue1, kSize);
  TypeParam bytes2(kValue2);

  EXPECT_TRUE(bytes1 != bytes2);
}

TYPED_TEST(TypedBytesTest, EqualsPositive1) {
  TypeParam bytes1(kValue1, kSize);

  EXPECT_TRUE(bytes1.Equals(kValue1, kSize));
  EXPECT_TRUE(bytes1.Equals(kValue1));
}

TYPED_TEST(TypedBytesTest, EqualsNegative1) {
  TypeParam bytes1(kValue1, kSize);

  EXPECT_FALSE(bytes1.Equals(kValue1, kSize - 2));
  EXPECT_FALSE(bytes1.Equals(ByteContainerView(kValue1, kSize-2)));
}

TYPED_TEST(TypedBytesTest, EqualsNegative2) {
  TypeParam bytes1(kValue1, kSize);

  EXPECT_FALSE(bytes1.Equals(kValue2, kSize));
  EXPECT_FALSE(bytes1.Equals(kValue2));
}

TYPED_TEST(TypedBytesTest, Constructors) {
  TypeParam bytes1(kValue1, kSize);
  TypeParam bytes2(kValue1, kValue1 + kSize);
  TypeParam bytes3(kValue1);
  TypeParam bytes4{ByteContainerView(bytes1)};

  EXPECT_TRUE(bytes1 == bytes2);
  EXPECT_TRUE(bytes1 == bytes3);
  EXPECT_TRUE(bytes1 == bytes4);
}

TYPED_TEST(TypedBytesTest, Traits) {
  EXPECT_TRUE(std::is_trivially_copy_assignable<TypeParam>::value);

  TypeParam bytes(kValue1, kSize);
  EXPECT_EQ(kSize, sizeof(bytes));
  EXPECT_EQ(kSize, bytes.size());
  EXPECT_EQ(reinterpret_cast<uintptr_t>(&bytes),
            reinterpret_cast<uintptr_t>(bytes.data()));
}

TYPED_TEST(TypedBytesTest, Fill) {
  TypeParam bytes;

  bytes.fill('a');
  EXPECT_EQ(0, memcmp(bytes.data(), kValue3, bytes.size()));
}

TYPED_TEST(TypedBytesTest, Set) {
  TypeParam bytes;

  EXPECT_EQ(kSize, bytes.assign(kValue1, kSize));
  EXPECT_EQ(0, memcmp(bytes.data(), kValue1, bytes.size()));
}

TYPED_TEST(TypedBytesTest, SetSmallerInput) {
  TypeParam bytes;

  EXPECT_EQ(kSize - 4, bytes.assign(kValue1, kSize - 4));
  EXPECT_EQ(0, memcmp(bytes.data(), kValue1, kSize - 4));
}

// Make sure that setting an object from an input that is larger than the
// object's size does not overwrite memory beyond the object.
TYPED_TEST(TypedBytesTest, SetLargerInput) {
  // Fill a large vector (tmp1) with the letter 'a' and place a new
  // SafeBytes<kSize> object at its beginning.
  std::vector<uint8_t> tmp1;
  tmp1.resize(4096);
  memset(tmp1.data(), 'a', 4096);
  TypeParam *bytes = new (tmp1.data()) TypeParam;

  // Fill a second large vector (tmp2) with 'b' and set the placed
  // SafeCryptoByte<kSize> object using this vector.
  std::vector<uint8_t> tmp2;
  tmp2.resize(4096);
  memset(tmp2.data(), 'b', 4096);
  EXPECT_EQ(bytes->size(), bytes->assign(tmp2.data(), 4096));

  // Set tmp2 to expected contents of the first vector. The first eight bytes
  // should be set to 'b', while the remainder should be set to 'a'.
  memset(tmp2.data() + kSize, 'a', 4096 - kSize);

  // Compare the contents of the two vectors
  EXPECT_EQ(tmp2, tmp1);
}

// Make sure that the pointer-based variant of replace works correctly for a
// range contained within the object.
TYPED_TEST(TypedBytesTest, ReplacePtrWithinRange) {
  size_t replace_pos = kSize / 2;
  size_t requested_replace_count = kSize - replace_pos - 1;
  size_t expected_replace_count = kSize - replace_pos - 1;

  TypeParam bytes(kValue1, kSize);
  EXPECT_EQ(bytes.replace(replace_pos, kValue2, requested_replace_count),
            expected_replace_count);

  uint8_t buffer[kSize];
  memcpy(buffer, kValue1, kSize);
  memcpy(buffer + replace_pos, kValue2, expected_replace_count);
  TypeParam bytes2(buffer, kSize);

  EXPECT_EQ(bytes, bytes2);
}

// Make sure that the value-based variant of replace works correctly for a range
// contained within the object.
TYPED_TEST(TypedBytesTest, ReplaceValueWithinRange) {
  size_t replace_pos = kSize / 2;
  size_t requested_replace_count = kSize - replace_pos - 1;
  size_t expected_replace_count = kSize - replace_pos - 1;

  TypeParam bytes(kValue1, kSize);
  EXPECT_EQ(bytes.replace(replace_pos, 'a', requested_replace_count),
            expected_replace_count);

  uint8_t buffer[kSize];
  memcpy(buffer, kValue1, kSize);
  memset(buffer + replace_pos, 'a', expected_replace_count);
  TypeParam bytes2(buffer, kSize);

  EXPECT_EQ(bytes, bytes2);
}

// Make sure that the pointer-based variant of replace works correctly for a
// range protruding outside the object, and that it does not write outside the
// object.
TYPED_TEST(TypedBytesTest, ReplacePtrLargeRange) {
  size_t replace_pos = kSize / 2;
  size_t requested_replace_count = kSize;
  size_t expected_replace_count =
      std::min(kSize - replace_pos, requested_replace_count);

  uint8_t buffer1[256];
  memset(buffer1, 'x', sizeof(buffer1));
  TypeParam *bytes = new (buffer1) TypeParam(kValue1, kSize);
  EXPECT_EQ(bytes->replace(replace_pos, kValue2, requested_replace_count),
            expected_replace_count);

  uint8_t buffer2[256];
  memset(buffer2, 'x', sizeof(buffer1));
  memcpy(buffer2, kValue1, kSize);
  memcpy(buffer2 + replace_pos, kValue2, expected_replace_count);

  EXPECT_EQ(memcmp(buffer1, buffer2, sizeof(buffer1)), 0);
}

// Make sure that the value-based variant of replace works correctly for a range
// protruding outside the object, and that it does not write outside the object.
TYPED_TEST(TypedBytesTest, ReplaceValueLargeRange) {
  size_t replace_pos = kSize / 2;
  size_t requested_replace_count = kSize;
  size_t expected_replace_count =
      std::min(kSize - replace_pos, requested_replace_count);

  uint8_t buffer1[256];
  memset(buffer1, 'x', sizeof(buffer1));
  TypeParam *bytes = new (buffer1) TypeParam(kValue1, kSize);
  EXPECT_EQ(bytes->replace(replace_pos, 'a', requested_replace_count),
            expected_replace_count);

  uint8_t buffer2[256];
  memset(buffer2, 'x', sizeof(buffer1));
  memcpy(buffer2, kValue1, kSize);
  memset(buffer2 + replace_pos, 'a', expected_replace_count);

  EXPECT_EQ(memcmp(buffer1, buffer2, sizeof(buffer1)), 0);
}

// Make sure that if the pointer-based variant of replace is called with |pos| >
// |Size|, it leaves the object unchanged.
TYPED_TEST(TypedBytesTest, ReplacePtrWithLargePos) {
  size_t replace_pos = kSize + 1;
  size_t requested_replace_count = kSize;
  size_t expected_replace_count = 0;

  TypeParam bytes(kValue1, kSize);
  EXPECT_EQ(bytes.replace(replace_pos, kValue2, requested_replace_count),
            expected_replace_count);

  TypeParam bytes2(kValue1, kSize);
  EXPECT_EQ(bytes, bytes2);
}

// Make sure that if the value-based variant of replace is called with
// |pos| > |Size|, it leaves the object unchanged.
TYPED_TEST(TypedBytesTest, ReplaceValueWithLargePos) {
  size_t replace_pos = kSize + 1;
  size_t requested_replace_count = kSize;
  size_t expected_replace_count = 0;

  TypeParam bytes(kValue1, kSize);
  EXPECT_EQ(bytes.replace(replace_pos, 'a', requested_replace_count),
            expected_replace_count);

  TypeParam bytes2(kValue1, kSize);
  EXPECT_EQ(bytes, bytes2);
}

TYPED_TEST(TypedBytesTest, Cleanse) {
  TypeParam bytes(kValue1, kSize);
  EXPECT_TRUE(bytes.Equals(kValue1, kSize));
  bytes.Cleanse();
  uint8_t buffer[kSize];
  // The object uses OPENSSL_cleanse for its cleansing needs, which zeros out
  // the data. The test ensures that the zeroing was actually performed.
  memset(buffer, 0, kSize);
  EXPECT_TRUE(bytes.Equals(buffer, kSize));
}

TYPED_TEST(TypedBytesTest, Destructor) {
  uint8_t buffer1[kSize];
  // Due to the contract provided by the object it is safe to place a kSize
  // sized object in a kSize-sized memory block.
  TypeParam *bytes = new (buffer1) TypeParam(kValue1, kSize);

  EXPECT_TRUE(bytes->Equals(kValue1, kSize));
  bytes->~TypeParam();

  if (TypeParam::policy() == DataSafety::SAFE) {
    // A SAFE object's destructor uses OPENSSL_cleanse for its cleansing needs,
    // which zeros out the data. The test ensures that the zeroing was actually
    // performed.
    uint8_t buffer2[kSize];
    memset(buffer2, 0, kSize);
    EXPECT_EQ(0, memcmp(buffer1, buffer2, kSize));
  } else {
    EXPECT_EQ(0, memcmp(buffer1, kValue1, kSize));
  }
}

TYPED_TEST(TypedBytesTest, MutableIteratorBasic) {
  TypeParam bytes1(kValue1, kSize);
  TypeParam bytes2;

  std::copy(bytes1.begin(), bytes1.end(), bytes2.begin());
  EXPECT_EQ(bytes1, bytes2);
  EXPECT_TRUE(std::equal(bytes2.begin(), bytes2.end(), bytes1.begin()));

  std::vector<uint8_t> vec;
  for (uint8_t &ch : bytes1) {
    vec.push_back(ch);
  }
  EXPECT_TRUE(std::equal(bytes2.begin(), bytes2.end(), vec.begin()));
}

TYPED_TEST(TypedBytesTest, ImplicitImmutableIteratorBasic) {
  const TypeParam bytes1(kValue1, kSize);
  TypeParam bytes2;

  std::copy(bytes1.begin(), bytes1.end(), bytes2.begin());
  EXPECT_EQ(bytes1, bytes2);
  EXPECT_TRUE(std::equal(bytes2.begin(), bytes2.end(), bytes1.begin()));

  std::vector<uint8_t> vec;
  for (const uint8_t &ch : bytes1) {
    vec.push_back(ch);
  }
  EXPECT_TRUE(std::equal(bytes2.begin(), bytes2.end(), vec.begin()));
}

TYPED_TEST(TypedBytesTest, ExplicitImmutableIteratorBasic) {
  TypeParam bytes1(kValue1, kSize);
  TypeParam bytes2;

  std::copy(bytes1.cbegin(), bytes1.cend(), bytes2.begin());
  EXPECT_EQ(bytes1, bytes2);
  EXPECT_TRUE(std::equal(bytes2.cbegin(), bytes2.cend(), bytes1.cbegin()));

  std::vector<uint8_t> vec;
  for (const uint8_t &ch : bytes1) {
    vec.push_back(ch);
  }
  EXPECT_TRUE(std::equal(bytes2.begin(), bytes2.end(), vec.begin()));
}

TYPED_TEST(TypedBytesTest, MutableIteratorArithmeticAndComparison) {
  TypeParam bytes1(kValue1, kSize);

  typename TypeParam::iterator it1 = bytes1.begin();
  typename TypeParam::iterator it2 = it1 + 5;
  EXPECT_TRUE(it1 < it2);
  EXPECT_TRUE(it1 <= it2);
  EXPECT_TRUE(it1 != it2);
  EXPECT_FALSE(it1 > it2);
  EXPECT_FALSE(it1 >= it2);
  EXPECT_FALSE(it1 == it2);
  EXPECT_EQ(it2 - it1, 5);
  EXPECT_EQ(*it2, it1[5]);
  EXPECT_EQ(it1 - it2, -5);
  EXPECT_EQ(it2[-5], *it1);

  it1++;
  ++it1;
  it1 += 1;
  it1 = it1 + 1;
  it1 = 1 + it1;
  EXPECT_FALSE(it1 < it2);
  EXPECT_TRUE(it1 <= it2);
  EXPECT_FALSE(it1 != it2);
  EXPECT_FALSE(it1 > it2);
  EXPECT_TRUE(it1 >= it2);
  EXPECT_TRUE(it1 == it2);
  EXPECT_EQ(it2 - it1, 0);
  EXPECT_EQ(*it2, it1[0]);
  EXPECT_EQ(it1 - it2, 0);
  EXPECT_EQ(it2[0], *it1);

  it2--;
  --it2;
  it2 -= 1;
  it2 = it2 - 2;
  EXPECT_FALSE(it1 < it2);
  EXPECT_FALSE(it1 <= it2);
  EXPECT_TRUE(it1 != it2);
  EXPECT_TRUE(it1 > it2);
  EXPECT_TRUE(it1 >= it2);
  EXPECT_FALSE(it1 == it2);
  EXPECT_EQ(it2 - it1, -5);
  EXPECT_EQ(it2[5], *it1);
  EXPECT_EQ(it1 - it2, 5);
  EXPECT_EQ(*it2, it1[-5]);
}

TYPED_TEST(TypedBytesTest, ImplicitImmutableIteratorArithmeticAndComparison) {
  const TypeParam bytes1(kValue1, kSize);

  typename TypeParam::const_iterator it1 = bytes1.begin();
  typename TypeParam::const_iterator it2 = it1 + 5;
  EXPECT_TRUE(it1 < it2);
  EXPECT_TRUE(it1 <= it2);
  EXPECT_TRUE(it1 != it2);
  EXPECT_FALSE(it1 > it2);
  EXPECT_FALSE(it1 >= it2);
  EXPECT_FALSE(it1 == it2);
  EXPECT_EQ(it2 - it1, 5);
  EXPECT_EQ(*it2, it1[5]);
  EXPECT_EQ(it1 - it2, -5);
  EXPECT_EQ(it2[-5], *it1);

  it1++;
  ++it1;
  it1 += 1;
  it1 = it1 + 1;
  it1 = 1 + it1;
  EXPECT_FALSE(it1 < it2);
  EXPECT_TRUE(it1 <= it2);
  EXPECT_FALSE(it1 != it2);
  EXPECT_FALSE(it1 > it2);
  EXPECT_TRUE(it1 >= it2);
  EXPECT_TRUE(it1 == it2);
  EXPECT_EQ(it2 - it1, 0);
  EXPECT_EQ(*it2, it1[0]);
  EXPECT_EQ(it1 - it2, 0);
  EXPECT_EQ(it2[0], *it1);

  it2--;
  --it2;
  it2 -= 1;
  it2 = it2 - 2;
  EXPECT_FALSE(it1 < it2);
  EXPECT_FALSE(it1 <= it2);
  EXPECT_TRUE(it1 != it2);
  EXPECT_TRUE(it1 > it2);
  EXPECT_TRUE(it1 >= it2);
  EXPECT_FALSE(it1 == it2);
  EXPECT_EQ(it2 - it1, -5);
  EXPECT_EQ(it2[5], *it1);
  EXPECT_EQ(it1 - it2, 5);
  EXPECT_EQ(*it2, it1[-5]);
}

TYPED_TEST(TypedBytesTest, ExplicitImmutableIteratorArithmeticAndComparison) {
  TypeParam bytes1(kValue1, kSize);

  typename TypeParam::const_iterator it1 = bytes1.cbegin();
  typename TypeParam::const_iterator it2 = it1 + 5;
  EXPECT_TRUE(it1 < it2);
  EXPECT_TRUE(it1 <= it2);
  EXPECT_TRUE(it1 != it2);
  EXPECT_FALSE(it1 > it2);
  EXPECT_FALSE(it1 >= it2);
  EXPECT_FALSE(it1 == it2);
  EXPECT_EQ(it2 - it1, 5);
  EXPECT_EQ(*it2, it1[5]);
  EXPECT_EQ(it1 - it2, -5);
  EXPECT_EQ(it2[-5], *it1);

  it1++;
  ++it1;
  it1 += 1;
  it1 = it1 + 1;
  it1 = 1 + it1;
  EXPECT_FALSE(it1 < it2);
  EXPECT_TRUE(it1 <= it2);
  EXPECT_FALSE(it1 != it2);
  EXPECT_FALSE(it1 > it2);
  EXPECT_TRUE(it1 >= it2);
  EXPECT_TRUE(it1 == it2);
  EXPECT_EQ(it2 - it1, 0);
  EXPECT_EQ(*it2, it1[0]);
  EXPECT_EQ(it1 - it2, 0);
  EXPECT_EQ(it2[0], *it1);

  it2--;
  --it2;
  it2 -= 1;
  it2 = it2 - 2;
  EXPECT_FALSE(it1 < it2);
  EXPECT_FALSE(it1 <= it2);
  EXPECT_TRUE(it1 != it2);
  EXPECT_TRUE(it1 > it2);
  EXPECT_TRUE(it1 >= it2);
  EXPECT_FALSE(it1 == it2);
  EXPECT_EQ(it2 - it1, -5);
  EXPECT_EQ(it2[5], *it1);
  EXPECT_EQ(it1 - it2, 5);
  EXPECT_EQ(*it2, it1[-5]);
}

TYPED_TEST(TypedBytesTest, MutableReverseIteratorBasic) {
  TypeParam bytes1(kValue1, kSize);
  TypeParam bytes2;

  std::copy(bytes1.rbegin(), bytes1.rend(), bytes2.begin());
  EXPECT_TRUE(std::equal(bytes2.rbegin(), bytes2.rend(), bytes1.begin()));
}

TYPED_TEST(TypedBytesTest, ImplicitImmutableReverseIteratorBasic) {
  const TypeParam bytes1(kValue1, kSize);
  TypeParam bytes2;

  std::copy(bytes1.rbegin(), bytes1.rend(), bytes2.begin());
  EXPECT_TRUE(std::equal(bytes2.rbegin(), bytes2.rend(), bytes1.begin()));
}

TYPED_TEST(TypedBytesTest, ExplicitImmutableReverseIteratorBasic) {
  TypeParam bytes1(kValue1, kSize);
  TypeParam bytes2;

  std::copy(bytes1.crbegin(), bytes1.crend(), bytes2.begin());
  EXPECT_TRUE(std::equal(bytes2.crbegin(), bytes2.crend(), bytes1.cbegin()));
}

// Tests the copy functionality using the subscript operator.
TYPED_TEST(TypedBytesTest, CopyViaSubscriptOperator) {
  const TypeParam bytes1(kValue1, kSize);
  TypeParam bytes2;

  for (int i = 0; i < bytes1.size(); i++) {
    bytes2[i] = bytes1[i];
  }
  EXPECT_EQ(bytes1, bytes2);
}

// Tests the copy functionality using the at() method.
TYPED_TEST(TypedBytesTest, CopyViaAtMethod) {
  const TypeParam bytes1(kValue1, kSize);
  TypeParam bytes2;

  for (int i = 0; i < bytes1.size(); i++) {
    bytes2.at(i) = bytes1.at(i);
  }
  EXPECT_EQ(bytes1, bytes2);
}

// Tests proper "new placement" operation.
TYPED_TEST(TypedBytesTest, NewPlacement) {
  using CompatibleVector = std::vector<
      char, typename std::allocator_traits<typename TypeParam::allocator_type>::
                template rebind_alloc<char>>;
  using SafeVector = std::vector<char, CleansingAllocator<char>>;

  const TypeParam bytes1(kValue1, kSize);

  // Place objects in CompatibleVector.
  CompatibleVector vec1(kLargeValue, kLargeValue + sizeof(kLargeValue));
  TypeParam *bytes2;

  bytes2 = TypeParam::Place(&vec1, 0);
  ASSERT_NE(bytes2, nullptr);
  EXPECT_EQ(bytes1, *bytes2);

  bytes2 = TypeParam::Place(&vec1, vec1.size() - TypeParam::size());
  ASSERT_NE(bytes2, nullptr);

  bytes2 = TypeParam::Place(&vec1, vec1.size() - TypeParam::size() + 1);
  EXPECT_EQ(bytes2, nullptr);

  // Place objects in SafeVector. Either type of object should work with a
  // SafeVector.
  SafeVector vec2(kLargeValue, kLargeValue + sizeof(kLargeValue));
  TypeParam *bytes3;

  bytes3 = TypeParam::Place(&vec2, 0);
  ASSERT_NE(bytes3, nullptr);
  EXPECT_EQ(bytes1, *bytes3);

  bytes3 = TypeParam::Place(&vec2, vec2.size() - TypeParam::size());
  ASSERT_NE(bytes3, nullptr);

  bytes3 = TypeParam::Place(&vec2, vec2.size() - TypeParam::size() + 1);
  EXPECT_EQ(bytes3, nullptr);
}

TYPED_TEST(TypedBytesTest, PrintTo) {
  TypeParam bytes(kValue1, kSize);
  std::string str1 = ::testing::PrintToString(bytes);
  std::string str2 = ConvertTrivialObjectToHexString(bytes);
  EXPECT_EQ(str1, str2);
}

///////////////////////////
// Untyped tests         //
///////////////////////////

TEST(BytesTest, UnsafeBytesIsTrivial) {
  EXPECT_TRUE(std::is_trivially_default_constructible<UnsafeBytes<1>>::value);
  EXPECT_TRUE(std::is_trivially_destructible<UnsafeBytes<1>>::value);
  EXPECT_TRUE(std::is_trivially_copy_constructible<UnsafeBytes<1>>::value);
  EXPECT_TRUE(std::is_trivially_copyable<UnsafeBytes<1>>::value);
  EXPECT_TRUE(std::is_trivial<UnsafeBytes<1>>::value);
}

// Make sure that objects that have different sizes are not considered equal by
// the equality operator, even when the first N bytes in the two objects match
// (where N is the size of the smaller object).
TEST(BytesTest, SafeEqualityOperatorNegative1) {
  SafeBytes<kSize> bytes1(kValue1, kSize);
  SafeBytes<kSize + 4> bytes2(kValue1, kSize);

  EXPECT_FALSE(bytes1 == bytes2);
}

// Make sure that objects that have different sizes are not considered equal by
// the inequality operator, even when the first N bytes in the two objects match
// (where N is the size of the smaller object).
TEST(BytesTest, SafeInequalityOperatorPositive1) {
  SafeBytes<kSize> bytes1(kValue1, kSize);
  SafeBytes<kSize + 4> bytes2(kValue1, kSize);

  EXPECT_TRUE(bytes1 != bytes2);
}

// Make sure that objects that have different sizes are not considered equal by
// the equality operator, even when the first N bytes in the two objects match
// (where N is the size of the smaller object).
TEST(BytesTest, UnsafeEqualityOperatorNegative1) {
  UnsafeBytes<kSize> bytes1(kValue1, kSize);
  UnsafeBytes<kSize + 4> bytes2(kValue1, kSize);

  EXPECT_FALSE(bytes1 == bytes2);
}

// Make sure that objects that have different sizes are not considered equal by
// the inequality operator, even when the first N bytes in the two objects match
// (where N is the size of the smaller object).
TEST(BytesTest, UnsafeInequalityOperatorPositive1) {
  UnsafeBytes<kSize> bytes1(kValue1, kSize);
  UnsafeBytes<kSize + 4> bytes2(kValue1, kSize);

  EXPECT_TRUE(bytes1 != bytes2);
}

TEST(BytesTest, SafeParams) {
  EXPECT_EQ(SafeBytes<kSize>::size(), kSize);
  EXPECT_EQ(SafeBytes<kSize>::policy(), DataSafety::SAFE);
}

TEST(BytesTest, UnsafeParams) {
  EXPECT_EQ(UnsafeBytes<kSize>::size(), kSize);
  EXPECT_EQ(UnsafeBytes<kSize>::policy(), DataSafety::UNSAFE);
}

}  // namespace
}  // namespace asylo
