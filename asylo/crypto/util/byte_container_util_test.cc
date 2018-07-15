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

#include "asylo/crypto/util/byte_container_util.h"

#include <cstdint>
#include <string>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/cleansing_types.h"

namespace asylo {
namespace {

constexpr char kStr1[] = "foo";
constexpr char kStr2[] = "bar";
constexpr char kStr3[] = "baz";
constexpr char kStr4[] = "foobar";

// A test fixture is required for defining typed tests.
template <typename T>
class ByteContainerUtilTest : public ::testing::Test {};

// Returns |value| as a 32-bit little-endian encoded integer. |value| must not
// exceed the max value of a uint32_t.
uint32_t EncodeLittleEndian(size_t value) {
#ifdef __x86_64__
  return value;
#else
#error "Only supported on x86_64 architecture"
#endif
}

typedef ::testing::Types<
    std::pair<std::string, std::string>, std::pair<std::vector<uint8_t>, std::string>,
    std::pair<std::basic_string<char>, std::basic_string<char>>,
    std::pair<std::string, CleansingString>, std::pair<CleansingString, std::string>,
    std::pair<std::vector<uint8_t>, CleansingString>,
    std::pair<CleansingVector<uint8_t>, std::string>,
    std::pair<CleansingVector<uint8_t>, CleansingString>,
    std::pair<CleansingString, CleansingString>>
    TestTypes;

TYPED_TEST_CASE(ByteContainerUtilTest, TestTypes);

// Verify that the serialization of no strings is an empty string.
TYPED_TEST(ByteContainerUtilTest, EmptySerialization) {
  std::vector<typename TypeParam::first_type> input = {};
  typename TypeParam::second_type output(kStr4);
  EXPECT_THAT(SerializeByteContainers(input, &output), IsOk());
  EXPECT_EQ(0, output.size());
}

// Verify that appending the serialization of no strings to a non-empty string
// does not alter the existing string.
TYPED_TEST(ByteContainerUtilTest, EmptySerializationAppend) {
  std::vector<typename TypeParam::first_type> input = {};
  typename TypeParam::second_type output(kStr4);
  EXPECT_THAT(AppendSerializedByteContainers(input, &output), IsOk());
  EXPECT_EQ(kStr4, output);
}

// Verify that a serialization contains all input strings and that the input
// strings can be inferred from the serialization.
TYPED_TEST(ByteContainerUtilTest, SerializationContainsAllByteContainers) {
  using ByteContainerT = typename TypeParam::first_type;
  using StringT = typename TypeParam::second_type;

  std::vector<ByteContainerT> inputs = {
      ByteContainerT(kStr1, kStr1 + sizeof(kStr1) - 1),
      ByteContainerT(kStr2, kStr2 + sizeof(kStr2) - 1),
      ByteContainerT(kStr3, kStr3 + sizeof(kStr3) - 1)};

  StringT output1;
  EXPECT_THAT(SerializeByteContainers(inputs, &output1), IsOk());

  int index = 0;
  for (const ByteContainerT &str : inputs) {
    uint32_t size = EncodeLittleEndian(str.size());
    ASSERT_EQ(0, memcmp(output1.data() + index, &size, sizeof(size)));
    index += sizeof(size);
    EXPECT_EQ(0, memcmp(output1.data() + index, str.data(), size));
    index += size;
  }

  StringT output2;
  for (const ByteContainerT &str : inputs) {
    std::vector<ByteContainerT> input = {str};
    EXPECT_THAT(AppendSerializedByteContainers(input, &output2), IsOk());
  }

  // serialized([a, b, c]) == (serialized(a) || serialized(b) || serialized(c))
  EXPECT_EQ(output1, output2);
}

// Verify that serializations are non-ambiguous, and unique per set of input
// strings.
TYPED_TEST(ByteContainerUtilTest, SerializationsAreUnique) {
  using ByteContainerT = typename TypeParam::first_type;
  using StringT = typename TypeParam::second_type;

  std::vector<ByteContainerT> inputs1 = {
      // [a, b, c]
      ByteContainerT(kStr1, kStr1 + sizeof(kStr1) - 1),
      ByteContainerT(kStr2, kStr2 + sizeof(kStr2) - 1),
      ByteContainerT(kStr3, kStr3 + sizeof(kStr3) - 1)};

  std::vector<ByteContainerT> inputs2 = {
      // [a || b, c]
      ByteContainerT(kStr4, kStr4 + sizeof(kStr4) - 1),
      ByteContainerT(kStr3, kStr3 + sizeof(kStr3) - 1)};

  StringT output1;
  StringT output2;

  EXPECT_THAT(SerializeByteContainers(inputs1, &output1), IsOk());
  EXPECT_THAT(SerializeByteContainers(inputs2, &output2), IsOk());

  // serialized(a, b, c) != serialized(a || b, c)
  EXPECT_NE(output1, output2);
}

}  // namespace
}  // namespace asylo
