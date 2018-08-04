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
#include "asylo/crypto/util/byte_container_view.h"
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

// Types for the serialized output.
typedef ::testing::Types<std::string, std::vector<uint8_t>, std::string,
                         CleansingString, CleansingVector<uint8_t>>
    OutputTypes;

TYPED_TEST_CASE(ByteContainerUtilTest, OutputTypes);

// Verify that the serialization of no strings is an empty string.
TYPED_TEST(ByteContainerUtilTest, EmptySerialization) {
  std::vector<ByteContainerView> input = {};
  TypeParam output(kStr4, kStr4 + sizeof(kStr4) - 1);
  EXPECT_THAT(SerializeByteContainers(input, &output), IsOk());
  EXPECT_EQ(0, output.size());
}

// Verify that appending the serialization of no strings to a non-empty string
// does not alter the existing string.
TYPED_TEST(ByteContainerUtilTest, EmptySerializationAppend) {
  std::vector<ByteContainerView> input = {};
  TypeParam output(kStr4, kStr4 + sizeof(kStr4) - 1);
  EXPECT_THAT(AppendSerializedByteContainers(input, &output), IsOk());
  EXPECT_EQ(ByteContainerView(kStr4), (output));
}

// Verify that a serialization contains all input strings and that the input
// strings can be inferred from the serialization.
TYPED_TEST(ByteContainerUtilTest, SerializationContainsAllByteContainers) {
  std::vector<ByteContainerView> inputs = {kStr1, kStr2, kStr3};

  TypeParam output1;
  EXPECT_THAT(SerializeByteContainers(inputs, &output1), IsOk());

  int index = 0;
  for (const auto &input : inputs) {
    uint32_t size = EncodeLittleEndian(input.size());
    ASSERT_EQ(0, memcmp(output1.data() + index, &size, sizeof(size)));
    index += sizeof(size);
    EXPECT_EQ(0, memcmp(output1.data() + index, input.data(), size));
    index += size;
  }

  TypeParam output2;
  for (const auto &input : inputs) {
    std::vector<ByteContainerView> single_input = {input};
    EXPECT_THAT(AppendSerializedByteContainers(single_input, &output2), IsOk());
  }

  // serialized([a, b, c]) == (serialized(a) || serialized(b) || serialized(c))
  EXPECT_EQ(ByteContainerView(output1), ByteContainerView(output2));
}

// Verify that serializations are unambiguous, and unique per set of input
// strings.
TYPED_TEST(ByteContainerUtilTest, SerializationsAreUnique) {
  // [a, b, c]
  std::vector<ByteContainerView> inputs1 = {kStr1, kStr2, kStr3};

  // [a || b, c]
  std::vector<ByteContainerView> inputs2 = {kStr3, kStr4};

  TypeParam output1;
  TypeParam output2;

  EXPECT_THAT(SerializeByteContainers(inputs1, &output1), IsOk());
  EXPECT_THAT(SerializeByteContainers(inputs2, &output2), IsOk());

  // serialized(a, b, c) != serialized(a || b, c)
  EXPECT_NE(ByteContainerView(output1), ByteContainerView(output2));
}

}  // namespace
}  // namespace asylo
