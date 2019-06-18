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

#include <byteswap.h>
#include <endian.h>

#include <cstdint>
#include <limits>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/types/span.h"

namespace asylo {
namespace {

using ::testing::Eq;
using ::testing::Test;
using ::testing::Types;

// This test provides aliases for the endianness-conversion functions that are
// overloaded for each of the types uint16_t, uint32_t, and uint64_t. This
// allows type-parameterized code to call the correct endianness-conversion
// function.

uint16_t Byteswap(uint16_t value) { return bswap_16(value); }
uint32_t Byteswap(uint32_t value) { return bswap_32(value); }
uint64_t Byteswap(uint64_t value) { return bswap_64(value); }

uint16_t HostToLe(uint16_t value) { return htole16(value); }
uint32_t HostToLe(uint32_t value) { return htole32(value); }
uint64_t HostToLe(uint64_t value) { return htole64(value); }

uint16_t HostToBe(uint16_t value) { return htobe16(value); }
uint32_t HostToBe(uint32_t value) { return htobe32(value); }
uint64_t HostToBe(uint64_t value) { return htobe64(value); }

uint16_t LeToHost(uint16_t value) { return le16toh(value); }
uint32_t LeToHost(uint32_t value) { return le32toh(value); }
uint64_t LeToHost(uint64_t value) { return le64toh(value); }

uint16_t BeToHost(uint16_t value) { return be16toh(value); }
uint32_t BeToHost(uint32_t value) { return be32toh(value); }
uint64_t BeToHost(uint64_t value) { return be64toh(value); }

// Test data for each type.
template <typename UIntT>
struct TestData;

template <>
struct TestData<uint16_t> {
  static constexpr uint16_t kTestValues[] = {0, 1, 0x0123};
};

template <>
struct TestData<uint32_t> {
  static constexpr uint32_t kTestValues[] = {0, 1, 0x0123, 0x01234567};
};

template <>
struct TestData<uint64_t> {
  static constexpr uint64_t kTestValues[] = {0, 1, 0x0123, 0x01234567,
                                             0x0123456789abcdef};
};

// The test data must be re-declared in namespace scope since it is odr-used.
constexpr uint16_t TestData<uint16_t>::kTestValues[];
constexpr uint32_t TestData<uint32_t>::kTestValues[];
constexpr uint64_t TestData<uint64_t>::kTestValues[];

// A type-parameterized test fixture for endian functions tests. Contains
// methods for each of the endianness functions for the type parameter. The
// methods are named based on whether the endianness of the host and other value
// are expected to be the same or swapped.
template <typename UIntT>
class EndianTest : public Test {
 protected:
  // The hto[bl]e##() function for the same endianness as the host.
  UIntT HostToSame(UIntT value) {
    return IsLittleEndian() ? HostToLe(value) : HostToBe(value);
  }

  // The hto[bl]e##() function for the alternate endianness to the host.
  UIntT HostToDiff(UIntT value) {
    return IsLittleEndian() ? HostToBe(value) : HostToLe(value);
  }

  // The [bl]e@@toh() function for the same endianness as the host.
  UIntT SameToHost(UIntT value) {
    return IsLittleEndian() ? LeToHost(value) : BeToHost(value);
  }

  // The [bl]e@@toh() function for the alternate endianness to the host.
  UIntT DiffToHost(UIntT value) {
    return IsLittleEndian() ? BeToHost(value) : LeToHost(value);
  }

 private:
  // Returns true if the host is little-endian and false if it is big-endian.
  bool IsLittleEndian() { return le16toh(1) == 1; }
};

using EndianTypes = Types<uint16_t, uint32_t, uint64_t>;
TYPED_TEST_SUITE(EndianTest, EndianTypes);

TYPED_TEST(EndianTest, HostToSamePreservesValues) {
  for (auto value : absl::MakeSpan(TestData<TypeParam>::kTestValues)) {
    EXPECT_THAT(this->HostToSame(value), Eq(value));
  }
}

TYPED_TEST(EndianTest, HostToDiffByteswapsValues) {
  for (auto value : absl::MakeSpan(TestData<TypeParam>::kTestValues)) {
    EXPECT_THAT(this->HostToDiff(value), Eq(Byteswap(value)));
  }
}

TYPED_TEST(EndianTest, SameToHostPreservesValues) {
  for (auto value : absl::MakeSpan(TestData<TypeParam>::kTestValues)) {
    EXPECT_THAT(this->SameToHost(value), Eq(value));
  }
}

TYPED_TEST(EndianTest, DiffToHostByteswapsValues) {
  for (auto value : absl::MakeSpan(TestData<TypeParam>::kTestValues)) {
    EXPECT_THAT(this->DiffToHost(value), Eq(Byteswap(value)));
  }
}

}  // namespace
}  // namespace asylo
