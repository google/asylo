/*
 *
 * Copyright 2018 Asylo authors
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

#include <cstring>
#include <memory>
#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/base/macros.h"
#include "asylo/platform/primitives/extent.h"

namespace asylo {
namespace primitives {
namespace {

using ::testing::Eq;

// Test that a default-constructed Extent is empty.
TEST(ExtentTest, ExtentDefaultExtentIsEmpty) { EXPECT_TRUE(Extent().empty()); }

// Test that an extent can be constructed from const and non-const pointers
TEST(ExtentTest, ExtentFromConst) {
  int x = 5;
  const int* const_addr_x = &x;
  int* addr_x = &x;

  Extent const_extent(const_addr_x);
  Extent extent(addr_x);

  EXPECT_THAT(const_extent.As<int>(), Eq(&x));
  EXPECT_THAT(extent.As<int>(), Eq(&x));
}

// Tests that an extent constructed from a pointer to an object contains
// the span of that object's location in memory.
TEST(ExtentTest, ExtentOfPointerRefersToObjectMemoryLocation) {
  constexpr uint64_t kStartValue = 1729;

  uint64_t test_object = kStartValue;
  Extent test_object_extent(&test_object);
  EXPECT_THAT(test_object_extent.As<uint64_t>(), Eq(&test_object));
  uint8_t* test_object_array = test_object_extent.As<uint8_t>();

  for (int i = 0; i < test_object_extent.size(); ++i) {
    // Flip every bit in each byte.
    test_object_array[i] ^= ~0;
  }
  EXPECT_THAT(test_object, Eq(~kStartValue));
}

// Tests that an extent constructed from a pointer and a count contains
// the corresponding array in memory.
TEST(ExtentTest, ExtentOfPointerAndCountRefersToArray) {
  double test_data[] = {1.6449,   1.0823,   1.0173,   1.00407,
                        1.000994, 1.000246, 1.0000612};

  // Test that initialization with an array type works.
  Extent array_extent(test_data, ABSL_ARRAYSIZE(test_data));
  for (int i = 0; i < ABSL_ARRAYSIZE(test_data); ++i) {
    EXPECT_THAT(&array_extent.As<double>()[i], Eq(&test_data[i]));
  }

  // Test that initialization with a pointer type works.
  double test_data_copy[ABSL_ARRAYSIZE(test_data)];
  memcpy(test_data_copy, test_data, ABSL_ARRAYSIZE(test_data));
  Extent pointer_extent(test_data_copy, ABSL_ARRAYSIZE(test_data));
  for (int i = 0; i < ABSL_ARRAYSIZE(test_data); ++i) {
    EXPECT_THAT(&pointer_extent.As<double>()[i], Eq(&test_data_copy[i]));
  }
}

}  // namespace
}  // namespace primitives
}  // namespace asylo
