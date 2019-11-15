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

#include "asylo/test/util/memory_matchers.h"

#include <cstdint>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/base/attributes.h"
#include "asylo/crypto/util/bytes.h"
#include "asylo/crypto/util/trivial_object_util.h"

namespace asylo {
namespace {

using ::testing::Not;
using ::testing::Test;
using ::testing::Types;

struct SimpleStruct {
  int i;
  uint64_t i64;
} ABSL_ATTRIBUTE_PACKED;

template <typename T>
class TypedMemoryMatchersTest : public Test {};

using MyTypes = Types<UnsafeBytes<42>, SafeBytes<787>, SimpleStruct, uint64_t>;

TYPED_TEST_SUITE(TypedMemoryMatchersTest, MyTypes);

TYPED_TEST(TypedMemoryMatchersTest, TrivialObjectEq) {
  TypeParam obj = TrivialRandomObject<TypeParam>();
  TypeParam obj_copy = obj;

  EXPECT_THAT(obj, TrivialObjectEq(obj_copy));
}

TYPED_TEST(TypedMemoryMatchersTest, NotTrivialObjectEq) {
  TypeParam obj = TrivialRandomObject<TypeParam>();
  TypeParam not_obj = TrivialRandomObject<TypeParam>();

  EXPECT_THAT(obj, Not(TrivialObjectEq(not_obj)));
}

TYPED_TEST(TypedMemoryMatchersTest, MemEqWithLength) {
  TypeParam obj = TrivialRandomObject<TypeParam>();
  EXPECT_THAT(&obj, MemEq(&obj, sizeof(obj)));
  EXPECT_THAT(&obj, MemEq(&obj, sizeof(obj) / 2));
}

TYPED_TEST(TypedMemoryMatchersTest, NotMemEqWithLength) {
  TypeParam obj = TrivialRandomObject<TypeParam>();
  TypeParam not_obj = TrivialRandomObject<TypeParam>();
  EXPECT_THAT(&obj, Not(MemEq(&not_obj, sizeof(obj))));
  EXPECT_THAT(&obj, Not(MemEq(&not_obj, sizeof(obj) / 2)));
}

}  // namespace
}  // namespace asylo
