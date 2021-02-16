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

#include "asylo/crypto/util/byte_container_reader.h"

#include <cstring>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/base/macros.h"
#include "absl/status/status.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/crypto/util/trivial_object_util.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/cleansing_types.h"

namespace asylo {
namespace {

using ::testing::ElementsAreArray;
using ::testing::Eq;
using ::testing::Test;
using ::testing::Types;

// Test structure to serve as a trivial object type for object reads.
struct TrivialStruct {
  uint16_t u;
  char c;
  int64_t i;

  bool operator==(const TrivialStruct &rhs) const {
    return u == rhs.u && c == rhs.c && i == rhs.i;
  }
};

template <typename T>
class ByteContainerReadSingleTests : public Test {};
using TrivialTypes = Types<uint8_t, int, int64_t, TrivialStruct>;
TYPED_TEST_SUITE(ByteContainerReadSingleTests, TrivialTypes);

TYPED_TEST(ByteContainerReadSingleTests, ReadOne) {
  const TypeParam kInput = TrivialRandomObject<TypeParam>();
  ByteContainerReader reader(ByteContainerView(&kInput, sizeof(kInput)));
  EXPECT_THAT(reader.BytesRemaining(), Eq(sizeof(kInput)));

  TypeParam output;
  ASSERT_THAT(reader.ReadSingle(&output), IsOk());
  EXPECT_THAT(output, Eq(kInput));
  EXPECT_THAT(reader.BytesRemaining(), Eq(0));
}

TYPED_TEST(ByteContainerReadSingleTests, ReadMultiple) {
  const TypeParam kInputs[] = {
      TrivialRandomObject<TypeParam>(), TrivialRandomObject<TypeParam>(),
      TrivialRandomObject<TypeParam>(), TrivialRandomObject<TypeParam>(),
      TrivialRandomObject<TypeParam>()};
  ByteContainerReader reader(kInputs, sizeof(kInputs));

  for (size_t i = 0; i < ABSL_ARRAYSIZE(kInputs); ++i) {
    EXPECT_THAT(reader.BytesRemaining(),
                Eq((ABSL_ARRAYSIZE(kInputs) - i) * sizeof(TypeParam)));

    TypeParam output;
    ASSERT_THAT(reader.ReadSingle(&output), IsOk());
    EXPECT_THAT(output, Eq(kInputs[i]));
  }

  EXPECT_THAT(reader.BytesRemaining(), Eq(0));
}

TYPED_TEST(ByteContainerReadSingleTests, ReadTooManyObjects) {
  const TypeParam kInputs[] = {TrivialRandomObject<TypeParam>(),
                               TrivialRandomObject<TypeParam>()};
  ByteContainerReader reader(kInputs, sizeof(kInputs) - 1);

  TypeParam output;
  ASSERT_THAT(reader.ReadSingle(&output), IsOk());
  EXPECT_THAT(output, Eq(kInputs[0]));

  EXPECT_THAT(reader.BytesRemaining(), Eq(sizeof(TypeParam) - 1));

  TypeParam *obj = nullptr;
  ASSERT_THAT(reader.ReadSingle(obj),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(reader.BytesRemaining(), Eq(sizeof(TypeParam) - 1));
}

TYPED_TEST(ByteContainerReadSingleTests, ReadRaw) {
  const TypeParam kInput = TrivialRandomObject<TypeParam>();
  ByteContainerReader reader(ByteContainerView(&kInput, sizeof(kInput)));

  TypeParam output;
  ASSERT_THAT(reader.ReadRaw(sizeof(output), &output), IsOk());
  EXPECT_THAT(output, Eq(kInput));
  EXPECT_THAT(reader.BytesRemaining(), Eq(0));
}

TYPED_TEST(ByteContainerReadSingleTests, ReadRawTooManyBytes) {
  const TypeParam kInput = TrivialRandomObject<TypeParam>();
  const size_t kSize = sizeof(kInput) - 1;
  ByteContainerReader reader(ByteContainerView(&kInput, kSize));

  TypeParam *output = nullptr;
  ASSERT_THAT(reader.ReadRaw(sizeof(TypeParam), output),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(reader.BytesRemaining(), Eq(kSize));
}

template <typename T>
class ByteContainerReadMultipleTests : public Test {};
using ContainerTypes =
    Types<std::string, CleansingString, std::vector<uint8_t>,
          std::vector<TrivialStruct>, CleansingVector<TrivialStruct>>;
TYPED_TEST_SUITE(ByteContainerReadMultipleTests, ContainerTypes);

TYPED_TEST(ByteContainerReadMultipleTests, ReadZeroObjects) {
  using ValueType = typename TypeParam::value_type;
  const ValueType kInput[] = {};
  ByteContainerReader reader(ByteContainerView(&kInput, sizeof(kInput)));
  EXPECT_THAT(reader.BytesRemaining(), Eq(0));

  TypeParam output;
  EXPECT_THAT(reader.ReadMultiple(0, &output), IsOk());
  EXPECT_THAT(reader.BytesRemaining(), Eq(0));
  EXPECT_THAT(output.size(), Eq(0));
}

TYPED_TEST(ByteContainerReadMultipleTests, ReadOneObject) {
  using ValueType = typename TypeParam::value_type;
  const ValueType kInput = TrivialRandomObject<ValueType>();
  ByteContainerReader reader(ByteContainerView(&kInput, sizeof(kInput)));
  EXPECT_THAT(reader.BytesRemaining(), Eq(sizeof(kInput)));

  TypeParam output;
  EXPECT_THAT(reader.ReadMultiple(1, &output), IsOk());
  EXPECT_THAT(reader.BytesRemaining(), Eq(0));
  EXPECT_THAT(output.front(), Eq(kInput));
}

TYPED_TEST(ByteContainerReadMultipleTests, ReadMultipleObjects) {
  using ValueType = typename TypeParam::value_type;
  const ValueType kInput[] = {TrivialRandomObject<ValueType>(),
                              TrivialRandomObject<ValueType>(),
                              TrivialRandomObject<ValueType>()};
  ByteContainerReader reader(ByteContainerView(&kInput, sizeof(kInput)));
  EXPECT_THAT(reader.BytesRemaining(), Eq(sizeof(kInput)));

  TypeParam output;
  EXPECT_THAT(reader.ReadMultiple(ABSL_ARRAYSIZE(kInput) - 1, &output), IsOk());
  EXPECT_THAT(reader.BytesRemaining(), Eq(sizeof(ValueType)));

  EXPECT_THAT(reader.ReadMultiple(1, &output), IsOk());
  EXPECT_THAT(reader.BytesRemaining(), Eq(0));

  EXPECT_THAT(output, ElementsAreArray(kInput));
}

TYPED_TEST(ByteContainerReadMultipleTests, ReadPastEnd) {
  using ValueType = typename TypeParam::value_type;
  const ValueType kInput = TrivialRandomObject<ValueType>();
  ByteContainerReader reader(ByteContainerView(&kInput, sizeof(kInput)));
  EXPECT_THAT(reader.BytesRemaining(), Eq(sizeof(kInput)));

  TypeParam output;
  EXPECT_THAT(reader.ReadMultiple(2, &output),
              StatusIs(absl::StatusCode::kInvalidArgument));

  // Ensure that, after error, we can still read successfully
  EXPECT_THAT(reader.ReadMultiple(1, &output), IsOk());
  EXPECT_THAT(output.front(), Eq(kInput));
}

}  // namespace
}  // namespace asylo
