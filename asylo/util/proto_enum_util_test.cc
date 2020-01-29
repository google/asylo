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

#include "asylo/util/proto_enum_util.h"

#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/util/proto_enum_util_test.pb.h"

namespace asylo {
namespace {

using ::testing::ElementsAreArray;
using ::testing::Eq;
using ::testing::Ne;
using ::testing::StrEq;

constexpr TestProtoEnum kAllValues[] = {
    TEST_PROTO_ENUM_UNKNOWN,
    TEST_PROTO_ENUM_VALUE_A,
    TEST_PROTO_ENUM_VALUE_B,
    TEST_PROTO_ENUM_VALUE_C,
};

TEST(ProtoEnumUtilTest, EnumeratorValuesMapToValueName) {
  EXPECT_THAT(ProtoEnumValueName(TestProtoEnum::TEST_PROTO_ENUM_VALUE_A),
              StrEq("TEST_PROTO_ENUM_VALUE_A"));
  EXPECT_THAT(ProtoEnumValueName(TestProtoEnum::TEST_PROTO_ENUM_VALUE_B),
              StrEq("TEST_PROTO_ENUM_VALUE_B"));
  EXPECT_THAT(ProtoEnumValueName(TestProtoEnum::TEST_PROTO_ENUM_VALUE_C),
              StrEq("TEST_PROTO_ENUM_VALUE_C"));
}

TEST(ProtoEnumUtilTest, NonEnumeratorValuesMapToDecimalRepresentation) {
  EXPECT_THAT(ProtoEnumValueName(static_cast<TestProtoEnum>(-1000)),
              StrEq("-1000"));
  EXPECT_THAT(ProtoEnumValueName(static_cast<TestProtoEnum>(-4)), StrEq("-4"));
  EXPECT_THAT(ProtoEnumValueName(static_cast<TestProtoEnum>(12)), StrEq("12"));
  EXPECT_THAT(ProtoEnumValueName(static_cast<TestProtoEnum>(10000)),
              StrEq("10000"));
}

TEST(ProtoEnumUtilTest, EnumeratorRangeFormatting) {
  constexpr TestProtoEnum kInputs[] = {
      TEST_PROTO_ENUM_VALUE_A,
      static_cast<TestProtoEnum>(42),
      TEST_PROTO_ENUM_VALUE_C,
  };

  EXPECT_THAT(AllProtoEnumValueNames(kInputs),
              StrEq("[TEST_PROTO_ENUM_VALUE_A, 42, TEST_PROTO_ENUM_VALUE_C]"));
}

TEST(ProtoEnumUtilTest, IterateEnum) {
  std::vector<TestProtoEnum> values;
  for (TestProtoEnum e : ProtoEnumRange<TestProtoEnum>()) {
    values.push_back(e);
  }
  EXPECT_THAT(values, ElementsAreArray(kAllValues));
}

TEST(ProtoEnumUtilTest, IteratorEquality) {
  EXPECT_THAT(ProtoEnumRange<TestProtoEnum>().begin(),
              Eq(ProtoEnumRange<TestProtoEnum>().begin()));
}

TEST(ProtoEnumUtilTest, IteratorInequality) {
  EXPECT_THAT(ProtoEnumRange<TestProtoEnum>().begin(),
              Ne(ProtoEnumRange<TestProtoEnum>().end()));
}

}  // namespace
}  // namespace asylo
