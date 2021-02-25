/*
 *
 * Copyright 2020 Asylo authors
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

#include "asylo/util/proto_parse_util.h"

#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/status/status.h"
#include "asylo/test/util/proto_matchers.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/proto_parse_util_test.pb.h"

namespace asylo {
namespace {

TEST(ProtoParseUtilTest, ParseEmptyMessage) {
  TestMessage expected;
  EXPECT_THAT(ParseTextProto<TestMessage>(""),
              IsOkAndHolds(EqualsProto(expected)));
  TestMessage message = ParseTextProtoOrDie("");
  EXPECT_THAT(message, EqualsProto(expected));
}

TEST(ProtoParseUtilTest, ParsePartialMessage) {
  constexpr absl::string_view kInput = R"proto(
    enum_field: TEST_VALUE_FORTY_TWO
  )proto";

  TestMessage expected;
  expected.set_enum_field(TEST_VALUE_FORTY_TWO);
  EXPECT_THAT(ParseTextProto<TestMessage>(kInput),
              IsOkAndHolds(EqualsProto(expected)));
  TestMessage actual = ParseTextProtoOrDie(kInput);
  EXPECT_THAT(actual, EqualsProto(expected));
}

TEST(ProtoParseUtilTest, ParseFullMessage) {
  constexpr absl::string_view kInput = R"proto(
    enum_field: TEST_VALUE_ONE
    int_field: 123
    message_field: { string_field: "Lorem ipsum" }
  )proto";

  TestMessage expected;
  expected.set_enum_field(TEST_VALUE_ONE);
  expected.set_int_field(123);
  expected.mutable_message_field()->set_string_field("Lorem ipsum");
  EXPECT_THAT(ParseTextProto<TestMessage>(kInput),
              IsOkAndHolds(EqualsProto(expected)));
  TestMessage actual = ParseTextProtoOrDie(kInput);
  EXPECT_THAT(actual, EqualsProto(expected));
}

TEST(ProtoParseUtilTest, ParseInvalidInput) {
  TestMessage expected;
  EXPECT_THAT(ParseTextProto<TestMessage>("garbage"),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_DEATH_IF_SUPPORTED(TestMessage m = ParseTextProtoOrDie("junk"), "");
}

}  // namespace
}  // namespace asylo
