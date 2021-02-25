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

#include "asylo/util/proto_struct_util.h"

#include "google/protobuf/struct.pb.h"
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/status/status.h"
#include "asylo/test/util/proto_matchers.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status.h"

namespace asylo {
namespace sgx {
namespace {

using ::testing::Pointee;
using ::testing::StrEq;

TEST(JsonUtilTest, JsonGetObjectFailsOnNonObjects) {
  google::protobuf::Value value;
  value.set_number_value(0.);
  EXPECT_THAT(JsonGetObject(value),
              StatusIs(absl::StatusCode::kInvalidArgument));

  value.set_string_value("");
  EXPECT_THAT(JsonGetObject(value),
              StatusIs(absl::StatusCode::kInvalidArgument));

  value.mutable_list_value();
  EXPECT_THAT(JsonGetObject(value),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(JsonUtilTest, JsonGetObjectSucceedsOnObjects) {
  google::protobuf::Value value;
  value.mutable_struct_value();
  EXPECT_THAT(JsonGetObject(value),
              IsOkAndHolds(Pointee(EqualsProto(google::protobuf::Struct()))));
}

TEST(JsonUtilTest, JsonGetArrayFailsOnNonArrays) {
  google::protobuf::Value value;
  value.set_number_value(0.);
  EXPECT_THAT(JsonGetArray(value),
              StatusIs(absl::StatusCode::kInvalidArgument));

  value.set_string_value("");
  EXPECT_THAT(JsonGetArray(value),
              StatusIs(absl::StatusCode::kInvalidArgument));

  value.mutable_struct_value();
  EXPECT_THAT(JsonGetArray(value),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(JsonUtilTest, JsonGetArraySucceedsOnArrays) {
  google::protobuf::Value value;
  value.mutable_list_value();
  EXPECT_THAT(
      JsonGetArray(value),
      IsOkAndHolds(Pointee(EqualsProto(google::protobuf::ListValue()))));
}

TEST(JsonUtilTest, JsonGetStringFailsOnNonStrings) {
  google::protobuf::Value value;
  value.set_number_value(0.);
  EXPECT_THAT(JsonGetString(value),
              StatusIs(absl::StatusCode::kInvalidArgument));

  value.mutable_list_value();
  EXPECT_THAT(JsonGetString(value),
              StatusIs(absl::StatusCode::kInvalidArgument));

  value.mutable_struct_value();
  EXPECT_THAT(JsonGetString(value),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(JsonUtilTest, JsonGetStringSucceedsOnStrings) {
  google::protobuf::Value value;
  value.set_string_value("");
  EXPECT_THAT(JsonGetString(value), IsOkAndHolds(Pointee(StrEq(""))));

  value.set_string_value("foobar");
  EXPECT_THAT(JsonGetString(value), IsOkAndHolds(Pointee(StrEq("foobar"))));
}

TEST(JsonUtilTest, JsonGetNumberFailsOnNonNumbers) {
  google::protobuf::Value value;
  value.set_string_value("");
  EXPECT_THAT(JsonGetNumber(value),
              StatusIs(absl::StatusCode::kInvalidArgument));

  value.mutable_list_value();
  EXPECT_THAT(JsonGetNumber(value),
              StatusIs(absl::StatusCode::kInvalidArgument));

  value.mutable_struct_value();
  EXPECT_THAT(JsonGetNumber(value),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(JsonUtilTest, JsonGetNumberSucceedsOnNumbers) {
  google::protobuf::Value value;
  value.set_number_value(0.);
  EXPECT_THAT(JsonGetNumber(value), IsOkAndHolds(0.));

  value.set_number_value(12.);
  EXPECT_THAT(JsonGetNumber(value), IsOkAndHolds(12.));

  value.set_number_value(-3.14);
  EXPECT_THAT(JsonGetNumber(value), IsOkAndHolds(-3.14));
}

TEST(JsonUtilTest, JsonObjectGetFieldFailsIfTheFieldIsAbsent) {
  google::protobuf::Struct object;
  google::protobuf::Value value;
  value.set_number_value(0.);
  object.mutable_fields()->insert({"bar", value});
  EXPECT_THAT(JsonObjectGetField(object, "foo"),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(JsonUtilTest, JsonObjectGetFieldSucceedsIfTheFieldIsPresent) {
  google::protobuf::Struct object;
  google::protobuf::Value value;
  value.set_number_value(0.);
  object.mutable_fields()->insert({"foo", value});
  EXPECT_THAT(JsonObjectGetField(object, "foo"),
              IsOkAndHolds(Pointee(EqualsProto(object.fields().at("foo")))));
}

}  // namespace
}  // namespace sgx
}  // namespace asylo
