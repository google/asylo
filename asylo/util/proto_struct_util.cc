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

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"

namespace asylo {

StatusOr<const google::protobuf::Struct *> JsonGetObject(
    const google::protobuf::Value &value) {
  if (value.kind_case() != google::protobuf::Value::kStructValue) {
    return absl::InvalidArgumentError("JSON value is not an object");
  }

  return &value.struct_value();
}

StatusOr<const google::protobuf::ListValue *> JsonGetArray(
    const google::protobuf::Value &value) {
  if (value.kind_case() != google::protobuf::Value::kListValue) {
    return absl::InvalidArgumentError("JSON value is not an array");
  }

  return &value.list_value();
}

StatusOr<const std::string *> JsonGetString(
    const google::protobuf::Value &value) {
  if (value.kind_case() != google::protobuf::Value::kStringValue) {
    return absl::InvalidArgumentError("JSON value is not a string");
  }

  return &value.string_value();
}

StatusOr<double> JsonGetNumber(const google::protobuf::Value &value) {
  if (value.kind_case() != google::protobuf::Value::kNumberValue) {
    return absl::InvalidArgumentError("JSON value is not an integer");
  }

  return value.number_value();
}

StatusOr<const google::protobuf::Value *> JsonObjectGetField(
    const google::protobuf::Struct &object, const std::string &field_name) {
  if (!object.fields().contains(field_name)) {
    return absl::InvalidArgumentError(
        absl::StrCat("JSON object does not have a ", field_name, " field"));
  }

  return &object.fields().at(field_name);
}

}  // namespace asylo
