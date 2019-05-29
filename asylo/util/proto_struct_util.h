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

#ifndef ASYLO_UTIL_PROTO_STRUCT_UTIL_H_
#define ASYLO_UTIL_PROTO_STRUCT_UTIL_H_

#include <string>

#include "google/protobuf/struct.pb.h"
#include "asylo/util/statusor.h"

namespace asylo {

// This file contains functions to work with the google::protobuf::Value
// representation of JSON objects. It is intended to be used for verifying that
// a JSON message matches a specification.
//
// NOTE: Many of the functions in this file return references into their inputs.
// Users must ensure that the inputs outlive the returned references, and that
// the inputs are not mutated in a way that invalidates the returned references.

// Returns &value.struct_value() if |value| is a JSON object. Otherwise, returns
// an INVALID_ARGUMENT error.
StatusOr<const google::protobuf::Struct *> JsonGetObject(
    const google::protobuf::Value &value);

// Returns &value.list_value() if |value| is a JSON array. Otherwise, returns an
// INVALID_ARGUMENT error.
StatusOr<const google::protobuf::ListValue *> JsonGetArray(
    const google::protobuf::Value &value);

// Returns value.string_value() if |value| is a string. Otherwise, returns an
// INVALID_ARGUMENT error.
StatusOr<const std::string *> JsonGetString(
    const google::protobuf::Value &value);

// Returns value.number_value() if |value| is a number. Otherwise, returns an
// INVALID_ARGUMENT error.
StatusOr<double> JsonGetNumber(const google::protobuf::Value &value);

// Returns a pointer to |object|'s |field_name| field if |object| has a field
// called |field_name|. Otherwise, returns an INVALID_ARGUMENT error.
//
// Note that if |object| is mutated the returned pointer may become invalid.
StatusOr<const google::protobuf::Value *> JsonObjectGetField(
    const google::protobuf::Struct &object, const std::string &field_name);

}  // namespace asylo

#endif  // ASYLO_UTIL_PROTO_STRUCT_UTIL_H_
