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

#ifndef ASYLO_UTIL_PROTO_ENUM_UTIL_H_
#define ASYLO_UTIL_PROTO_ENUM_UTIL_H_

#include <string>

#include <google/protobuf/descriptor.h>
#include <google/protobuf/generated_enum_reflection.h>

namespace asylo {

// Returns a human-readable name for |enum_value|. ProtoEnumT must be a protobuf
// enum type.
//
// If |enum_value| is one of the enumerator values of ProtoEnumT, then
// ProtoEnumValueName() returns the name of the enumerator value. Otherwise,
// ProtoEnumValueName() returns the decimal representation of |enum_value|.
template <typename ProtoEnumT>
std::string ProtoEnumValueName(ProtoEnumT enum_value) {
  const google::protobuf::EnumValueDescriptor *value_descriptor =
      google::protobuf::GetEnumDescriptor<ProtoEnumT>()->FindValueByNumber(enum_value);
  if (value_descriptor == nullptr) {
    return std::to_string(enum_value);
  }

  return value_descriptor->name();
}

}  // namespace asylo

#endif  // ASYLO_UTIL_PROTO_ENUM_UTIL_H_
