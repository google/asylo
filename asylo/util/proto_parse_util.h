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

#ifndef ASYLO_UTIL_PROTO_PARSE_UTIL_H_
#define ASYLO_UTIL_PROTO_PARSE_UTIL_H_

#include <string>

#include <google/protobuf/text_format.h>
#include "absl/strings/string_view.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"

namespace asylo {

// Parses |text| into a protobuf of type |T| on success. Returns
// INVALID_ARGUMENT if the input is not a valid textproto encoding of |T|.
template <typename T>
StatusOr<T> ParseTextProto(absl::string_view text) {
  T proto;
  if (!google::protobuf::TextFormat::ParseFromString(std::string{text}, &proto)) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "Invalid textproto input");
  }
  return proto;
}

// Parses |text| into a protobuf of type |T| on success. Results in a fatal
// error if the input is not a valid textproto encoding of |T|.
template <typename T>
T ParseTextProtoOrDie(absl::string_view text) {
  return ParseTextProto<T>(text).ValueOrDie();
}

}  // namespace asylo

#endif  // ASYLO_UTIL_PROTO_PARSE_UTIL_H_
