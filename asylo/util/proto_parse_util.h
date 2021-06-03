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
#include "absl/status/status.h"
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
    return absl::InvalidArgumentError("Invalid textproto input");
  }
  return proto;
}

namespace internal {

// Helper type which can perform implicit conversions of textproto to some
// protobuf message type. If the conversion is not valid, then the program
// is aborted. This type is intended to be used only with `ParseTextProtoOrDie`.
class ParseTextProtoOrDieHelper {
 public:
  explicit ParseTextProtoOrDieHelper(absl::string_view text) : text_(text) {}

  template <typename T>
  operator T() const {
    auto parse_result = ParseTextProto<T>(text_);
    ASYLO_CHECK_OK(parse_result.status());
    return *parse_result;
  }

 private:
  absl::string_view text_;
};

}  // namespace internal

// Parses |text| into a protobuf via `ParseTextProtoOrDieHelper`, which performs
// the actual conversion. A helper type is used so that callers do not have to
// explicitly pass a template parameter for the desired output message type.
// If |text| cannot successfully be parsed, the program is aborted. This
// function is intended to be used for static protobufs, which are known good
// at build time. If |text| is not a known, build time constant,
// `ParseTextProto` should be used instead.
inline internal::ParseTextProtoOrDieHelper ParseTextProtoOrDie(
    absl::string_view text) {
  return internal::ParseTextProtoOrDieHelper(text);
}

}  // namespace asylo

#endif  // ASYLO_UTIL_PROTO_PARSE_UTIL_H_
