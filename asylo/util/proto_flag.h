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

#ifndef ASYLO_UTIL_PROTO_FLAG_H_
#define ASYLO_UTIL_PROTO_FLAG_H_

#include <string>

#include <google/protobuf/text_format.h>
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "asylo/util/logging.h"

namespace asylo {

// @file proto_flag.h
// @brief The functions in this file add support for parsing protobuf flags that
// are passed as textprotos. Only protobufs in the asylo namespace are
// supported.

template <class T>
bool AbslParseFlag(absl::string_view text, T *flag, std::string *error) {
  if (!google::protobuf::TextFormat::ParseFromString(
          std::string(text.data(), text.size()), flag)) {
    *error =
        absl::StrCat("Failed to parse ", flag->GetDescriptor()->full_name());
    return false;
  }
  return true;
}

template <class T>
std::string AbslUnparseFlag(const T &flag) {
  std::string serialized_flag;
  CHECK(google::protobuf::TextFormat::PrintToString(flag, &serialized_flag));
  return serialized_flag;
}

}  // namespace asylo

#endif  // ASYLO_UTIL_PROTO_FLAG_H_
