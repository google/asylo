/*
 *
 * Copyright 2018 Asylo authors
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

#include "asylo/platform/common/debug_strings.h"

#include <vector>

#include "absl/strings/str_cat.h"
#include "absl/types/span.h"

namespace asylo {
namespace {

std::string ToHex(absl::Span<const uint8_t> buffer) {
  // Each byte gets 2 characters for hex digits. The 1 is for the trailing '\0'
  // that snprintf inserts.
  std::vector<char> string_data(1 + buffer.size() * 2, '\0');
  size_t index = 0;
  for (auto byte : buffer) {
    snprintf(&string_data[index], string_data.size() - index, "%02X", byte);
    index += 2;
  }
  return std::string(string_data.data());
}

}  // namespace

std::string buffer_to_hex_string(const void *buf, int nbytes) {
  if (!buf) {
    return "null";
  }
  if (nbytes < 0) {
    return absl::StrCat("[ERROR: negative length ", nbytes, "]");
  }
  if (nbytes == 0) {
    return "[]";
  }
  return absl::StrCat(
      "[0x",
      ToHex(absl::MakeConstSpan(static_cast<const uint8_t *>(buf), nbytes)),
      "]");
}

}  // namespace asylo
