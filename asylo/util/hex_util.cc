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

#include "asylo/util/hex_util.h"

#include <endian.h>

#include "absl/strings/ascii.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"

namespace asylo {

bool IsHexEncoded(absl::string_view str) {
  for (char c : str) {
    if (!absl::ascii_isxdigit(c)) {
      return false;
    }
  }
  return str.size() % 2 == 0;
}

std::string Uint16ToLittleEndianHexString(uint16_t val) {
  uint16_t le_val = htole16(val);
  return absl::BytesToHexString(
      absl::string_view{reinterpret_cast<char *>(&le_val), sizeof(uint16_t)});
}

std::string BufferToDebugHexString(const void *buf, int nbytes) {
  if (!buf) {
    return "null";
  }
  if (nbytes < 0) {
    return absl::StrCat("[ERROR: negative length ", nbytes, "]");
  }
  if (nbytes == 0) {
    return "[]";
  }
  return absl::StrCat("[0x",
                      absl::BytesToHexString(absl::string_view(
                          reinterpret_cast<const char *>(buf), nbytes)),
                      "]");
}

}  // namespace asylo
