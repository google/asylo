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

#ifndef ASYLO_UTIL_HEX_UTIL_H_
#define ASYLO_UTIL_HEX_UTIL_H_

#include <cstdint>
#include <string>

#include "absl/strings/string_view.h"

namespace asylo {

// Returns true if |str| can be interpreted as a hex-encoding of a sequence of
// bytes.
bool IsHexEncoded(absl::string_view str);

// Returns the little-endian hex-string representation of |val|.
std::string Uint16ToLittleEndianHexString(uint16_t val);

// Returns a hex representation of the provided input buffer of a given size.
// If |buf| is nullptr, returns "null".
// If |nbytes| is 0, returns "[]".
// If |nbytes| is negative, returns an error message with the negative value.
// Otherwise, returns "[0x" buf[0]...buf[nbytes-1] "]" formatted as hexadecimal
// digits.
std::string BufferToDebugHexString(const void *buf, int nbytes);

}  // namespace asylo

#endif  // ASYLO_UTIL_HEX_UTIL_H_
