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

#ifndef ASYLO_PLATFORM_COMMON_DEBUG_STRINGS_H_
#define ASYLO_PLATFORM_COMMON_DEBUG_STRINGS_H_

#include <string>

namespace asylo {

// If |buf| is nullptr, returns "null".
// If |nbytes| is 0, returns "[]".
// If |nbytes| is negative, returns an error message with the negative value.
// Otherwise, returns "[0x" buf[0]...buf[nbytes-1] "]" formatted as hexadecimal
// digits.
std::string buffer_to_hex_string(const void *buf, int nbytes);

}  // namespace asylo

#endif  // ASYLO_PLATFORM_COMMON_DEBUG_STRINGS_H_
