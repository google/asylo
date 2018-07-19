/*
 *
 * Copyright 2017 Asylo authors
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

#include "asylo/crypto/util/bssl_util.h"

#include <string>

namespace asylo {

std::string BsslLastErrorString() {
  static constexpr int kErrorStringBufferLength = 256;
  static char buffer[kErrorStringBufferLength];
  ERR_error_string_n(ERR_get_error(), buffer, sizeof(buffer));
  ERR_clear_error();
  return std::string(buffer);
}

}  // namespace asylo
