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

#ifndef ASYLO_UTIL_URL_UTIL_H_
#define ASYLO_UTIL_URL_UTIL_H_

#include <string>

#include "absl/strings/string_view.h"
#include "asylo/util/statusor.h"

namespace asylo {

// Decodes URL-encoded |url| and resturns the result. Returns a non-OK Status if
// the decoding fails.
StatusOr<std::string> UrlDecode(absl::string_view url);

}  // namespace asylo

#endif  // ASYLO_UTIL_URL_UTIL_H_
