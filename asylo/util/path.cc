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

#include "asylo/util/path.h"

#include "absl/strings/str_cat.h"

namespace asylo {

std::string JoinPath() { return std::string(); }

std::string JoinPath(absl::string_view path) {
  return std::string(path.data(), path.size());
}

std::string JoinPath(absl::string_view path1, absl::string_view path2) {
  if (path1.empty()) {
    return JoinPath(path2);
  }
  if (path2.empty()) {
    return JoinPath(path1);
  }
  if (path1.back() == '/') {
    return JoinPath(path1.substr(0, path1.size() - 1), path2);
  }
  if (path2.front() == '/') {
    return JoinPath(path1, path2.substr(1, path2.size() - 1));
  }
  return absl::StrCat(path1, "/", path2);
}

}  // namespace asylo
