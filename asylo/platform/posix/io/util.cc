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

#include "asylo/platform/posix/io/util.h"

#include <vector>

#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"
#include "absl/strings/string_view.h"

namespace asylo {
namespace io {
namespace util {

std::string NormalizePath(absl::string_view path) {
  // Collects the current view of the directories in the path.
  std::vector<absl::string_view> directories;

  // Scan through the path, finding the directories.
  size_t current_directory = 0;
  while (current_directory < path.size()) {
    // Extract the next directory name.
    size_t next_directory = path.find_first_of('/', current_directory);
    if (next_directory == std::string::npos) next_directory = path.size();
    absl::string_view name =
        path.substr(current_directory, next_directory - current_directory);

    // Advance past the "/".
    current_directory = next_directory + 1;

    // If the directory name is empty or ".", leave it out entirely.
    if (name.empty() || name == ".") continue;

    // If the directory name is "..", back up by one.
    if (name == "..") {
      // If already at the root, stay at the root.
      if (!directories.empty()) directories.pop_back();
      continue;
    }

    // Otherwise, keep track of this directory.
    directories.push_back(name);
  }

  return absl::StrCat("/", absl::StrJoin(directories, "/"));
}

}  // namespace util
}  // namespace io
}  // namespace asylo
