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

#ifndef ASYLO_UTIL_PATH_H_
#define ASYLO_UTIL_PATH_H_

#include <string>

#include "absl/strings/string_view.h"

namespace asylo {

// JoinPath() is a family of utility functions that can be used to assemble
// POSIX path fragments into a single canonical path. JoinPath() may be invoked
// with an arbitrary number of arguments of various types. However, each of
// those arguments must be implicitly convertible to absl::string_view.
//
// All functions in this family assume that their inputs are well-formed
// POSIX-path fragments. If the inputs are not well-formed, the resulting string
// might not be a well-formed POSIX path.

// Declarations of JoinPath() that take less than three arguments.

// Returns an empty string.
std::string JoinPath();

// Copies contents of |path1| to a new string and returns it.
std::string JoinPath(absl::string_view path);

// Generates a new string that contains the concatenation of |path1|, "/", and
// |path2|, and returns that string. Strips out any '/' characters from the end
// of |path1| and the beginning of |path2| before performing the concatenation.
std::string JoinPath(absl::string_view path1, absl::string_view path2);

// Variadic definition of JoinPath() that takes three or more arguments.
template <typename... Args>
std::string JoinPath(absl::string_view path1, absl::string_view path2,
                     absl::string_view path3, Args... args) {
  return JoinPath(JoinPath(JoinPath(path1, path2), path3),
                  std::forward<Args>(args)...);
}

}  // namespace asylo

#endif  // ASYLO_UTIL_PATH_H_
