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

#ifndef ASYLO_BAZEL_APPLICATION_WRAPPER_ARGV_H_
#define ASYLO_BAZEL_APPLICATION_WRAPPER_ARGV_H_

#include <string>
#include <vector>

#include <google/protobuf/repeated_field.h>
#include "absl/strings/string_view.h"

namespace asylo {

// A utility class that owns an array of null-terminated strings and provides
// constant-time conversion to the underlying array. Argv is intended to be used
// to deserialize arguments that are passed to a function that has the calling
// contract of the main() function (C Standard section 5.1.2.2.1).
class Argv {
 public:
  // Constructs an Argv from a container of string-like objects.
  // StringViewIterableT must support STL-style iteration, and its element type
  // must be implicitly convertible to absl::string_view.
  template <typename StringViewIterableT>
  explicit Argv(const StringViewIterableT &arguments) {
    size_t total_args_length = 0;
    for (absl::string_view argument : arguments) {
      total_args_length += argument.size();
    }
    args_contiguous_.resize(total_args_length + arguments.size());

    int next_arg_index = 0;
    argv_.reserve(arguments.size() + 1);
    for (absl::string_view argument : arguments) {
      argument.copy(&args_contiguous_[next_arg_index], argument.size());
      args_contiguous_[next_arg_index + argument.size()] = '\0';
      argv_.push_back(&args_contiguous_[next_arg_index]);
      next_arg_index += argument.size() + 1;
    }
    argv_.push_back(nullptr);
  }

  // Returns the number of command-line arguments.
  int argc() const;

  // Returns an array of pointers to null-terminated strings, representing the
  // command-line arguments in order. The array has argc() + 1 elements, and the
  // last element is a nullptr.
  //
  // The returned array and all contained strings are owned by the Argv.
  char **argv();

  // Writes the null-terminated strings in the |argc|-long array |argv| to
  // |field|.
  static void WriteArgvToRepeatedStringField(
      int argc, const char *const *argv,
      google::protobuf::RepeatedPtrField<std::string> *field);

 private:
  // A buffer containing the command-line arguments. The arguments are separated
  // from each other by null bytes.
  std::string args_contiguous_;

  // An array of pointers into args_contiguous_, representing the command-line
  // arguments in order. The last element is a null pointer to conform with the
  // calling contract of main().
  std::vector<char *> argv_;
};

}  // namespace asylo

#endif  // ASYLO_BAZEL_APPLICATION_WRAPPER_ARGV_H_
