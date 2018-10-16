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

#include "asylo/bazel/application_wrapper/argv.h"

#include <array>
#include <string>

#include <google/protobuf/repeated_field.h>
#include <gtest/gtest.h>
#include "absl/base/macros.h"

namespace asylo {
namespace {

// Example command-line arguments used for testing.
constexpr char kTestArgs[][9] = {"the",  "quick", "brown", "fox", "jumps",
                                 "over", "the",   "lazy",  "dog"};

// Tests that WriteArgvToRepeatedStringField correctly converts from the
// conventional argc/argv representation to a repeated string field in a
// protobuf.
TEST(ArgvTest, ArgcArgvToRepeatedStringField) {
  std::array<const char *, ABSL_ARRAYSIZE(kTestArgs)> test_argv;
  for (int i = 0; i < ABSL_ARRAYSIZE(kTestArgs); ++i) {
    test_argv[i] = kTestArgs[i];
  }

  google::protobuf::RepeatedPtrField<std::string> repeated_string_field;
  Argv::WriteArgvToRepeatedStringField(test_argv.size(), test_argv.data(),
                                       &repeated_string_field);

  ASSERT_EQ(repeated_string_field.size(), test_argv.size());
  for (int i = 0; i < repeated_string_field.size(); ++i) {
    EXPECT_EQ(repeated_string_field[i], test_argv[i]);
  }
}

// Tests that Argv correctly converts from a repeated string field in a protobuf
// to the conventional argc/argv representation.
TEST(ArgvTest, RepeatedStringFieldToArgcArgv) {
  google::protobuf::RepeatedPtrField<std::string> repeated_string_field;
  repeated_string_field.Reserve(ABSL_ARRAYSIZE(kTestArgs));
  for (int i = 0; i < ABSL_ARRAYSIZE(kTestArgs); ++i) {
    *repeated_string_field.Add() = kTestArgs[i];
  }

  Argv arguments(repeated_string_field);
  int argc = arguments.argc();
  char **argv = arguments.argv();

  ASSERT_EQ(argc, repeated_string_field.size());
  for (int i = 0; i < argc; ++i) {
    EXPECT_EQ(argv[i], repeated_string_field[i]);
  }
  EXPECT_EQ(argv[argc], nullptr);
}

}  // namespace
}  // namespace asylo
