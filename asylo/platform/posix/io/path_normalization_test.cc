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

#include <utility>
#include <vector>

#include <gtest/gtest.h>
#include "absl/strings/str_replace.h"
#include "absl/strings/string_view.h"
#include "asylo/platform/posix/io/util.h"

namespace asylo {
namespace io {
namespace util {
namespace {

using PathParams = std::vector<std::pair<absl::string_view, absl::string_view>>;

// Value-parameterized test that accepts entries from a map pairing input
// strings to expected output strings.
class PathNormalizationTest
    : public ::testing::TestWithParam<PathParams::value_type> {};

// Provides a more informative test name for the various paths being tested. The
// input path is appended to the test name, with substitutions for characters
// not allowed in test names. Returns std::string instead of string to match
// expectections of gtest code that will use this.
std::string PathParamsValueToTestName(
    ::testing::TestParamInfo<PathParams::value_type> param_info) {
  absl::string_view input = param_info.param.first;

  // Empty names are not allowed.
  if (input.empty()) return "EMPTY";

  // '/', '\', and '.' are not allowed.
  // Replace them with '_', 'B', and 'D', respectively.
  return absl::StrReplaceAll(input, {{"/", "_"}, {"\\", "B"}, {".", "D"}});
}

// This parameterized test case simply verifies that NormalizePath's output
// matches the expected output for the provided parameters.
TEST_P(PathNormalizationTest, HasExpectedResult) {
  PathParams::value_type params = GetParam();
  EXPECT_EQ(NormalizePath(params.first), params.second);
}

// Returns a mapping of inputs to outputs to be verified.
PathParams GetTestPathParams() {
  return {
      {"", "/"},
      {"/", "/"},
      {".", "/"},
      {"..", "/"},
      {"/.", "/"},
      {"/..", "/"},
      {"./", "/"},
      {"../", "/"},
      {"/./", "/"},
      {"/../", "/"},
      {"foo", "/foo"},
      {"foo/", "/foo"},
      {"/foo/bar", "/foo/bar"},
      {"/foo/bar/", "/foo/bar"},
      {"foo/bar", "/foo/bar"},
      {"foo/bar/", "/foo/bar"},
      {"/../foo/bar", "/foo/bar"},
      {"/./foo/bar", "/foo/bar"},
      {"/foo/bar/..", "/foo"},
      {"/foo/bar/.", "/foo/bar"},
      {"/foo/./bar", "/foo/bar"},
      {"/foo/../bar", "/bar"},
      {"/foo/../../bar", "/bar"},
      {"foo/../../bar", "/bar"},
      {"/foo/././bar", "/foo/bar"},
      {"/foo/../..", "/"},
      {"foo/../..", "/"},
      {"/foo/../bar/baz/..", "/bar"},
      {"/foo/bar/baz/../../qux", "/foo/qux"},
      {"//foo/bar", "/foo/bar"},
      {"/foo//bar", "/foo/bar"},
      {"foo//////bar", "/foo/bar"},
      {"/foo/bar//", "/foo/bar"},
      {"/foo/bar\\/baz/../qux", "/foo/bar\\/qux"},
  };
}

// Instantiates a test case for each of the entries in the |test_params| map.
INSTANTIATE_TEST_SUITE_P(PathList, PathNormalizationTest,
                         ::testing::ValuesIn(GetTestPathParams()),
                         PathParamsValueToTestName);

}  // namespace
}  // namespace util
}  // namespace io
}  // namespace asylo
