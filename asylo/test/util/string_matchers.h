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

#ifndef ASYLO_TEST_UTIL_STRING_MATCHERS_H_
#define ASYLO_TEST_UTIL_STRING_MATCHERS_H_

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/strings/string_view.h"

namespace asylo {

void SkipWhiteSpace(absl::string_view::const_iterator it_end,
                    absl::string_view::const_iterator *it) {
  while (*it != it_end && isspace(**it)) {
    (*it)++;
  }
}

MATCHER_P(EqualIgnoreWhiteSpace, expected_arg, "") {
  // Make copies for modification.
  absl::string_view actual(arg);
  auto actual_it = actual.cbegin();
  absl::string_view expected(expected_arg);
  auto expected_it = expected.cbegin();

  SkipWhiteSpace(actual.end(), &actual_it);
  SkipWhiteSpace(expected.end(), &expected_it);

  while (actual_it != actual.end() && expected_it != expected.end()) {
    if (*actual_it != *expected_it) {
      return false;
    }
    actual_it++;
    expected_it++;
    SkipWhiteSpace(actual.end(), &actual_it);
    SkipWhiteSpace(expected.end(), &expected_it);
  }

  return actual_it == actual.end() && expected_it == expected.end();
}

}  // namespace asylo

#endif  // ASYLO_TEST_UTIL_STRING_MATCHERS_H_
