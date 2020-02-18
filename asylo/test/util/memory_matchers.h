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

#ifndef ASYLO_TEST_UTIL_MEMORY_MATCHERS_H_
#define ASYLO_TEST_UTIL_MEMORY_MATCHERS_H_

#include <cstddef>
#include <cstdint>
#include <type_traits>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/strings/str_format.h"

namespace asylo {
namespace memory_matchers_internal {

using ::testing::MatchResultListener;

// Returns true if two buffers are the same size and contain the same bytes.
bool MemoryEquals(MatchResultListener *listener, const void *expected,
                  size_t expected_size, const void *actual,
                  size_t actual_size) {
  if (expected_size != actual_size) {
    *listener << " due to a size mismatch; expected: " << expected_size << ", "
              << "actual: " << actual_size;
    return false;
  }

  const uint8_t *actual_bytes = static_cast<const uint8_t *>(actual);
  const uint8_t *expected_bytes = static_cast<const uint8_t *>(expected);
  for (size_t i = 0; i < expected_size; ++i) {
    if (actual_bytes[i] != expected_bytes[i]) {
      *listener << absl::StrFormat(
          "which contains byte 0x%x at position %d where byte 0x%x was "
          "expected",
          actual_bytes[i], i, expected_bytes[i]);
      return false;
    }
  }

  return true;
}

template <typename T>
constexpr void StaticAssertMemComparable(const T &) {
  static_assert(!std::is_pointer<T>::value, "Type must not be a pointer");
  static_assert(std::is_trivially_copy_assignable<T>::value,
                "Type must be raw memory comparable.");
}

}  // namespace memory_matchers_internal

// Matches two trivial objects by comparing their raw memory. The objects' types
// must be trivially copyable and the same size. Either objects or
// pointers-to-objects may be compared by this matcher.
//
// NOTE: If the types being compared are objects with padding between fields,
// then this matcher may not always work as expected. Padding bytes are not
// necessarily copied by compiler-generated assignment operators.
MATCHER_P(TrivialObjectEq, expected,
          absl::StrFormat("contains %s bytes as the buffer at address %p",
                          (negation ? "same" : "different"), &expected)) {
  static_assert(sizeof(expected_type) == sizeof(arg_type),
                "Expected and arg sizes do not match");
  memory_matchers_internal::StaticAssertMemComparable(expected);
  memory_matchers_internal::StaticAssertMemComparable(arg);
  return memory_matchers_internal::MemoryEquals(result_listener, &expected,
                                                sizeof(expected_type), &arg,
                                                sizeof(arg_type));
}

// Matches a buffer by comparing the first |size| bytes of |expected| and |arg|.
MATCHER_P2(MemEq, expected, size, "") {
  using ExpectedNonRefT = typename std::remove_reference<expected_type>::type;
  using ArgNonRefT = typename std::remove_reference<arg_type>::type;
  static_assert(std::is_pointer<ExpectedNonRefT>::value,
                "Expected must be pointer");
  static_assert(std::is_pointer<ArgNonRefT>::value, "Arg must be a pointer");

  using ExpectedPointeeT = typename std::remove_pointer<ExpectedNonRefT>::type;
  using ArgPointeeT = typename std::remove_pointer<ArgNonRefT>::type;
  static_assert(!std::is_pointer<ExpectedPointeeT>::value,
                "Expected type must not be a double-pointer");
  static_assert(!std::is_pointer<ArgPointeeT>::value,
                "Arg type must not be a double-pointer");

  return memory_matchers_internal::MemoryEquals(result_listener, expected, size,
                                                arg, size);
}

}  // namespace asylo

#endif  // ASYLO_TEST_UTIL_MEMORY_MATCHERS_H_
