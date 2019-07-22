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

#ifndef ASYLO_UTIL_BINARY_SEARCH_H_
#define ASYLO_UTIL_BINARY_SEARCH_H_

#include <cstddef>
#include <functional>
#include <limits>
#include <type_traits>

#include "asylo/util/function_traits.h"

namespace asylo {

// Returns the largest size_t for which f returns true, or 0 if f returns
// false for all numbers. Assumes f returns true for all numbers from 0 up
// to an unknown constant k, and false above that. Finds an upper bound in such
// a way that f will never be called on an argument larger than 2*k.
template <class FuncT>
size_t BinarySearch(FuncT f) {
  // Force f to have the correct type.
  static_assert(FunctionTraits<FuncT>::template CheckReturnType<bool>::value,
                "Expected a function which returns a bool");
  static_assert(
      FunctionTraits<FuncT>::template CheckArgumentTypes<size_t>::value,
      "Expected a function which returns takes a size_t");

  if (!f(0) || !f(1)) {
    return 0;
  }

  size_t lower_bound = 1;
  size_t upper_bound = 2;
  size_t max_bits = sizeof(size_t) * 8;

  // Successively double to find reasonable upper bound.
  // This avoids calling f on max value for size_t
  // (which could be extremely expensive in some cases).
  for (int i = 1; i < max_bits && f(upper_bound); i++) {
    lower_bound = size_t{1} << i;
    if (i != max_bits - 1) {
      upper_bound = lower_bound << 1;
    } else {
      upper_bound = std::numeric_limits<std::ptrdiff_t>::max();
      if (f(upper_bound)) {
        return upper_bound;
      }
    }
  }

  // Invariant: f(lower_bound) is true, f(upper_bound) is false
  while (upper_bound - lower_bound > 1) {
    // Division before addition to avoid overflow
    size_t test_value = (lower_bound / 2) + (upper_bound / 2);
    // Guarantee progress by never testing the lower bound
    if (test_value == lower_bound) {
      test_value += 1;
    }
    if (f(test_value)) {
      lower_bound = test_value;
    } else {
      upper_bound = test_value;
    }
  }

  return lower_bound;
}

}  // namespace asylo

#endif  // ASYLO_UTIL_BINARY_SEARCH_H_
