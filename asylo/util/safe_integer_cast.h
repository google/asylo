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

#ifndef ASYLO_UTIL_SAFE_INTEGER_CAST_H_
#define ASYLO_UTIL_SAFE_INTEGER_CAST_H_

#include <cstdint>
#include <limits>
#include <type_traits>

#include "absl/types/optional.h"

namespace asylo {

// Converts |source| from a SourceIntT to a DestIntT, or returns absl::nullopt
// if |source| cannot be represented as a DestIntT.
//
template <typename DestIntT, typename SourceIntT>
inline absl::optional<DestIntT> SafeIntegerCast(SourceIntT source) {
  static_assert(std::is_integral<DestIntT>::value,
                "DestIntT must be an integral type");
  static_assert(std::is_integral<SourceIntT>::value,
                "SourceIntT must be an integral type");
  static_assert(sizeof(SourceIntT) <= sizeof(intmax_t),
                "SourceIntT must not be larger than intmax_t. Note that this "
                "error indicates that your compiler is not "
                "standard-compliant.");
  static_assert(sizeof(DestIntT) <= sizeof(intmax_t),
                "SourceIntT must not be larger than intmax_t. Note that this "
                "error indicates that your compiler is not "
                "standard-compliant.");

  static constexpr bool IsSourceIntTUnsigned =
      std::is_unsigned<SourceIntT>::value;
  static constexpr bool IsDestIntTUnsigned = std::is_unsigned<DestIntT>::value;
  static constexpr intmax_t kDestIntTMin =
      static_cast<intmax_t>(std::numeric_limits<DestIntT>::min());
  static constexpr uintmax_t kDestIntTMax =
      static_cast<uintmax_t>(std::numeric_limits<DestIntT>::max());

  if (IsSourceIntTUnsigned != IsDestIntTUnsigned ||
      sizeof(SourceIntT) > sizeof(DestIntT)) {
    if (source < static_cast<SourceIntT>(0)) {
      if (IsDestIntTUnsigned || static_cast<intmax_t>(source) < kDestIntTMin) {
        return absl::nullopt;
      }
    } else if (static_cast<uintmax_t>(source) > kDestIntTMax) {
      return absl::nullopt;
    }
  }

  return static_cast<DestIntT>(source);
}

}  // namespace asylo

#endif  // ASYLO_UTIL_SAFE_INTEGER_CAST_H_
