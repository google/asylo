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

#ifndef ASYLO_UTIL_STATUS_MACROS_H_
#define ASYLO_UTIL_STATUS_MACROS_H_

#include <type_traits>
#include <utility>

#include "absl/base/optimization.h"
#include "absl/status/status.h"

namespace asylo {
namespace internal {

// This template is chosen if the input object has a function called "status".
template <typename T>
inline constexpr bool HasStatus(decltype(std::declval<T>().status()) *) {
  return true;
}

// Default template, chosen when no prior templates match.
template <typename T>
inline constexpr bool HasStatus(...) {
  return false;
}

// `StatusOr`-like overload which returns a wrapped `Status`-like value.
template <typename T,
          typename std::enable_if<HasStatus<T>(nullptr), int>::type = 0>
inline auto ToStatus(T&& status_or) -> decltype(status_or.status()) {
  return status_or.status();
}

// Identity function for all `Status`-like objects.
template <typename T,
          typename std::enable_if<!HasStatus<T>(nullptr), int>::type = 0>
inline T ToStatus(T&& status_like) {
  return status_like;
}

}  // namespace internal
}  // namespace asylo

/// Evaluates an expression that produces an `Status`-like object with
/// a `.ok()` method. If this method returns false, the object is
/// returned from the current function. If the expression evaluates to a
/// `StatusOr` object, then it is converted to a `Status` on return.
///
/// Example:
/// ```
///   ::asylo::Status MultiStepFunction() {
///     ASYLO_RETURN_IF_ERROR(Function(args...));
///     ASYLO_RETURN_IF_ERROR(foo.Method(args...));
///     return ::absl::OkStatus();
///   }
/// ```
#define ASYLO_RETURN_IF_ERROR(expr)                                         \
do {                                                                        \
  auto _asylo_status_to_verify = (expr);                                    \
  if (ABSL_PREDICT_FALSE(!_asylo_status_to_verify.ok())) {                  \
    return ::asylo::internal::ToStatus(                                     \
        std::forward<decltype(_asylo_status_to_verify)>(                    \
            _asylo_status_to_verify));                                      \
  }                                                                         \
} while (false)

/// Evaluates an expression `rexpr` that returns a `StatusOr`-like
/// object with `.ok()`, `.status()`, and `.value()` methods.  If
/// the result is OK, moves its value into the variable defined by
/// `lhs`, otherwise returns the result of the `.status()` from the
/// current function. The error result of `.status` is returned
/// unchanged. If there is an error, `lhs` is not evaluated: thus any
/// side effects of evaluating `lhs` will only occur if `rexpr.ok()`
/// is true.
///
/// Interface:
/// ```
///   ASYLO_ASSIGN_OR_RETURN(lhs, rexpr)
/// ```
///
/// Example: Assigning to an existing variable:
/// ```
///   ValueType value;
///   ASYLO_ASSIGN_OR_RETURN(value, MaybeGetValue(arg));
/// ```
///
/// Example: Assigning to an expression with side effects:
/// ```
///   MyProto data;
///   ASYLO_ASSIGN_OR_RETURN(*data.mutable_str(), MaybeGetValue(arg));
///   // No field "str" is added on error.
/// ```
///
/// Example: Assigning to a `std::unique_ptr`.
/// ```
///   std::unique_ptr<T> ptr;
///   ASYLO_ASSIGN_OR_RETURN(ptr, MaybeGetPtr(arg));
/// ```
#define ASYLO_ASSIGN_OR_RETURN(lhs, rexpr)                  \
  do {                                                      \
    auto _asylo_status_or_value = (rexpr);                  \
    if (ABSL_PREDICT_FALSE(!_asylo_status_or_value.ok())) { \
      return _asylo_status_or_value.status();               \
    }                                                       \
    lhs = std::move(_asylo_status_or_value).value();        \
  } while (false)

#endif  // ASYLO_UTIL_STATUS_MACROS_H_
