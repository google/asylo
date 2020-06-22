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

#ifndef ASYLO_UTIL_STATUS_INTERNAL_H_
#define ASYLO_UTIL_STATUS_INTERNAL_H_

// This header is intended for internal use by the status library only. Other
// libraries should not include this header directly, no directly invoke the
// constructs defined in this header.

#include <string>
#include <type_traits>

#include "absl/meta/type_traits.h"
#include "asylo/util/error_space.h"

namespace asylo {
namespace status_internal {

// ErrorCodeHolder is an intermediate type capable of holding an integer error
// code, and implicitly converting it to any enum. This type is used in
// implicit conversion of a ::asylo::Status object to other status-type
// objects (e.g., ::util::Status or ::grpc::Status) that expect a specific
// type of enum as one of their constructor inputs.
struct ErrorCodeHolder {
  // Constructs an ErrorCodeHolder that holds |code|.
  explicit ErrorCodeHolder(int code) : error_code(code) {}

  // Implicit type-cast operator that converts stored code to an enum type
  // (enum or enum_class).
  template <typename EnumT,
            typename E = typename absl::enable_if_t<std::is_enum<EnumT>::value>>
  operator EnumT() {
    return static_cast<EnumT>(error_code);
  }
  int error_code;
};

// A traits structure that determines whether the template parameter StatusT is
// a status type and whether it supports the CanonicalCode() method. StatusT is
// considered a status type if:
//   1. It has a two-parameter constructor that takes an enum as its first
//      parameter and a string as its second parameter.
//   2. It has non-static error_code(), error_message(), and ok() methods.
// If StatusT meets the above requirements, then
// status_type_traits<StatusT>::is_status is statically set to true, else it is
// set to false.
//
// The structure also provides a public static method CanonicalCode() which
// returns the canonical-equivalent of the code held by the status-type object.
//
// If the object has a CanonicalCode() method, it calls that method. Otherwise,
// it calls the error_code() method and treats the returned value as an error
// code in the canonical error space.
template <typename StatusT>
struct status_type_traits {
 private:
  // Checks if the StatusT type supports the minimal API required of a
  // status-type object.
  //
  // Restrictive prototype. Objects that support the minimal API will match this
  // prototype.
  template <typename StatusU>
  static auto CheckMinimalApi(StatusU *s, int *i, std::string *str, bool *b)
      -> decltype(StatusU(ErrorCodeHolder(0), ""), *i = s->error_code(),
                  *str = std::string(s->error_message()), *b = s->ok(),
                  std::true_type());

  // Non-restrictive prototype. Objects that do not support the minimal API will
  // match this prototype.
  template <typename StatusU>
  static auto CheckMinimalApi(...) -> decltype(std::false_type());
  using minimal_api_type = decltype(CheckMinimalApi<StatusT>(
      static_cast<StatusT *>(0), static_cast<int *>(0),
      static_cast<std::string *>(0), static_cast<bool *>(0)));

  // Checks if the StatusT type implements the CanonicalCode() method.
  //
  // Restrictive prototype. Objects that implement the CanonicalCode() method
  // will match this prototype.
  template <typename StatusU>
  static auto CheckExtendedApi(StatusU *s, int *i)
      -> decltype(*i = s->Canonical());

  // Non-restrictive prototype. Objects that do not implement the
  // CanonicalCode() method will match this prototype.
  template <typename StatusU>
  static auto CheckExtendedApi(...) -> decltype(std::false_type());
  using extended_api_type = decltype(CheckExtendedApi<StatusT>(
      static_cast<StatusT *>(0), static_cast<int *>(0)));

  // CanonicalCode() implementation for types that implement the
  // CanonicalCode() method.
  static error::GoogleError CanonicalCode(const StatusT &status,
                                          std::true_type t) {
    return static_cast<error::GoogleError>(status.CanonicalCode());
  }

  // CanonicalCode() implementation for types that do not implement the
  // CanonicalCode() method.
  static error::GoogleError CanonicalCode(const StatusT &status,
                                          std::false_type t) {
    return static_cast<error::GoogleError>(status.error_code());
  }

 public:
  static constexpr bool is_status = minimal_api_type::value;

  // Returns the canonical-equivalent of the error code held by |status|.
  // |status| must be a status-type object.
  static error::GoogleError CanonicalCode(const StatusT &status) {
    static_assert(
        is_status,
        "CanonicalCode<StatusT>() invoked on a non-status-type object");
    return CanonicalCode(status, extended_api_type());
  }
};

}  // namespace status_internal
}  // namespace asylo

#endif  // ASYLO_UTIL_STATUS_INTERNAL_H_
