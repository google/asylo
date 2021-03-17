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

#ifndef ASYLO_PLATFORM_PRIMITIVES_PRIMITIVE_STATUS_H_
#define ASYLO_PLATFORM_PRIMITIVES_PRIMITIVE_STATUS_H_

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <type_traits>

#include "absl/status/status.h"
#include "asylo/util/error_codes.h"  // IWYU pragma: export

namespace asylo {
namespace primitives {

// This file declares types shared between between trusted and untrusted code.
//
// Trusted and untrusted components may be built with different compilers and be
// linked against different implementations of the C++ runtime. In general,
// these versions are not binary compatible. For example:
//
// * Types with a virtual function table will be initialized differently
//   depending on where they were initialized, and an object passed to trusted
//   code from the untrusted application may try to invoke a untrusted code when
//   a virtual method is called or visa-versa.
//
// * Types which do memory allocation in their destructor may attempt to free
//   themselves from the wrong heap.
//
// * Types which depend on the implementation of standard types like std::string
//   may have completely incompatible runtime representation.
//
// These requirements exist because enclave code is linked against our own
// custom C++ runtime. The are not related to SGX per se and hold even for the
// simulator and RPC implementations.

// Ensure common width for implementation-defined types.
static_assert(sizeof(size_t) == 8, "Unexpected size for type size_t");

/// This enum of error codes aliases `absl::StatusCode`. These aliases are
/// needed because these error codes may be used by low-level runtime components
/// which must compile without C++ runtime support. Abseil does not guarantee
/// that the file defining `absl::StatusCode` will be supported in such an
/// environment.
enum AbslStatusCode : int {
  kOk = 0,
  kCancelled = 1,
  kUnknown = 2,
  kInvalidArgument = 3,
  kDeadlineExceeded = 4,
  kNotFound = 5,
  kAlreadyExists = 6,
  kPermissionDenied = 7,
  kResourceExhausted = 8,
  kFailedPrecondition = 9,
  kAborted = 10,
  kOutOfRange = 11,
  kUnimplemented = 12,
  kInternal = 13,
  kUnavailable = 14,
  kDataLoss = 15,
  kUnauthenticated = 16,
};

/// \class PrimitiveStatus primitive_status.h @primitive_status
/// Shared representation of a status code across the enclave boundary.
///
/// PrimitiveStatus does not include an error space and always refers to a
/// google::GoogleError value.
class PrimitiveStatus {
 public:
  /// Maximum error string length in characters.
  static constexpr size_t kMessageMax = 1024;

  /// Builds an OK status.
  PrimitiveStatus() : PrimitiveStatus(AbslStatusCode::kOk) {}

  /// Builds a status with an error code and an empty message.
  ///
  /// \param code An error code that is interpreted as a google::GoogleError
  ///    value.
  explicit PrimitiveStatus(int code) : error_code_(code) { message_[0] = '\0'; }

  /// Builds a status with an error code and error message.
  ///
  /// \param code An error code that is interpreted as a google::GoogleError
  ///    value.
  /// \param message A message string that is truncated if longer than
  ///    `kMessageMax - 1` characters. The length is computed with strlen.
  PrimitiveStatus(int code, const char *message)
      : PrimitiveStatus(code, message, strlen(message)) {}

  /// Builds a status with an error code and a message of size `message_size`.
  ///
  /// \param code An error code that is interpreted as a google::GoogleError
  ///    value.
  /// \param message A message string that is truncated if longer than
  ///    `kMessageMax - 1` characters.
  /// \param message_size The size of the `message` to copy, which will not
  ///    exceed `kMessageMax - 1` characters.
  PrimitiveStatus(int code, const char *message, size_t message_size)
      : error_code_(code) {
    message_size = std::min(message_size, kMessageMax - 1);
    memcpy(message_, message, message_size);
    message_[message_size] = '\0';
  }

  /// Builds a status with an error code and a message in string format.
  PrimitiveStatus(int code, const std::string &message)
        : PrimitiveStatus(code, message.data(), message.length()) {}

  /// Copy constructor.
  ///
  /// \param other The status to copy. Strings are memcpy'd.
  PrimitiveStatus(const PrimitiveStatus &other)
        : PrimitiveStatus(other.error_code_, other.message_) {}

  PrimitiveStatus &operator=(const PrimitiveStatus &other) {
    error_code_ = other.error_code_;
    size_t size = std::min(strlen(other.message_), kMessageMax - 1);
    memcpy(message_, other.message_, size);
    message_[size] = '\0';
    return *this;
  }

  /// PrimitiveStatus::OkStatus() is the canonical name for an OK status.
  /// \returns An OK status object.
  static PrimitiveStatus OkStatus() { return PrimitiveStatus{}; }

  /// Getter for this object's error code.
  ///
  /// \returns The integer error code for this object.
  int error_code() const { return error_code_; }

  /// Getter for this object's error message.
  ///
  /// returns The string error message for this object.
  const char *error_message() const { return message_; }

  /// Predicate for non-error status.
  ///
  /// \returns True if and only if this object is OK (indicates no error).
  bool ok() const { return error_code_ == AbslStatusCode::kOk; }

 private:
  // This method is not intended to be called, it is defined only to provide a
  // scope where offsetof may be applied to private members and PrimitiveStatus
  // is a complete type.
  static void CheckLayout() {
    static_assert(std::is_standard_layout<PrimitiveStatus>::value,
                  "PrimitiveStatus must satisfy std::is_standard_layout");
    static_assert(offsetof(PrimitiveStatus, error_code_) == 0x0,
                  "Unexpected layout for field PrimitiveStatus::error_code_");
    static_assert(offsetof(PrimitiveStatus, message_) == sizeof(uint32_t),
                  "Unexpected layout for field PrimitiveStatus::message_");
  }

  int32_t error_code_;         // An error::GoogleError condition code.
  char message_[kMessageMax];  // An associated error string.
};

}  // namespace primitives
}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_PRIMITIVE_STATUS_H_
