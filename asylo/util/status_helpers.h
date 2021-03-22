/*
 * Copyright 2021 Asylo authors
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
 */

#ifndef ASYLO_UTIL_STATUS_HELPERS_H_
#define ASYLO_UTIL_STATUS_HELPERS_H_

#include <string>
#include <type_traits>

#include <google/protobuf/message.h>
#include "absl/strings/str_cat.h"
#include "asylo/util/status.h"
#include "asylo/util/status.pb.h"
#include "asylo/util/status_helpers_internal.h"

namespace asylo {

/// Converts a status-like object to another status type.
///
/// The source and target types must:
///
///   * Have a two-parameter constructor that takes an enum as its first
///     parameter and a string as its second parameter.
///   * Have non-static `const` `error_code()`, `error_message()`, and `ok()`
///     methods.
///
/// This function is provided for the convenience of Asylo-SDK consumers
/// utilizing other status types such as `::grpc::Status`.
///
/// Note that all statuses are converted to the canonical error space, so
/// additional error space information is lost.
///
/// Payloads are preserved if both input and output status types support them.
///
/// \param from_status A status-like object to copy.
/// \return A status-like object copied from `from_status`.
template <typename ToStatusT, typename FromStatusT>
ToStatusT ConvertStatus(const FromStatusT &from_status) {
  return internal::ConvertStatusImpl<ToStatusT, FromStatusT>::Convert(
      from_status);
}

/// Exports the contents of `status` into a `StatusProto`. This function sets
/// the `space` and `canonical_code` fields in `status_proto` even if `status`
/// is in the canonical error space.
///
/// \param status A `Status` to pack into a proto.
/// \return A `StatusProto` representing `status`.
StatusProto StatusToProto(const Status &status);

/// Returns a `Status` based on the contents of the given `status_proto`.
///
/// If the error space given by `status_proto.space()` is unrecognized, the
/// returned `Status` is in the canonical error space and has an error code
/// equal to `status_proto.canonical_code()`. If `status_proto` has no canonical
/// code, the returned `Status` has an error code of
/// `error::GoogleError::UNKNOWN`. Note that the error message is only set if
/// `status_proto` represents a non-OK status.
///
/// If the given `status_proto` is invalid, the error code of the returned
/// `Status` is `error::StatusError::INVALID_STATUS_PROTO`. A `StatusProto` is
/// valid if and only if all the following conditions hold:
///
///   * If `code()` is 0, then `canonical_code()` is set to 0.
///   * If `canonical_code()` is 0, then `code()` is set to 0.
///   * If the error space is recognized, then `canonical_code()` is equal to
///     the equivalent canonical code given by the error space.
///
/// \param status_proto A protobuf object to unpack.
/// \return A `Status` based on the contents of `status_proto`.
Status StatusFromProto(const StatusProto &status_proto);

/// Returns the type URL associated with a given protobuf message type. This
/// should be used when embedding a message of that type as a payload in a
/// `Status`.
///
/// \return The type URL to use for `MessageT` payloads.
template <typename MessageT>
std::string GetTypeUrl() {
  static_assert(std::is_base_of<google::protobuf::Message, MessageT>::value,
                "MessageT must be a protobuf message type");
  return absl::StrCat("type.googleapis.com/",
                      MessageT::GetDescriptor()->full_name());
}

}  // namespace asylo

#endif  // ASYLO_UTIL_STATUS_HELPERS_H_
