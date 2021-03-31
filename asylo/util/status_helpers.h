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

#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "asylo/util/status.h"
#include "asylo/util/status.pb.h"
#include "asylo/util/status_helpers_internal.h"
#include "asylo/util/statusor.h"

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
/// `absl::StatusCode::kUnknown`. Note that the error message is only set if
/// `status_proto` represents a non-OK status.
///
/// If the given `status_proto` is invalid, then the returned `Status` has an
/// appropriate error code and message. A `StatusProto` is valid if and only if
/// all the following conditions hold:
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
  return internal::ProtoPayloadImpl<MessageT>::GetTypeUrl();
}

/// Gets the payload of type `MessageT` in `status`. `MessageT` must be a
/// protobuf message type.
///
/// The `status` argument may be either an Asylo `Status` or an `absl::Status`.
///
/// \param status The status to find the payload in.
/// \return The payload of type `MessageT` in `status`, or `absl::nullopt` if
///         `status` contains no payload of the given type. Also returns
///         `absl::nullopt` if there was a parsing error.
template <typename MessageT, typename StatusT = Status>
absl::optional<MessageT> GetProtoPayload(const StatusT &status) {
  return internal::ProtoPayloadImpl<MessageT, StatusT>::GetPayload(status);
}

/// Adds a payload of type `MessageT` to `status`. `MessageT` must be a protobuf
/// message type. Note that a `Status` can only have one payload of any given
/// message type.
///
/// The message is embedded with the same type URL that would be used to pack
/// the message into a `google::protobuf::Any`.
///
/// The `status` argument may be either an Asylo `Status` or an `absl::Status`.
///
/// \param message A protobuf message object.
/// \param[in,out] status The status to add the payload to.
template <typename MessageT, typename StatusT = Status>
void SetProtoPayload(const MessageT &message, StatusT &status) {
  internal::ProtoPayloadImpl<MessageT, StatusT>::SetPayload(message, status);
}

/// Returns the `Status` with the provided context prepended to its error
/// message. Returns `OkStatus()` if the given `Status` is OK.
///
/// \param status A `Status` to add context to.
/// \param context Additional context to add to the `Status`.
/// \return `status` with `context` prepended, along with an appropriate
///         separator.
Status WithContext(const Status &status, absl::string_view context);

/// As the `Status` overload above, but for `StatusOr<T>`.
///
/// \param status A `StatusOr<T>` to add context to, if it is not OK.
/// \param context Additional context to add to the `Status`.
/// \return `status_or` if it is OK, otherwise `status_or.status()` with
///         `context` prepended to the error message.
template <typename T>
StatusOr<T> WithContext(StatusOr<T> status_or, absl::string_view context) {
  if (status_or.ok()) {
    return status_or;
  }
  return WithContext(status_or.status(), context);
}

/// As the `StatusOr<T>` overload above, but for `absl::StatusOr<T>`.
///
/// \param status An `absl::StatusOr<T>` to add context to, if it is not OK.
/// \param context Additional context to add to the `absl::Status`.
/// \return `status_or` if it is OK, otherwise `status_or.status()` with
///         `context` prepended to the error message.
template <typename T>
absl::StatusOr<T> WithContext(absl::StatusOr<T> status_or,
                              absl::string_view context) {
  if (status_or.ok()) {
    return status_or;
  }
  return WithContext(status_or.status(), context);
}

}  // namespace asylo

#endif  // ASYLO_UTIL_STATUS_HELPERS_H_
