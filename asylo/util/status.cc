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

#include "asylo/util/status.h"

#include <functional>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/strings/cord.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "asylo/util/status_error_space.h"

namespace asylo {

#ifdef NDEBUG
constexpr char kMovedByConstructorErrorMsg[] = "";
constexpr char kMovedByAssignmentErrorMsg[] = "";
constexpr char kStatusProtoErrorSpaceMsg[] = "";
constexpr char kStatusProtoOkMismatchMsg[] = "";
#else
constexpr char kMovedByConstructorErrorMsg[] =
    "Invalidated by move-constructor";
constexpr char kMovedByAssignmentErrorMsg[] = "Invalidated by move-assignment";
constexpr char kStatusProtoErrorSpaceMsg[] =
    "ErrorSpace canonical code mismatch";
constexpr char kStatusProtoOkMismatchMsg[] =
    "The ErrorSpace error_code equivalent of GoogleError::OK should be zero";
#endif

Status::Status()
    : error_space_(
          error::error_enum_traits<error::GoogleError>::get_error_space()),
      error_code_(error::GoogleError::OK) {}

Status::Status(const error::ErrorSpace *space, int code,
               absl::string_view message)
    : error_space_(space), error_code_(code) {
  if (code != 0) {
    message_ = std::string(message);
  }
}

Status::Status(Status &&other)
    : error_space_(other.error_space_),
      error_code_(other.error_code_),
      message_(std::move(other.message_)),
      payloads_(std::move(other.payloads_)) {
  other.Set(error::StatusError::MOVED, kMovedByConstructorErrorMsg);
}

Status::Status(const absl::Status &other) {
  Set(other.code(), other.message());
  other.ForEachPayload(
      [this](absl::string_view type_url, const absl::Cord &payload) {
        SetPayload(type_url, payload);
      });
}

Status &Status::operator=(Status &&other) {
  error_space_ = other.error_space_;
  error_code_ = other.error_code_;
  message_ = std::move(other.message_);
  payloads_ = std::move(other.payloads_);
  other.Set(error::StatusError::MOVED, kMovedByAssignmentErrorMsg);
  return *this;
}

Status Status::OkStatus() { return Status(); }

Status::operator ::absl::Status() const {
  absl::Status status(code(), message());
  for (const auto &it : payloads_) {
    status.SetPayload(it.first, it.second);
  }
  return status;
}

int Status::error_code() const { return raw_code(); }

int Status::raw_code() const { return error_code_; }

absl::string_view Status::error_message() const { return message(); }

absl::string_view Status::message() const { return message_; }

const error::ErrorSpace *Status::error_space() const { return error_space_; }

bool Status::ok() const { return error_code_ == 0; }

std::string Status::ToString() const {
  if (ok()) {
    return error_space_->String(error_code_);
  }

  std::string status_string = ToStringWithoutPayloads();
  for (const auto &it : payloads_) {
    absl::StrAppend(&status_string,
                    absl::StrFormat(" [%s='%s']", it.first,
                                    absl::CHexEscape(std::string(it.second))));
  }
  return status_string;
}

Status Status::ToCanonical() const {
  // Allow at most one layer of error-code translation.
  if (IsCanonical()) {
    return *this;
  }
  Status canonical(code(), ToStringWithoutPayloads());
  canonical.payloads_ = payloads_;
  return canonical;
}

error::GoogleError Status::CanonicalCode() const {
  return error_space_->GoogleErrorCode(error_code_);
}

absl::StatusCode Status::code() const {
  return static_cast<absl::StatusCode>(CanonicalCode());
}

void Status::SaveTo(StatusProto *status_proto) const {
  status_proto->Clear();
  status_proto->set_code(error_code_);
  status_proto->set_error_message(message_);
  status_proto->set_space(error_space_->SpaceName());
  status_proto->set_canonical_code(static_cast<int>(code()));
  for (const auto &it : payloads_) {
    (*status_proto->mutable_payloads())[it.first] = std::string(it.second);
  }
}

void Status::RestoreFrom(const StatusProto &status_proto) {
  payloads_.clear();
  // Set the error code from the error space, if recognized.
  error_space_ = error::ErrorSpace::Find(status_proto.space());
  if (error_space_) {
    // The canonical code must match the canonical code as computed by the
    // error space.
    if (status_proto.has_canonical_code() &&
        (error_space_->GoogleErrorCode(status_proto.code()) !=
         status_proto.canonical_code())) {
      Set(error::StatusError::RESTORE_ERROR, kStatusProtoErrorSpaceMsg);
      return;
    } else {
      error_code_ = status_proto.code();
    }
  } else {
    // Error space lookup failed. Use the canonical error space.
    error_space_ =
        error::error_enum_traits<error::GoogleError>::get_error_space();

    // Both error code and canonical code must be OK, or neither.
    if (status_proto.has_canonical_code() &&
        ((status_proto.code() == 0) != (status_proto.canonical_code() == 0))) {
      Set(error::StatusError::RESTORE_ERROR, kStatusProtoOkMismatchMsg);
      return;
    }
    if (status_proto.has_canonical_code()) {
      error_code_ = status_proto.canonical_code();
    } else {
      // Default to error::GoogleError::UNKNOWN.
      error_code_ = error::GoogleError::UNKNOWN;
    }
  }
  if (error_code_ != 0) {
    message_ = status_proto.error_message();
    for (const auto &it : status_proto.payloads()) {
      payloads_[it.first] = it.second;
    }
  } else {
    message_.clear();
  }
}

Status Status::WithPrependedContext(absl::string_view context) {
  message_ = absl::StrCat(context, ": ", message_);
  return *this;
}

absl::optional<absl::Cord> Status::GetPayload(
    absl::string_view type_url) const {
  auto it = payloads_.find(type_url);
  if (it == payloads_.end()) {
    return absl::nullopt;
  }
  return it->second;
}

void Status::SetPayload(absl::string_view type_url, absl::Cord payload) {
  if (ok()) {
    return;
  }
  payloads_[type_url] = std::move(payload);
}

bool Status::ErasePayload(absl::string_view type_url) {
  return payloads_.erase(type_url) > 0;
}

void Status::ForEachPayload(
    const std::function<void(absl::string_view, const absl::Cord &)> &visitor)
    const {
  for (const auto &it : payloads_) {
    visitor(it.first, it.second);
  }
}

bool Status::IsCanonical() const {
  return error_space_->SpaceName() == error::kCanonicalErrorSpaceName;
}

std::string Status::ToStringWithoutPayloads() const {
  return absl::StrCat(error_space_->SpaceName(),
                      "::", error_space_->String(error_code_), ": ", message_);
}

bool operator==(const Status &lhs, const Status &rhs) {
  return (lhs.raw_code() == rhs.raw_code()) &&
         (lhs.message() == rhs.message()) &&
         (lhs.error_space() == rhs.error_space()) &&
         (lhs.payloads_ == rhs.payloads_);
}

bool operator!=(const Status &lhs, const Status &rhs) { return !(lhs == rhs); }

bool operator==(const Status &lhs, const absl::Status &rhs) {
  return lhs == Status(rhs);
}

bool operator!=(const Status &lhs, const absl::Status &rhs) {
  return lhs != Status(rhs);
}

bool operator==(const absl::Status &lhs, const Status &rhs) {
  return Status(lhs) == rhs;
}

bool operator!=(const absl::Status &lhs, const Status &rhs) {
  return Status(lhs) != rhs;
}

std::ostream &operator<<(std::ostream &os, const Status &status) {
  return os << status.ToString();
}

Status OkStatus() { return Status(); }

}  // namespace asylo
