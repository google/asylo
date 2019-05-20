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

#include "asylo/identity/sgx/tcb.h"

#include <cstdint>

#include "google/protobuf/timestamp.pb.h"
#include <google/protobuf/util/time_util.h>
#include "absl/strings/str_cat.h"
#include "asylo/identity/sgx/platform_provisioning.h"
#include "asylo/util/status_macros.h"

namespace asylo {
namespace sgx {
namespace {

// Validates a google.protobuf.Timestamp message. Returns an OK status if and
// only if the message is valid.
//
// A google.protobuf.Timestamp message is valid according to the documentation
// in timestamp.proto.
Status ValidateTimestamp(const google::protobuf::Timestamp &timestamp) {
  if (timestamp.seconds() < google::protobuf::util::TimeUtil::kTimestampMinSeconds ||
      timestamp.seconds() > google::protobuf::util::TimeUtil::kTimestampMaxSeconds) {
    return Status(
        error::GoogleError::INVALID_ARGUMENT,
        absl::StrCat("Timestamp's \"seconds\" field must be between ",
                     google::protobuf::util::TimeUtil::kTimestampMinSeconds, " and ",
                     google::protobuf::util::TimeUtil::kTimestampMaxSeconds,
                     " (inclusive)"));
  }

  if (timestamp.nanos() < 0 || timestamp.nanos() > 999999999) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "Timestamp's \"nanos\" field must be between 0 and "
                  "999999999 (inclusive)");
  }

  return Status::OkStatus();
}

// Validates a TcbStatus message. Returns an OK status if and only if the
// message is valid.
//
// A TcbStatus message is valid if and only if its |value| field is set except
// when the |known_status| variant is set and equal to INVALID.
//
// A TcbStatus message is NOT considered invalid if it has an |unknown_status|
// string that represents an existing StatusType value. This allows new cases to
// be added to TcbStatus.StatusType without invalidating old data.
Status ValidateTcbStatus(const TcbStatus &tcb_status) {
  if (tcb_status.value_case() == TcbStatus::VALUE_NOT_SET) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "TcbStatus has an empty \"value\" variant");
  }

  if (tcb_status.value_case() == TcbStatus::kKnownStatus &&
      tcb_status.known_status() == TcbStatus::INVALID) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "TcbStatus has an unknown \"known_status\"");
  }

  return Status::OkStatus();
}

// Validates a TcbLevel message. Returns an OK status if and only if the
// message is valid.
//
// A TcbLevel message is valid if and only if its |tcb| and |status| fields are
// set and each is valid according to its respective validator.
Status ValidateTcbLevel(const TcbLevel &tcb_level) {
  if (!tcb_level.has_tcb()) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "TcbLevel does not have a \"tcb\" field");
  }

  if (!tcb_level.has_status()) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "TcbLevel does not have a \"status\" field");
  }

  ASYLO_RETURN_IF_ERROR(ValidateTcb(tcb_level.tcb()));
  ASYLO_RETURN_IF_ERROR(ValidateTcbStatus(tcb_level.status()));

  return Status::OkStatus();
}

// Validates a TcbInfoImpl message with a |version| of 1. Returns an OK status
// if and only if the message is valid.
//
// A TcbInfoImpl message with a |version| of 1 is valid if and only if:
//
//   * Its |issue_date|, |next_update|, |fmspc|, and |pce_id| fields are set.
//   * Each of those fields is valid according its type's validator.
//   * Each element of |tcb_levels| is valid according to ValidateTcbLevel().
//   * The |issue_date| is before the |next_update|.
Status ValidateTcbInfoImplV1(const TcbInfoImpl &tcb_info_impl) {
  if (!tcb_info_impl.has_issue_date()) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "TcbInfoImpl does not have a \"issue_date\" field");
  }

  if (!tcb_info_impl.has_next_update()) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "TcbInfoImpl does not have a \"next_update\" field");
  }

  if (!tcb_info_impl.has_fmspc()) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "TcbInfoImpl does not have a \"fmspc\" field");
  }

  if (!tcb_info_impl.has_pce_id()) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "TcbInfoImpl does not have a \"pce_id\" field");
  }

  ASYLO_RETURN_IF_ERROR(ValidateTimestamp(tcb_info_impl.issue_date()));
  ASYLO_RETURN_IF_ERROR(ValidateTimestamp(tcb_info_impl.next_update()));

  if (tcb_info_impl.issue_date() >= tcb_info_impl.next_update()) {
    return Status(
        error::GoogleError::INVALID_ARGUMENT,
        "TcbInfoImpl's \"next_update\" is not after its \"issue_date\"");
  }

  ASYLO_RETURN_IF_ERROR(ValidateFmspc(tcb_info_impl.fmspc()));
  ASYLO_RETURN_IF_ERROR(ValidatePceId(tcb_info_impl.pce_id()));

  for (const TcbLevel &tcb_level : tcb_info_impl.tcb_levels()) {
    ASYLO_RETURN_IF_ERROR(ValidateTcbLevel(tcb_level));
  }

  return Status::OkStatus();
}

// Validates a TcbInfoImpl message. Returns an OK status if and only if the
// message is valid.
//
// A TcbInfoImpl message is valid if and only if:
//
//   * Its |version| field is set to a recognized value.
//   * The rest of the message is valid according to the validator corresponding
//     to the message's |version|.
Status ValidateTcbInfoImpl(const TcbInfoImpl &tcb_info_impl) {
  if (!tcb_info_impl.has_version()) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "TcbInfoImpl does not have a \"version\" field");
  }

  switch (tcb_info_impl.version()) {
    case 1:
      return ValidateTcbInfoImplV1(tcb_info_impl);
    default:
      return Status(error::GoogleError::INVALID_ARGUMENT,
                    absl::StrCat("TcbInfoImpl has an unknown (Intel) version: ",
                                 tcb_info_impl.version()));
  }
}

}  // namespace

const int kTcbComponentsSize = 16;

Status ValidateTcb(const Tcb &tcb) {
  if (!tcb.has_components()) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "Tcb does not have a \"components\" field");
  }

  if (!tcb.has_pce_svn()) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "Tcb does not have a \"pce_svn\" field");
  }

  if (tcb.components().size() != kTcbComponentsSize) {
    return Status(
        error::GoogleError::INVALID_ARGUMENT,
        absl::StrCat(
            "Tcb's \"components\" field has an invalid size (must be exactly ",
            kTcbComponentsSize, " bytes)"));
  }

  return ValidatePceSvn(tcb.pce_svn());

  return Status::OkStatus();
}

Status ValidateRawTcb(const RawTcb &raw_tcb) {
  if (!raw_tcb.has_cpu_svn()) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "RawTcb does not have a \"cpu_svn\" field");
  }

  if (!raw_tcb.has_pce_svn()) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "RawTcb does not have a \"pce_svn\" field");
  }

  ASYLO_RETURN_IF_ERROR(ValidateCpuSvn(raw_tcb.cpu_svn()));
  ASYLO_RETURN_IF_ERROR(ValidatePceSvn(raw_tcb.pce_svn()));

  return Status::OkStatus();
}

Status ValidateTcbInfo(const TcbInfo &tcb_info) {
  if (tcb_info.value_case() != TcbInfo::kImpl) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "TcbInfo has an unknown \"value\" variant");
  }

  return ValidateTcbInfoImpl(tcb_info.impl());
}

}  // namespace sgx
}  // namespace asylo
