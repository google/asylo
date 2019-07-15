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
#include <google/protobuf/util/message_differencer.h>
#include <google/protobuf/util/time_util.h>
#include "absl/container/flat_hash_map.h"
#include "absl/strings/str_cat.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/identity/sgx/platform_provisioning.h"
#include "asylo/util/status_macros.h"

namespace asylo {
namespace sgx {
namespace {

// Compares two objects of type T, which must have <, ==, and > operators.
// Should only be used with types where exactly one of:
//
//   * x < y
//   * x == y
//   * x > y
//
// Is true for any given |x| and |y| of type T.
template <typename T>
PartialOrder CompareTotal(const T &lhs, const T &rhs) {
  if (lhs < rhs) {
    return PartialOrder::kLess;
  } else if (lhs == rhs) {
    return PartialOrder::kEqual;
  } else {
    return PartialOrder::kGreater;
  }
}

// Returns the order between two pairs in a product ordering, assuming that
// |lhs| and |rhs| represent the orders between the pairs' first elements and
// their second elements, respectively.
//
// That is, let |lhs| be the order between A and B and |rhs| be the order
// between C and D. Then OrderCombine(lhs, rhs) returns the order between the
// pairs (A, C) and (B, D) in the product ordering.
//
// Put another way, consider a PartialOrder as representing a combination of two
// bools: an is_less_than_or_equal_to bool and an is_greater_than_or_equal_to
// bool. The OrderCombine() of two PartialOrders is a PartialOrder each of whose
// component bools is the logical-and of the same bool in the original
// PartialOrders.
//
// This represents the semantics described above because (A, C) is less than or
// equal to (B, D) if and only if:
//
//     A <= B && C <= D
//
// And similarly for greater-than-or-equal-to.
//
// The result of the function is shown in the following table:
//
// OrderCombine()|    kLess    |   kEqual    |  kGreater   |kIncomparable
// --------------+-------------------------------------------------------
// kLess         |    kLess    |    kLess    |kIncomparable|kIncomparable
// kEqual        |    kLess    |   kEqual    |  kGreater   |kIncomparable
// kGreater      |kIncomparable|  kGreater   |  kGreater   |kIncomparable
// kIncomparable |kIncomparable|kIncomparable|kIncomparable|kIncomparable
//
// For more information on the product ordering, see:
// https://en.wikipedia.org/wiki/Product_order.
PartialOrder OrderCombine(PartialOrder lhs, PartialOrder rhs) {
  switch (lhs) {
    case PartialOrder::kLess:
      return rhs == PartialOrder::kLess || rhs == PartialOrder::kEqual
                 ? PartialOrder::kLess
                 : PartialOrder::kIncomparable;
    case PartialOrder::kEqual:
      return rhs;
    case PartialOrder::kGreater:
      return rhs == PartialOrder::kEqual || rhs == PartialOrder::kGreater
                 ? PartialOrder::kGreater
                 : PartialOrder::kIncomparable;
    case PartialOrder::kIncomparable:
      return PartialOrder::kIncomparable;
  }
  // GCC 4.9 requires this unreachable return statement.
  return PartialOrder::kIncomparable;
}

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

  absl::flat_hash_map<std::string, TcbStatus> tcb_to_status_map;
  for (const TcbLevel &tcb_level : tcb_info_impl.tcb_levels()) {
    ASYLO_RETURN_IF_ERROR(ValidateTcbLevel(tcb_level));
    std::string map_key = absl::StrCat(tcb_level.tcb().components(),
                                       tcb_level.tcb().pce_svn().value());
    auto insert_pair = tcb_to_status_map.insert({map_key, tcb_level.status()});
    if (!insert_pair.second &&
        !google::protobuf::util::MessageDifferencer::Equals(tcb_level.status(),
                                                  insert_pair.first->second)) {
      return Status(
          error::GoogleError::INVALID_ARGUMENT,
          "TcbInfoImpl contains two entries with the same Tcb but different "
          "statuses");
    }
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

PartialOrder CompareTcbs(const Tcb &lhs, const Tcb &rhs) {
  ByteContainerView lhs_bytes(lhs.components());
  ByteContainerView rhs_bytes(rhs.components());
  PartialOrder current = PartialOrder::kEqual;
  for (int i = 0; i < kTcbComponentsSize; ++i) {
    current = OrderCombine(current, CompareTotal(lhs_bytes[i], rhs_bytes[i]));
    if (current == PartialOrder::kIncomparable) {
      return PartialOrder::kIncomparable;
    }
  }
  return OrderCombine(
      current, CompareTotal(lhs.pce_svn().value(), rhs.pce_svn().value()));
}

StatusOr<std::string> TcbStatusToString(const TcbStatus &status) {
  switch (status.value_case()) {
    case TcbStatus::kKnownStatus:
      switch (status.known_status()) {
        case TcbStatus::UP_TO_DATE:
          return "UpToDate";
        case TcbStatus::CONFIGURATION_NEEDED:
          return "ConfigurationNeeded";
        case TcbStatus::OUT_OF_DATE:
          return "OutOfDate";
        case TcbStatus::REVOKED:
          return "Revoked";
        default:
          return Status(error::GoogleError::INVALID_ARGUMENT,
                        "Unknown known status code");
      }
      break;
    case TcbStatus::kUnknownStatus:
      return status.unknown_status();
    default:
      return Status(error::GoogleError::INVALID_ARGUMENT,
                    "Unknown TcbStatus variant");
  }
}

}  // namespace sgx
}  // namespace asylo
