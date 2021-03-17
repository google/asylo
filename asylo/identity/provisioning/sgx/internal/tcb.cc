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

#include "asylo/identity/provisioning/sgx/internal/tcb.h"

#include <endian.h>

#include <cstdint>

#include "google/protobuf/timestamp.pb.h"
#include <google/protobuf/util/message_differencer.h>
#include <google/protobuf/util/time_util.h>
#include "absl/base/attributes.h"
#include "absl/container/flat_hash_map.h"
#include "absl/hash/hash.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/identity/provisioning/sgx/internal/container_util.h"
#include "asylo/identity/provisioning/sgx/internal/platform_provisioning.h"
#include "asylo/util/hex_util.h"
#include "asylo/util/proto_enum_util.h"
#include "asylo/util/status_macros.h"

namespace asylo {
namespace sgx {

const size_t kPcesvnSize = 2;
const size_t kRawTcbSize = kCpusvnSize + kPcesvnSize;

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
  return PartialOrder::kIncomparable;
}

// Returns an error indicating that |tcb_info_version| is an unknown TCB info
// version.
Status UnknownTcbInfoVersionError(int tcb_info_version) {
  return absl::InvalidArgumentError(
      absl::StrCat("Unknown TCB info version: ", tcb_info_version));
}

// Returns an error indicating the TCB info version |tcb_info_version| does not
// support messages of type |message_name| satisfying |error_predicate|. The
// |error_predicate| should start with a verb (e.g. "is too long", "has too many
// \"repeated_field_elements\"").
Status WrongTcbInfoVersionError(absl::string_view message_name,
                                int tcb_info_version,
                                absl::string_view error_predicate) {
  return absl::InvalidArgumentError(
      absl::StrFormat("%s is for TCB info version %d but %s", message_name,
                      tcb_info_version, error_predicate));
}

// Validates a google.protobuf.Timestamp message. Returns an OK status if and
// only if the message is valid.
//
// A google.protobuf.Timestamp message is valid according to the documentation
// in timestamp.proto.
Status ValidateTimestamp(const google::protobuf::Timestamp &timestamp) {
  if (timestamp.seconds() < google::protobuf::util::TimeUtil::kTimestampMinSeconds ||
      timestamp.seconds() > google::protobuf::util::TimeUtil::kTimestampMaxSeconds) {
    return absl::InvalidArgumentError(absl::StrCat(
        "Timestamp's \"seconds\" field must be between ",
        google::protobuf::util::TimeUtil::kTimestampMinSeconds, " and ",
        google::protobuf::util::TimeUtil::kTimestampMaxSeconds, " (inclusive)"));
  }

  if (timestamp.nanos() < 0 || timestamp.nanos() > 999999999) {
    return absl::InvalidArgumentError(
        "Timestamp's \"nanos\" field must be between 0 and "
        "999999999 (inclusive)");
  }

  return absl::OkStatus();
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
    return absl::InvalidArgumentError(
        "TcbStatus has an empty \"value\" variant");
  }

  if (tcb_status.value_case() == TcbStatus::kKnownStatus &&
      tcb_status.known_status() == TcbStatus::INVALID) {
    return absl::InvalidArgumentError(
        "TcbStatus has an unknown \"known_status\"");
  }

  return absl::OkStatus();
}

// Validates a TcbLevel message under |tcb_info_version|. Returns an OK status
// if and only if the message is valid.
//
// A TcbLevel message is valid if and only if
//
//   * The |tcb| and |status| fields are set.
//   * If the |tcb_info_version| is 1, then the |tcb_date| field is unset and
//     the |advisority_ids| field is empty.
//   * If the |tcb_info_version| is 2, then the |tcb_date| field is set.
//   * Each set field is valid according to its respective validator.
Status ValidateTcbLevel(const TcbLevel &tcb_level, int tcb_info_version) {
  if (!tcb_level.has_tcb()) {
    return absl::InvalidArgumentError("TcbLevel does not have a \"tcb\" field");
  }

  if (!tcb_level.has_status()) {
    return absl::InvalidArgumentError(
        "TcbLevel does not have a \"status\" field");
  }

  ASYLO_RETURN_IF_ERROR(ValidateTcb(tcb_level.tcb()));
  ASYLO_RETURN_IF_ERROR(ValidateTcbStatus(tcb_level.status()));

  switch (tcb_info_version) {
    case 1:
      if (tcb_level.has_tcb_date()) {
        return WrongTcbInfoVersionError("TcbLevel", tcb_info_version,
                                        "has a \"tcb_date\" field");
      }
      if (!tcb_level.advisory_ids().empty()) {
        return WrongTcbInfoVersionError(
            "TcbLevel", tcb_info_version,
            "has a non-empty \"advisory_ids\" field");
      }
      break;
    case 2:
      if (!tcb_level.has_tcb_date()) {
        return WrongTcbInfoVersionError("TcbLevel", tcb_info_version,
                                        "does not have a \"tcb_date\" field");
      }
      break;
    default:
      return UnknownTcbInfoVersionError(tcb_info_version);
  }

  return absl::OkStatus();
}

// Validates a TcbInfoImpl message with a |version| of 1 or 2. Returns an OK
// status if and only if the message is valid.
//
// A TcbInfoImpl message with a |version| of 1 or 2 is valid if and only if:
//
//   * Its |issue_date|, |next_update|, |fmspc|, and |pce_id| fields are set.
//   * Its |tcb_type| and |tcb_evaluation_data_number| fields are set if and
//     only if its |version| is 2.
//   * Each of the set fields is valid according its type's validator.
//   * Each element of |tcb_levels| is valid according to ValidateTcbLevel()
//     under |version|.
//   * The |issue_date| is before the |next_update|.
Status ValidateTcbInfoImplV1andV2(const TcbInfoImpl &tcb_info_impl) {
  if (!tcb_info_impl.has_issue_date()) {
    return absl::InvalidArgumentError(
        "TcbInfoImpl does not have a \"issue_date\" field");
  }

  if (!tcb_info_impl.has_next_update()) {
    return absl::InvalidArgumentError(
        "TcbInfoImpl does not have a \"next_update\" field");
  }

  if (!tcb_info_impl.has_fmspc()) {
    return absl::InvalidArgumentError(
        "TcbInfoImpl does not have a \"fmspc\" field");
  }

  if (!tcb_info_impl.has_pce_id()) {
    return absl::InvalidArgumentError(
        "TcbInfoImpl does not have a \"pce_id\" field");
  }

  ASYLO_RETURN_IF_ERROR(ValidateTimestamp(tcb_info_impl.issue_date()));
  ASYLO_RETURN_IF_ERROR(ValidateTimestamp(tcb_info_impl.next_update()));

  if (tcb_info_impl.issue_date() >= tcb_info_impl.next_update()) {
    return absl::InvalidArgumentError(
        "TcbInfoImpl's \"next_update\" is not after its \"issue_date\"");
  }

  ASYLO_RETURN_IF_ERROR(ValidateFmspc(tcb_info_impl.fmspc()));
  ASYLO_RETURN_IF_ERROR(ValidatePceId(tcb_info_impl.pce_id()));

  switch (tcb_info_impl.version()) {
    case 1:
      if (tcb_info_impl.has_tcb_type()) {
        return WrongTcbInfoVersionError("TcbInfoImpl", tcb_info_impl.version(),
                                        "has a \"tcb_type\" field");
      }
      if (tcb_info_impl.has_tcb_evaluation_data_number()) {
        return WrongTcbInfoVersionError(
            "TcbInfoImpl", tcb_info_impl.version(),
            "has a \"tcb_evaluation_data_number\" field");
      }
      break;
    case 2:
      if (!tcb_info_impl.has_tcb_type()) {
        return WrongTcbInfoVersionError("TcbInfoImpl", tcb_info_impl.version(),
                                        "does not have a \"tcb_type\" field");
      }
      if (!TcbType_IsValid(tcb_info_impl.tcb_type()) ||
          tcb_info_impl.tcb_type() == TcbType::TCB_TYPE_UNKNOWN) {
        return absl::InvalidArgumentError(
            absl::StrCat("Unknown TCB type: ",
                         ProtoEnumValueName(tcb_info_impl.tcb_type())));
      }
      if (!tcb_info_impl.has_tcb_evaluation_data_number()) {
        return WrongTcbInfoVersionError(
            "TcbInfoImpl", tcb_info_impl.version(),
            "does not have a \"tcb_evaluation_data_number\" field");
      }
      break;
    default:
      return UnknownTcbInfoVersionError(tcb_info_impl.version());
  }

  absl::flat_hash_map<Tcb, TcbStatus, absl::Hash<Tcb>, MessageEqual>
      tcb_to_status_map;
  for (const TcbLevel &tcb_level : tcb_info_impl.tcb_levels()) {
    ASYLO_RETURN_IF_ERROR(ValidateTcbLevel(tcb_level, tcb_info_impl.version()));
    auto insert_pair =
        tcb_to_status_map.insert({tcb_level.tcb(), tcb_level.status()});
    if (!insert_pair.second &&
        !google::protobuf::util::MessageDifferencer::Equals(tcb_level.status(),
                                                  insert_pair.first->second)) {
      return absl::InvalidArgumentError(
          "TcbInfoImpl contains two entries with the same Tcb but different "
          "statuses");
    }
  }

  return absl::OkStatus();
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
    return absl::InvalidArgumentError(
        "TcbInfoImpl does not have a \"version\" field");
  }

  switch (tcb_info_impl.version()) {
    case 1:
    case 2:
      return ValidateTcbInfoImplV1andV2(tcb_info_impl);
    default:
      return absl::InvalidArgumentError(
          absl::StrCat("TcbInfoImpl has an unknown (Intel) version: ",
                       tcb_info_impl.version()));
  }
}

}  // namespace

Status ValidateTcb(const Tcb &tcb) {
  if (!tcb.has_components()) {
    return absl::InvalidArgumentError(
        "Tcb does not have a \"components\" field");
  }

  if (!tcb.has_pce_svn()) {
    return absl::InvalidArgumentError("Tcb does not have a \"pce_svn\" field");
  }

  if (tcb.components().size() != kTcbComponentsSize) {
    return absl::InvalidArgumentError(absl::StrCat(
        "Tcb's \"components\" field has an invalid size (must be exactly ",
        kTcbComponentsSize, " bytes)"));
  }

  return ValidatePceSvn(tcb.pce_svn());
}

Status ValidateRawTcb(const RawTcb &raw_tcb) {
  if (!raw_tcb.has_cpu_svn()) {
    return absl::InvalidArgumentError(
        "RawTcb does not have a \"cpu_svn\" field");
  }

  if (!raw_tcb.has_pce_svn()) {
    return absl::InvalidArgumentError(
        "RawTcb does not have a \"pce_svn\" field");
  }

  ASYLO_RETURN_IF_ERROR(ValidateCpuSvn(raw_tcb.cpu_svn()));
  ASYLO_RETURN_IF_ERROR(ValidatePceSvn(raw_tcb.pce_svn()));

  return absl::OkStatus();
}

Status ValidateTcbInfo(const TcbInfo &tcb_info) {
  if (tcb_info.value_case() != TcbInfo::kImpl) {
    return absl::InvalidArgumentError(
        "TcbInfo has an unknown \"value\" variant");
  }

  return ValidateTcbInfoImpl(tcb_info.impl());
}

StatusOr<PartialOrder> CompareTcbs(TcbType tcb_type, const Tcb &lhs,
                                   const Tcb &rhs) {
  ByteContainerView lhs_bytes(lhs.components());
  ByteContainerView rhs_bytes(rhs.components());
  PartialOrder current;
  switch (tcb_type) {
    case TcbType::TCB_TYPE_0:
      current = PartialOrder::kEqual;
      for (int i = 0; i < kTcbComponentsSize; ++i) {
        current =
            OrderCombine(current, CompareTotal(lhs_bytes[i], rhs_bytes[i]));
        if (current == PartialOrder::kIncomparable) {
          return PartialOrder::kIncomparable;
        }
      }
      return OrderCombine(
          current, CompareTotal(lhs.pce_svn().value(), rhs.pce_svn().value()));
    default:
      return Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Unknown TCB type: ", ProtoEnumValueName(tcb_type)));
  }
}

StatusOr<asylo::sgx::RawTcb> ParseRawTcbHex(absl::string_view raw_tcb_hex) {
  if (!IsHexEncoded(raw_tcb_hex)) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "Value is not a valid hex-encoded string");
  }
  std::string raw_tcb = absl::HexStringToBytes(raw_tcb_hex);
  if (raw_tcb.size() != kRawTcbSize) {
    return Status(absl::StatusCode::kInvalidArgument,
                  absl::StrCat("Value has invalid size: ", raw_tcb.size(),
                               " bytes (expected ", kRawTcbSize, " bytes)"));
  }
  RawTcb raw_tcb_proto;
  raw_tcb_proto.mutable_cpu_svn()->set_value(raw_tcb.data(), kCpusvnSize);
  const uint16_t pce_svn = le16toh(
      *reinterpret_cast<const uint16_t *>(&raw_tcb.data()[kCpusvnSize]));
  raw_tcb_proto.mutable_pce_svn()->set_value(pce_svn);
  return raw_tcb_proto;
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
          return Status(absl::StatusCode::kInvalidArgument,
                        "Unknown known status code");
      }
      break;
    case TcbStatus::kUnknownStatus:
      return status.unknown_status();
    default:
      return Status(absl::StatusCode::kInvalidArgument,
                    "Unknown TcbStatus variant");
  }
}

}  // namespace sgx
}  // namespace asylo
