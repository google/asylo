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

#include "asylo/identity/sgx/tcb_info_from_json.h"

#include <endian.h>

#include <cstdint>
#include <limits>
#include <memory>
#include <string>
#include <utility>

#include "google/protobuf/struct.pb.h"
#include "google/protobuf/timestamp.pb.h"
#include <google/protobuf/repeated_field.h>
#include <google/protobuf/util/json_util.h>
#include <google/protobuf/util/message_differencer.h>
#include <google/protobuf/util/time_util.h>
#include "absl/base/call_once.h"
#include "absl/container/flat_hash_map.h"
#include "absl/strings/ascii.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/time/civil_time.h"
#include "absl/time/time.h"
#include "asylo/util/logging.h"
#include "asylo/identity/sgx/platform_provisioning.h"
#include "asylo/identity/sgx/platform_provisioning.pb.h"
#include "asylo/identity/sgx/tcb.h"
#include "asylo/identity/sgx/tcb.pb.h"
#include "asylo/identity/sgx/tcb_container_util.h"
#include "asylo/util/hex_util.h"
#include "asylo/util/proto_struct_util.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"

namespace asylo {
namespace sgx {
namespace {

// Parses an ISO 8601 time string from |time_string|.
StatusOr<absl::Time> ParseIso8601TimeString(const std::string &time_string) {
  absl::Time time;
  std::string error;
  if (!absl::ParseTime("%Y-%m-%dT%H:%M:%SZ", time_string, &time, &error)) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  absl::StrCat("Could not parse time string: ", error));
  }

  return time;
}

// Returns true if |time| can be represented by a valid
// google.protobuf.Timestamp and false otherwise.
bool CanBeTimestampProto(absl::Time time) {
  const absl::TimeZone utc = absl::UTCTimeZone();
  const absl::Time timestamp_proto_minimum =
      absl::FromCivil(absl::CivilSecond(1, 1, 1, 0, 0, 0), utc);
  const absl::Time timestamp_proto_maximum =
      absl::FromCivil(absl::CivilSecond(9999, 12, 31, 23, 59, 59), utc);
  return time >= timestamp_proto_minimum && time <= timestamp_proto_maximum;
}

// Returns a map from known Intel TCB status strings to TcbStatus.StatusType
// values.
const absl::flat_hash_map<std::string, TcbStatus::StatusType>
    &KnownStatusesMap() {
  static absl::once_flag once_init;
  static absl::flat_hash_map<std::string, TcbStatus::StatusType> *map = nullptr;

  absl::call_once(once_init, [] {
    map = new absl::flat_hash_map<std::string, TcbStatus::StatusType>({
        {"UpToDate", TcbStatus::UP_TO_DATE},
        {"OutOfDate", TcbStatus::OUT_OF_DATE},
        {"ConfigurationNeeded", TcbStatus::CONFIGURATION_NEEDED},
        {"Revoked", TcbStatus::REVOKED},
    });
  });
  return *map;
}

// Parses a valid SGX TCB component SVN from |component_json|.
StatusOr<int> SgxTcbComponentSvnFromJson(
    const google::protobuf::Value &component_json) {
  double component;
  ASYLO_ASSIGN_OR_RETURN(component, JsonGetNumber(component_json));
  if (component < 0. || component > 255.) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "An SGX TCB component SVN is out of bounds");
  }
  return component;
}

// Parses a valid PceSvn from |pce_svn_json|.
StatusOr<PceSvn> PceSvnFromJson(const google::protobuf::Value &pce_svn_json) {
  double pce_svn_raw;
  ASYLO_ASSIGN_OR_RETURN(pce_svn_raw, JsonGetNumber(pce_svn_json));
  if (pce_svn_raw < 0. || pce_svn_raw > kPceSvnMaxValue) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "pcesvn is out of bounds");
  }

  PceSvn pce_svn;
  pce_svn.set_value(pce_svn_raw);
  return pce_svn;
}

StatusOr<Tcb> TcbFromJsonValue(const google::protobuf::Value &json_value) {
  const google::protobuf::Struct *tcb_object;
  ASYLO_ASSIGN_OR_RETURN(tcb_object, JsonGetObject(json_value));

  Tcb tcb;

  tcb.set_components(std::string(kTcbComponentsSize, 0));
  for (int i = 0; i < kTcbComponentsSize; ++i) {
    const std::string field_name = absl::StrFormat("sgxtcbcomp%02dsvn", i + 1);
    const google::protobuf::Value *component_json;
    ASYLO_ASSIGN_OR_RETURN(component_json,
                           JsonObjectGetField(*tcb_object, field_name));
    ASYLO_ASSIGN_OR_RETURN((*tcb.mutable_components())[i],
                           SgxTcbComponentSvnFromJson(*component_json));
  }

  const google::protobuf::Value *pce_svn_json;
  ASYLO_ASSIGN_OR_RETURN(pce_svn_json,
                         JsonObjectGetField(*tcb_object, "pcesvn"));
  ASYLO_ASSIGN_OR_RETURN(*tcb.mutable_pce_svn(), PceSvnFromJson(*pce_svn_json));

  // Each TCB JSON object should have kTcbComponentsSize + 1 fields: one
  // "sgxtcbcomp##svn" for each number between 1 and kTcbComponentsSize, as well
  // as a "pcesvn" field.
  if (tcb_object->fields().size() > kTcbComponentsSize + 1) {
    std::string json_string;
    if (!google::protobuf::util::MessageToJsonString(json_value, &json_string).ok()) {
      json_string = "TCB JSON";
    }
    LOG(WARNING) << absl::StrCat("Encountered unrecognized fields in ",
                                 json_string);
  }

  return tcb;
}

// Parses a valid TcbStatus from |tcb_status_json|.
StatusOr<TcbStatus> TcbStatusFromJson(
    const google::protobuf::Value &tcb_status_json) {
  const std::string *status_string;
  ASYLO_ASSIGN_OR_RETURN(status_string, JsonGetString(tcb_status_json));
  TcbStatus status;
  if (KnownStatusesMap().contains(*status_string)) {
    status.set_known_status(KnownStatusesMap().at(*status_string));
  } else {
    status.set_unknown_status(*status_string);
  }
  return status;
}

// Parses a valid TcbLevel from |tcb_level_json|.
StatusOr<TcbLevel> TcbLevelFromJson(
    const google::protobuf::Value &tcb_level_json) {
  const google::protobuf::Struct *tcb_level_object;
  ASYLO_ASSIGN_OR_RETURN(tcb_level_object, JsonGetObject(tcb_level_json));
  TcbLevel tcb_level;

  const google::protobuf::Value *tcb_json;
  ASYLO_ASSIGN_OR_RETURN(tcb_json,
                         JsonObjectGetField(*tcb_level_object, "tcb"));
  ASYLO_ASSIGN_OR_RETURN(*tcb_level.mutable_tcb(), TcbFromJsonValue(*tcb_json));

  const google::protobuf::Value *status_json;
  ASYLO_ASSIGN_OR_RETURN(status_json,
                         JsonObjectGetField(*tcb_level_object, "status"));
  ASYLO_ASSIGN_OR_RETURN(*tcb_level.mutable_status(),
                         TcbStatusFromJson(*status_json));

  // Each TCB level JSON object should have two fields: "tcb" and "status".
  if (tcb_level_json.struct_value().fields().size() > 2) {
    std::string json_string;
    if (!google::protobuf::util::MessageToJsonString(tcb_level_json, &json_string).ok()) {
      json_string = "TCB level JSON";
    }
    LOG(WARNING) << absl::StrCat("Encountered unrecognized fields in ",
                                 json_string);
  }

  return tcb_level;
}

// Parses a valid Intel TCB info version number from |version_json|.
StatusOr<int> VersionFromJson(const google::protobuf::Value &version_json) {
  ASYLO_RETURN_IF_ERROR(JsonGetNumber(version_json));

  double version = version_json.number_value();
  if (version < static_cast<double>(std::numeric_limits<int32_t>::min()) ||
      version > static_cast<double>(std::numeric_limits<int32_t>::max())) {
    return Status(error::GoogleError::OUT_OF_RANGE,
                  "Version of TCB info JSON cannot be represented");
  }
  return version;
}

// Parses a valid google.protobuf.Timestamp from |timestamp_json|. The
// |timestamp_json| must be in ISO 8601 format.
StatusOr<google::protobuf::Timestamp> TimestampFromJson(
    const google::protobuf::Value &timestamp_json) {
  const std::string *timestamp_string;
  ASYLO_ASSIGN_OR_RETURN(timestamp_string, JsonGetString(timestamp_json));

  absl::Time time;
  ASYLO_ASSIGN_OR_RETURN(time, ParseIso8601TimeString(*timestamp_string));
  if (!CanBeTimestampProto(time)) {
    return Status(
        error::GoogleError::OUT_OF_RANGE,
        "Timestamp cannot be represented as a google.protobuf.Timestamp");
  }

  google::protobuf::Timestamp timestamp;
  absl::Duration from_unix_epoch = time - absl::UnixEpoch();
  int64_t num_seconds = from_unix_epoch / absl::Seconds(1);
  int64_t num_nanos =
      (from_unix_epoch - num_seconds * absl::Seconds(1)) / absl::Nanoseconds(1);
  timestamp.set_seconds(num_seconds);
  timestamp.set_nanos(num_nanos);
  return timestamp;
}

// Parses a valid Fmspc from |fmspc_json|.
StatusOr<Fmspc> FmspcFromJson(const google::protobuf::Value &fmspc_json) {
  const std::string *fmspc_hex_string;
  ASYLO_ASSIGN_OR_RETURN(fmspc_hex_string, JsonGetString(fmspc_json));
  if (!IsHexEncoded(*fmspc_hex_string)) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "FMSPC JSON is not a hex encoding string");
  }

  std::string fmspc_bytes = absl::HexStringToBytes(*fmspc_hex_string);
  if (fmspc_bytes.size() != kFmspcSize) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  absl::StrCat("FMSPC JSON does not represent a ", kFmspcSize,
                               "-byte value"));
  }

  Fmspc fmspc;
  fmspc.set_value(fmspc_bytes);
  return fmspc;
}

// Parses a valid PceId from |pce_id_json|.
StatusOr<PceId> PceIdFromJson(const google::protobuf::Value &pce_id_json) {
  constexpr int kPceIdNumBytes = 2;

  const std::string *pce_id_hex_string;
  ASYLO_ASSIGN_OR_RETURN(pce_id_hex_string, JsonGetString(pce_id_json));
  if (!IsHexEncoded(*pce_id_hex_string)) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "PCE ID JSON is not a hex encoding string");
  }

  std::string pce_id_bytes = absl::HexStringToBytes(*pce_id_hex_string);
  if (pce_id_bytes.size() != kPceIdNumBytes) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  absl::StrCat("PCE ID JSON does not represent a ",
                               kPceIdNumBytes, "-byte value"));
  }

  PceId pce_id;
  pce_id.set_value(
      le16toh(*reinterpret_cast<const uint16_t *>(pce_id_bytes.data())));
  return pce_id;
}

// Parses a valid list of TcbLevels from |tcb_levels_json|.
StatusOr<google::protobuf::RepeatedPtrField<TcbLevel>> TcbLevelsFromJson(
    const google::protobuf::Value &tcb_levels_json) {
  const google::protobuf::ListValue *tcb_levels_array;
  ASYLO_ASSIGN_OR_RETURN(tcb_levels_array, JsonGetArray(tcb_levels_json));

  absl::flat_hash_map<Tcb, TcbStatus, TcbHash, TcbEqual> tcb_to_status_map;
  google::protobuf::RepeatedPtrField<TcbLevel> tcb_levels;
  for (const auto &tcb_level_json : tcb_levels_array->values()) {
    TcbLevel tcb_level;
    ASYLO_ASSIGN_OR_RETURN(tcb_level, TcbLevelFromJson(tcb_level_json));
    auto insert_pair =
        tcb_to_status_map.insert({tcb_level.tcb(), tcb_level.status()});
    if (!insert_pair.second) {
      if (!google::protobuf::util::MessageDifferencer::Equals(insert_pair.first->second,
                                                    tcb_level.status())) {
        return Status(
            error::GoogleError::INVALID_ARGUMENT,
            "TCB info JSON contains the same TCB level multiple times with "
            "different statuses");
      } else {
        std::string json_string;
        if (!google::protobuf::util::MessageToJsonString(tcb_levels_json, &json_string)
                 .ok()) {
          json_string = "TCB levels JSON";
        }
        LOG(WARNING) << absl::StrCat("Encountered duplicate TCB entries in ",
                                     json_string);
        continue;
      }
    }
    *tcb_levels.Add() = std::move(tcb_level);
  }
  return tcb_levels;
}

// Parses a valid TcbInfo from |tcb_info_object|, whose "version" field must be
// equal to 1.
StatusOr<TcbInfo> TcbInfoFromJsonV1(
    const google::protobuf::Struct &tcb_info_object) {
  TcbInfo tcb_info;
  TcbInfoImpl *tcb_info_impl = tcb_info.mutable_impl();

  tcb_info_impl->set_version(1);

  const google::protobuf::Value *issue_date_json;
  ASYLO_ASSIGN_OR_RETURN(issue_date_json,
                         JsonObjectGetField(tcb_info_object, "issueDate"));
  ASYLO_ASSIGN_OR_RETURN(*tcb_info_impl->mutable_issue_date(),
                         TimestampFromJson(*issue_date_json));

  const google::protobuf::Value *next_update_json;
  ASYLO_ASSIGN_OR_RETURN(next_update_json,
                         JsonObjectGetField(tcb_info_object, "nextUpdate"));
  ASYLO_ASSIGN_OR_RETURN(*tcb_info_impl->mutable_next_update(),
                         TimestampFromJson(*next_update_json));

  if (tcb_info_impl->issue_date() >= tcb_info_impl->next_update()) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "Issue date does not come before next update");
  }

  const google::protobuf::Value *fmspc_json;
  ASYLO_ASSIGN_OR_RETURN(fmspc_json,
                         JsonObjectGetField(tcb_info_object, "fmspc"));
  ASYLO_ASSIGN_OR_RETURN(*tcb_info_impl->mutable_fmspc(),
                         FmspcFromJson(*fmspc_json));

  const google::protobuf::Value *pce_id_json;
  ASYLO_ASSIGN_OR_RETURN(pce_id_json,
                         JsonObjectGetField(tcb_info_object, "pceId"));
  ASYLO_ASSIGN_OR_RETURN(*tcb_info_impl->mutable_pce_id(),
                         PceIdFromJson(*pce_id_json));

  const google::protobuf::Value *tcb_levels_json;
  ASYLO_ASSIGN_OR_RETURN(tcb_levels_json,
                         JsonObjectGetField(tcb_info_object, "tcbLevels"));
  ASYLO_ASSIGN_OR_RETURN(*tcb_info_impl->mutable_tcb_levels(),
                         TcbLevelsFromJson(*tcb_levels_json));

  // The TCB info JSON object should have six top-level fields: "version",
  // "issueDate", "nextUpdate", "fmspc", "pceId", and "tcbLevels".
  if (tcb_info_object.fields().size() > 6) {
    std::string json_string;
    if (!google::protobuf::util::MessageToJsonString(tcb_info_object, &json_string)
             .ok()) {
      json_string = "TCB info JSON";
    }
    LOG(WARNING) << absl::StrCat("Encountered unrecognized fields in ",
                                 json_string);
  }

  return tcb_info;
}

}  // namespace

StatusOr<Tcb> TcbFromJson(const std::string &json_string) {
  google::protobuf::Value tcb_json;
  ASYLO_RETURN_IF_ERROR(
      Status(google::protobuf::util::JsonStringToMessage(json_string, &tcb_json)));
  return TcbFromJsonValue(tcb_json);
}

StatusOr<TcbInfo> TcbInfoFromJson(const std::string &json_string) {
  google::protobuf::Value tcb_info_json;
  ASYLO_RETURN_IF_ERROR(
      Status(google::protobuf::util::JsonStringToMessage(json_string, &tcb_info_json)));

  const google::protobuf::Struct *tcb_info_object;
  ASYLO_ASSIGN_OR_RETURN(tcb_info_object, JsonGetObject(tcb_info_json));

  const google::protobuf::Value *version_json;
  ASYLO_ASSIGN_OR_RETURN(version_json,
                         JsonObjectGetField(*tcb_info_object, "version"));
  int version;
  ASYLO_ASSIGN_OR_RETURN(version, VersionFromJson(*version_json));
  switch (version) {
    case 1:
      return TcbInfoFromJsonV1(*tcb_info_object);
    default:
      return Status(error::GoogleError::INVALID_ARGUMENT,
                    "Unrecognized version of TCB info JSON");
  }
}

}  // namespace sgx
}  // namespace asylo
