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

#include "asylo/identity/provisioning/sgx/internal/tcb_info_from_json.h"

#include <endian.h>

#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "google/protobuf/struct.pb.h"
#include <google/protobuf/text_format.h>
#include <google/protobuf/util/json_util.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/base/macros.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/time/civil_time.h"
#include "absl/time/time.h"
#include "absl/types/span.h"
#include "asylo/util/logging.h"
#include "asylo/identity/provisioning/sgx/internal/platform_provisioning.pb.h"
#include "asylo/identity/provisioning/sgx/internal/tcb.h"
#include "asylo/identity/provisioning/sgx/internal/tcb.pb.h"
#include "asylo/test/util/output_collector.h"
#include "asylo/test/util/proto_matchers.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"

namespace asylo {
namespace sgx {
namespace {

using ::testing::ContainsRegex;
using ::testing::Eq;
using ::testing::SizeIs;

constexpr char kLogWarningRegex[] = "  WARNING  ";

// Returns a valid Tcb JSON object.
google::protobuf::Value CreateValidTcbJson() {
  constexpr char kValidTcbJson[] = R"json({
        "sgxtcbcomp01svn": 0,
        "sgxtcbcomp02svn": 1,
        "sgxtcbcomp03svn": 2,
        "sgxtcbcomp04svn": 3,
        "sgxtcbcomp05svn": 4,
        "sgxtcbcomp06svn": 5,
        "sgxtcbcomp07svn": 6,
        "sgxtcbcomp08svn": 7,
        "sgxtcbcomp09svn": 8,
        "sgxtcbcomp10svn": 9,
        "sgxtcbcomp11svn": 10,
        "sgxtcbcomp12svn": 11,
        "sgxtcbcomp13svn": 12,
        "sgxtcbcomp14svn": 13,
        "sgxtcbcomp15svn": 14,
        "sgxtcbcomp16svn": 15,
        "pcesvn": 2
      })json";

  google::protobuf::Value tcb;
  ASYLO_CHECK_OK(
      Status(google::protobuf::util::JsonStringToMessage(kValidTcbJson, &tcb)));
  return tcb;
}

// Returns a valid TCB info JSON object at version 1 with one TCB level and its
// parsed protobuf representation.
std::pair<google::protobuf::Value, TcbInfo> CreateValidTcbInfoV1Pair() {
  constexpr char kValidTcbInfoJson[] = R"json({
        "version": 1,
        "issueDate": "2020-02-20T20:20:20Z",
        "nextUpdate": "2020-03-20T20:20:20Z",
        "fmspc": "0123456789ab",
        "pceId": "0000",
        "tcbLevels": [{
          "tcb": {
            "sgxtcbcomp01svn": 0,
            "sgxtcbcomp02svn": 1,
            "sgxtcbcomp03svn": 2,
            "sgxtcbcomp04svn": 3,
            "sgxtcbcomp05svn": 4,
            "sgxtcbcomp06svn": 5,
            "sgxtcbcomp07svn": 6,
            "sgxtcbcomp08svn": 7,
            "sgxtcbcomp09svn": 8,
            "sgxtcbcomp10svn": 9,
            "sgxtcbcomp11svn": 10,
            "sgxtcbcomp12svn": 11,
            "sgxtcbcomp13svn": 12,
            "sgxtcbcomp14svn": 13,
            "sgxtcbcomp15svn": 14,
            "sgxtcbcomp16svn": 15,
            "pcesvn": 2
          },
          "status": "foobar"
        }]
      })json";
  constexpr char kExpectedTcbInfoProto[] = R"proto(
    impl {
      version: 1
      issue_date { seconds: 1582230020 nanos: 0 }
      next_update: { seconds: 1584735620 nanos: 0 }
      fmspc { value: "\x01\x23\x45\x67\x89\xab" }
      pce_id { value: 0 }
      tcb_levels {
        tcb {
          components: "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
          pce_svn { value: 2 }
        }
        status { unknown_status: "foobar" }
      }
    }
  )proto";

  google::protobuf::Value tcb_info_json;
  ASYLO_CHECK_OK(Status(
      google::protobuf::util::JsonStringToMessage(kValidTcbInfoJson, &tcb_info_json)));
  TcbInfo tcb_info;
  CHECK(google::protobuf::TextFormat::ParseFromString(kExpectedTcbInfoProto, &tcb_info));
  return std::make_pair(tcb_info_json, tcb_info);
}

// Returns a valid TCB info JSON object at version 2 with one TCB level.
std::pair<google::protobuf::Value, TcbInfo> CreateValidTcbInfoV2Pair() {
  constexpr char kValidTcbInfoJson[] = R"pair.first({
        "version": 2,
        "issueDate": "2020-02-20T20:20:20Z",
        "nextUpdate": "2020-03-20T20:20:20Z",
        "fmspc": "0123456789ab",
        "pceId": "0000",
        "tcbType": 0,
        "tcbEvaluationDataNumber": 2,
        "tcbLevels": [{
          "tcb": {
            "sgxtcbcomp01svn": 0,
            "sgxtcbcomp02svn": 1,
            "sgxtcbcomp03svn": 2,
            "sgxtcbcomp04svn": 3,
            "sgxtcbcomp05svn": 4,
            "sgxtcbcomp06svn": 5,
            "sgxtcbcomp07svn": 6,
            "sgxtcbcomp08svn": 7,
            "sgxtcbcomp09svn": 8,
            "sgxtcbcomp10svn": 9,
            "sgxtcbcomp11svn": 10,
            "sgxtcbcomp12svn": 11,
            "sgxtcbcomp13svn": 12,
            "sgxtcbcomp14svn": 13,
            "sgxtcbcomp15svn": 14,
            "sgxtcbcomp16svn": 15,
            "pcesvn": 2
          },
          "tcbDate": "2020-02-20T20:20:20Z",
          "tcbStatus": "UpToDate",
          "advisoryIDs": ["Some advisory ID"]
        }]
      })pair.first";
  constexpr char kExpectedTcbInfoProto[] = R"proto(
    impl {
      version: 2
      issue_date { seconds: 1582230020 nanos: 0 }
      next_update: { seconds: 1584735620 nanos: 0 }
      fmspc { value: "\x01\x23\x45\x67\x89\xab" }
      pce_id { value: 0 }
      tcb_type: TCB_TYPE_0
      tcb_evaluation_data_number: 2
      tcb_levels {
        tcb {
          components: "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
          pce_svn { value: 2 }
        }
        tcb_date { seconds: 1582230020 nanos: 0 }
        status { known_status: UP_TO_DATE }
        advisory_ids: "Some advisory ID"
      }
    }
  )proto";

  google::protobuf::Value tcb_info_json;
  ASYLO_CHECK_OK(Status(
      google::protobuf::util::JsonStringToMessage(kValidTcbInfoJson, &tcb_info_json)));
  TcbInfo tcb_info;
  CHECK(google::protobuf::TextFormat::ParseFromString(kExpectedTcbInfoProto, &tcb_info));
  return std::make_pair(tcb_info_json, tcb_info);
}

// Returns a pair of TCB info JSON value and corresponding TcbInfo message for
// each version in |versions|.
std::vector<std::pair<google::protobuf::Value, TcbInfo>>
CreateValidTcbInfoPairsOfVersions(absl::Span<const int> versions) {
  std::vector<std::pair<google::protobuf::Value, TcbInfo>> tcb_info_pairs;
  for (int version : versions) {
    switch (version) {
      case 1:
        tcb_info_pairs.push_back(CreateValidTcbInfoV1Pair());
        break;
      case 2:
        tcb_info_pairs.push_back(CreateValidTcbInfoV2Pair());
        break;
      default:
        LOG(FATAL) << "Unknown TCB info version: " << version;
    }
  }
  return tcb_info_pairs;
}

// Returns the name of the TCB status field in a TCB level in
// |tcb_info_json|.
std::string StatusFieldName(const google::protobuf::Value &tcb_info_json) {
  CHECK_EQ(tcb_info_json.kind_case(), google::protobuf::Value::kStructValue);
  const google::protobuf::Value &version_json =
      tcb_info_json.struct_value().fields().at("version");
  CHECK_EQ(version_json.kind_case(), google::protobuf::Value::kNumberValue);
  switch (static_cast<int>(version_json.number_value())) {
    case 1:
      return "status";
    case 2:
      return "tcbStatus";
    default:
      LOG(FATAL) << "Unknown TCB info version: " << version_json.number_value();
  }
}

// Returns a string representation of |json|.
std::string JsonToString(const google::protobuf::Value &json) {
  std::string json_string;
  ASYLO_CHECK_OK(Status(google::protobuf::util::MessageToJsonString(json, &json_string)));
  return json_string;
}

TEST(TcbFromJsonValueTest, ImproperJsonFailsToParse) {
  EXPECT_THAT(TcbFromJson("} Wait a minute! This isn't proper JSON!"),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(TcbFromJsonTest, NonObjectJsonValueFailsToParse) {
  EXPECT_THAT(TcbFromJson("[\"An array, not an object\"]"),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(TcbFromJsonTest, MissingSgxTcbComponentSvnFailsToParse) {
  google::protobuf::Value json = CreateValidTcbJson();
  json.mutable_struct_value()->mutable_fields()->erase("sgxtcbcomp09svn");
  EXPECT_THAT(TcbFromJson(JsonToString(json)),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(TcbFromJsonTest, NonIntegerSgxTcbComponentSvnFailsToParse) {
  google::protobuf::Value json = CreateValidTcbJson();
  json.mutable_struct_value()
      ->mutable_fields()
      ->at("sgxtcbcomp06svn")
      .mutable_list_value();
  EXPECT_THAT(TcbFromJson(JsonToString(json)),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(TcbFromJsonTest, OutOfBoundsSgxTcbComponentSvnFailsToParse) {
  google::protobuf::Value json = CreateValidTcbJson();
  json.mutable_struct_value()
      ->mutable_fields()
      ->at("sgxtcbcomp15svn")
      .set_number_value(-7.0);
  EXPECT_THAT(TcbFromJson(JsonToString(json)),
              StatusIs(absl::StatusCode::kInvalidArgument));

  json.mutable_struct_value()
      ->mutable_fields()
      ->at("sgxtcbcomp15svn")
      .set_number_value(1000.0);
  EXPECT_THAT(TcbFromJson(JsonToString(json)),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(TcbFromJsonTest, WithoutPceSvnFieldFailsToParse) {
  google::protobuf::Value json = CreateValidTcbJson();
  json.mutable_struct_value()->mutable_fields()->erase("pcesvn");
  EXPECT_THAT(TcbFromJson(JsonToString(json)),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(TcbFromJsonTest, NonIntegerPceSvnFieldFailsToParse) {
  google::protobuf::Value json = CreateValidTcbJson();
  json.mutable_struct_value()->mutable_fields()->at("pcesvn").set_string_value(
      "");
  EXPECT_THAT(TcbFromJson(JsonToString(json)),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(TcbFromJsonTest, OutOfBoundsPceSvnFieldFailsToParse) {
  google::protobuf::Value json = CreateValidTcbJson();
  json.mutable_struct_value()->mutable_fields()->at("pcesvn").set_number_value(
      -15);
  EXPECT_THAT(TcbFromJson(JsonToString(json)),
              StatusIs(absl::StatusCode::kInvalidArgument));

  json.mutable_struct_value()->mutable_fields()->at("pcesvn").set_number_value(
      70000);
  EXPECT_THAT(TcbFromJson(JsonToString(json)),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(TcbFromJsonTest, CorrectTcbJsonParsesSuccessfully) {
  constexpr char kExpectedTcbProto[] = R"proto(
    components: "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
    pce_svn { value: 2 }
  )proto";

  Tcb tcb;
  ASYLO_ASSERT_OK_AND_ASSIGN(tcb,
                             TcbFromJson(JsonToString(CreateValidTcbJson())));
  ASYLO_ASSERT_OK(ValidateTcb(tcb));

  Tcb expected_tcb;
  ASSERT_TRUE(
      google::protobuf::TextFormat::ParseFromString(kExpectedTcbProto, &expected_tcb));
  EXPECT_THAT(tcb, EqualsProto(expected_tcb));
}

TEST(TcbFromJsonTest, ExtraFieldsCausesLogWarning) {
  google::protobuf::Value json = CreateValidTcbJson();
  google::protobuf::Value value;
  value.set_number_value(0.0);
  json.mutable_struct_value()->mutable_fields()->insert({"extra", value});

  Tcb tcb;
  OutputCollector warning_collector(kCollectStdout);
  ASYLO_ASSERT_OK_AND_ASSIGN(tcb, TcbFromJson(JsonToString(json)));
  ASYLO_ASSERT_OK(ValidateTcb(tcb));
  EXPECT_THAT(warning_collector.CollectOutputSoFar(),
              IsOkAndHolds(ContainsRegex(kLogWarningRegex)));
}

TEST(TcbInfoFromJsonTest, ImproperJsonFailsToParse) {
  EXPECT_THAT(TcbInfoFromJson("} Wait a minute! This isn't proper JSON!"),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(TcbInfoFromJsonTest, NonObjectJsonValueFailsToParse) {
  EXPECT_THAT(TcbInfoFromJson("[\"An array, not an object\"]"),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(TcbInfoFromJsonTest, TcbInfoJsonWithoutVersionFieldFailsToParse) {
  for (auto &pair : CreateValidTcbInfoPairsOfVersions({1, 2})) {
    pair.first.mutable_struct_value()->mutable_fields()->erase("version");
    EXPECT_THAT(TcbInfoFromJson(JsonToString(pair.first)),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbInfoFromJsonTest, TcbInfoJsonWithNonIntegerVersionFailsToParse) {
  for (auto &pair : CreateValidTcbInfoPairsOfVersions({1, 2})) {
    pair.first.mutable_struct_value()
        ->mutable_fields()
        ->at("version")
        .mutable_list_value();
    EXPECT_THAT(TcbInfoFromJson(JsonToString(pair.first)),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbInfoFromJsonTest, TcbInfoJsonWithOutOfRangeVersionFailsToParse) {
  for (auto &pair : CreateValidTcbInfoPairsOfVersions({1, 2})) {
    pair.first.mutable_struct_value()
        ->mutable_fields()
        ->at("version")
        .set_number_value(10000000000.0);
    EXPECT_THAT(TcbInfoFromJson(JsonToString(pair.first)),
                StatusIs(absl::StatusCode::kOutOfRange));
  }
}

TEST(TcbInfoFromJsonTest, TcbInfoJsonWithUnknownVersionFailsToParse) {
  for (auto &pair : CreateValidTcbInfoPairsOfVersions({1, 2})) {
    pair.first.mutable_struct_value()
        ->mutable_fields()
        ->at("version")
        .set_number_value(73.0);
    EXPECT_THAT(TcbInfoFromJson(JsonToString(pair.first)),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbInfoFromJsonTest, TcbInfoJsonWithoutIssueDateFieldFailsToParse) {
  for (auto &pair : CreateValidTcbInfoPairsOfVersions({1, 2})) {
    pair.first.mutable_struct_value()->mutable_fields()->erase("issueDate");
    EXPECT_THAT(TcbInfoFromJson(JsonToString(pair.first)),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbInfoFromJsonTest, TcbInfoJsonWithNonStringIssueDateFailsToParse) {
  for (auto &pair : CreateValidTcbInfoPairsOfVersions({1, 2})) {
    pair.first.mutable_struct_value()
        ->mutable_fields()
        ->at("issueDate")
        .mutable_list_value();
    EXPECT_THAT(TcbInfoFromJson(JsonToString(pair.first)),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbInfoFromJsonTest, TcbInfoJsonWithGarbledIssueDateFailsToParse) {
  for (auto &pair : CreateValidTcbInfoPairsOfVersions({1, 2})) {
    pair.first.mutable_struct_value()
        ->mutable_fields()
        ->at("issueDate")
        .set_string_value("2000-01-01T00:00:0whatisthemeaningoflifeZ");
    EXPECT_THAT(TcbInfoFromJson(JsonToString(pair.first)),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbInfoFromJsonTest, TcbInfoJsonWithOutOfRangeIssueDateFailsToParse) {
  for (auto &pair : CreateValidTcbInfoPairsOfVersions({1, 2})) {
    pair.first.mutable_struct_value()
        ->mutable_fields()
        ->at("issueDate")
        .set_string_value("10000-01-01T00:00:00Z");
    EXPECT_THAT(TcbInfoFromJson(JsonToString(pair.first)),
                StatusIs(absl::StatusCode::kOutOfRange));
  }
}

TEST(TcbInfoFromJsonTest, TcbInfoJsonWithoutNextUpdateFieldFailsToParse) {
  for (auto &pair : CreateValidTcbInfoPairsOfVersions({1, 2})) {
    pair.first.mutable_struct_value()->mutable_fields()->erase("nextUpdate");
    EXPECT_THAT(TcbInfoFromJson(JsonToString(pair.first)),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbInfoFromJsonTest, TcbInfoJsonWithNonStringNextUpdateFailsToParse) {
  for (auto &pair : CreateValidTcbInfoPairsOfVersions({1, 2})) {
    pair.first.mutable_struct_value()
        ->mutable_fields()
        ->at("nextUpdate")
        .mutable_list_value();
    EXPECT_THAT(TcbInfoFromJson(JsonToString(pair.first)),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbInfoFromJsonTest, TcbInfoJsonWithGarbledNextUpdateFailsToParse) {
  for (auto &pair : CreateValidTcbInfoPairsOfVersions({1, 2})) {
    pair.first.mutable_struct_value()
        ->mutable_fields()
        ->at("nextUpdate")
        .set_string_value("2000-01-01T00:00:0whatisthemeaningoflifeZ");
    EXPECT_THAT(TcbInfoFromJson(JsonToString(pair.first)),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbInfoFromJsonTest, TcbInfoJsonWithOutOfRangeNextUpdateFailsToParse) {
  for (auto &pair : CreateValidTcbInfoPairsOfVersions({1, 2})) {
    pair.first.mutable_struct_value()
        ->mutable_fields()
        ->at("nextUpdate")
        .set_string_value("10000-01-01T00:00:00Z");
    EXPECT_THAT(TcbInfoFromJson(JsonToString(pair.first)),
                StatusIs(absl::StatusCode::kOutOfRange));
  }
}

TEST(TcbInfoFromJsonTest, TcbInfoJsonWithIssueDateAfterNextUpdateFailsToParse) {
  for (auto &pair : CreateValidTcbInfoPairsOfVersions({1, 2})) {
    pair.first.mutable_struct_value()
        ->mutable_fields()
        ->at("issueDate")
        .set_string_value("3000-01-01T00:00:00Z");
    pair.first.mutable_struct_value()
        ->mutable_fields()
        ->at("nextUpdate")
        .set_string_value("2000-01-01T00:00:00Z");
    EXPECT_THAT(TcbInfoFromJson(JsonToString(pair.first)),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbInfoFromJsonTest, TcbInfoJsonWithoutFmspcFieldFailsToParse) {
  for (auto &pair : CreateValidTcbInfoPairsOfVersions({1, 2})) {
    pair.first.mutable_struct_value()->mutable_fields()->erase("fmspc");
    EXPECT_THAT(TcbInfoFromJson(JsonToString(pair.first)),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbInfoFromJsonTest, TcbInfoJsonWithNonStringFmspcFailsToParse) {
  for (auto &pair : CreateValidTcbInfoPairsOfVersions({1, 2})) {
    pair.first.mutable_struct_value()
        ->mutable_fields()
        ->at("fmspc")
        .mutable_list_value();
    EXPECT_THAT(TcbInfoFromJson(JsonToString(pair.first)),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbInfoFromJsonTest, TcbInfoJsonWithBadHexInFmspcFailsToParse) {
  for (auto &pair : CreateValidTcbInfoPairsOfVersions({1, 2})) {
    pair.first.mutable_struct_value()
        ->mutable_fields()
        ->at("fmspc")
        .set_string_value("00000000000z");
    EXPECT_THAT(TcbInfoFromJson(JsonToString(pair.first)),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbInfoFromJsonTest, TcbInfoJsonWithWrongSizeOfFmspcFailsToParse) {
  for (auto &pair : CreateValidTcbInfoPairsOfVersions({1, 2})) {
    pair.first.mutable_struct_value()
        ->mutable_fields()
        ->at("fmspc")
        .set_string_value("00ab");
    EXPECT_THAT(TcbInfoFromJson(JsonToString(pair.first)),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbInfoFromJsonTest, TcbInfoJsonWithoutPceIdFieldFailsToParse) {
  for (auto &pair : CreateValidTcbInfoPairsOfVersions({1, 2})) {
    pair.first.mutable_struct_value()->mutable_fields()->erase("pceId");
    EXPECT_THAT(TcbInfoFromJson(JsonToString(pair.first)),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbInfoFromJsonTest, TcbInfoJsonWithNonStringPceIdFailsToParse) {
  for (auto &pair : CreateValidTcbInfoPairsOfVersions({1, 2})) {
    pair.first.mutable_struct_value()
        ->mutable_fields()
        ->at("pceId")
        .mutable_list_value();
    EXPECT_THAT(TcbInfoFromJson(JsonToString(pair.first)),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbInfoFromJsonTest, TcbInfoJsonWithBadHexInPceIdFailsToParse) {
  for (auto &pair : CreateValidTcbInfoPairsOfVersions({1, 2})) {
    pair.first.mutable_struct_value()
        ->mutable_fields()
        ->at("pceId")
        .set_string_value("000z");
    EXPECT_THAT(TcbInfoFromJson(JsonToString(pair.first)),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbInfoFromJsonTest, TcbInfoJsonWithWrongSizeOfPceIdFailsToParse) {
  for (auto &pair : CreateValidTcbInfoPairsOfVersions({1, 2})) {
    pair.first.mutable_struct_value()
        ->mutable_fields()
        ->at("pceId")
        .set_string_value("00ab00");
    EXPECT_THAT(TcbInfoFromJson(JsonToString(pair.first)),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbInfoFromJsonTest, TcbInfoV2JsonWithoutTcbTypeFieldFailsToParse) {
  for (auto &pair : CreateValidTcbInfoPairsOfVersions({2})) {
    pair.first.mutable_struct_value()->mutable_fields()->erase("tcbType");
    EXPECT_THAT(TcbInfoFromJson(JsonToString(pair.first)),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbInfoFromJsonTest, TcbInfoV2JsonWithNonNumberTcbTypeFieldFailsToParse) {
  for (auto &pair : CreateValidTcbInfoPairsOfVersions({2})) {
    pair.first.mutable_struct_value()
        ->mutable_fields()
        ->at("tcbType")
        .mutable_list_value();
    EXPECT_THAT(TcbInfoFromJson(JsonToString(pair.first)),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbInfoFromJsonTest, TcbInfoV2JsonWithOutOfRangeTcbTypeFieldFailsToParse) {
  for (auto &pair : CreateValidTcbInfoPairsOfVersions({2})) {
    pair.first.mutable_struct_value()
        ->mutable_fields()
        ->at("tcbType")
        .set_number_value(10000000000.0);
    EXPECT_THAT(TcbInfoFromJson(JsonToString(pair.first)),
                StatusIs(absl::StatusCode::kOutOfRange));
  }
}

TEST(TcbInfoFromJsonTest, TcbInfoV2JsonWithUnknownTcbTypeFieldFailsToParse) {
  for (auto &pair : CreateValidTcbInfoPairsOfVersions({2})) {
    pair.first.mutable_struct_value()
        ->mutable_fields()
        ->at("tcbType")
        .set_number_value(3.0);
    EXPECT_THAT(TcbInfoFromJson(JsonToString(pair.first)),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbInfoFromJsonTest,
     TcbInfoV2JsonWithoutTcbEvaluationDataNumberFieldFailsToParse) {
  for (auto &pair : CreateValidTcbInfoPairsOfVersions({2})) {
    pair.first.mutable_struct_value()->mutable_fields()->erase(
        "tcbEvaluationDataNumber");
    EXPECT_THAT(TcbInfoFromJson(JsonToString(pair.first)),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbInfoFromJsonTest,
     TcbInfoV2JsonWithNonNumberTcbEvaluationDataNumberFieldFailsToParse) {
  for (auto &pair : CreateValidTcbInfoPairsOfVersions({2})) {
    pair.first.mutable_struct_value()
        ->mutable_fields()
        ->at("tcbEvaluationDataNumber")
        .mutable_list_value();
    EXPECT_THAT(TcbInfoFromJson(JsonToString(pair.first)),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbInfoFromJsonTest,
     TcbInfoV2JsonWithOutOfRangeTcbEvaluationDataNumberFieldFailsToParse) {
  for (auto &pair : CreateValidTcbInfoPairsOfVersions({2})) {
    pair.first.mutable_struct_value()
        ->mutable_fields()
        ->at("tcbEvaluationDataNumber")
        .set_number_value(10000000000.0);
    EXPECT_THAT(TcbInfoFromJson(JsonToString(pair.first)),
                StatusIs(absl::StatusCode::kOutOfRange));
  }
}

TEST(TcbInfoFromJsonTest, TcbInfoJsonWithoutTcbLevelsFieldFailsToParse) {
  for (auto &pair : CreateValidTcbInfoPairsOfVersions({1, 2})) {
    pair.first.mutable_struct_value()->mutable_fields()->erase("tcbLevels");
    EXPECT_THAT(TcbInfoFromJson(JsonToString(pair.first)),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbInfoFromJsonTest, TcbInfoJsonWithNonArrayTcbLevelsFailsToParse) {
  for (auto &pair : CreateValidTcbInfoPairsOfVersions({1, 2})) {
    pair.first.mutable_struct_value()
        ->mutable_fields()
        ->at("tcbLevels")
        .mutable_struct_value();
    EXPECT_THAT(TcbInfoFromJson(JsonToString(pair.first)),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbInfoFromJsonTest, TcbLevelJsonWithoutTcbFieldFailsToParse) {
  for (auto &pair : CreateValidTcbInfoPairsOfVersions({1, 2})) {
    pair.first.mutable_struct_value()
        ->mutable_fields()
        ->at("tcbLevels")
        .mutable_list_value()
        ->mutable_values(0)
        ->mutable_struct_value()
        ->mutable_fields()
        ->erase("tcb");
    EXPECT_THAT(TcbInfoFromJson(JsonToString(pair.first)),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbInfoFromJsonTest, TcbLevelJsonWithNonObjectTcbFailsToParse) {
  for (auto &pair : CreateValidTcbInfoPairsOfVersions({1, 2})) {
    pair.first.mutable_struct_value()
        ->mutable_fields()
        ->at("tcbLevels")
        .mutable_list_value()
        ->mutable_values(0)
        ->mutable_struct_value()
        ->mutable_fields()
        ->at("tcb")
        .mutable_list_value();
    EXPECT_THAT(TcbInfoFromJson(JsonToString(pair.first)),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbInfoFromJsonTest, TcbJsonWithMissingSgxTcbComponentSvnFailsToParse) {
  for (auto &pair : CreateValidTcbInfoPairsOfVersions({1, 2})) {
    pair.first.mutable_struct_value()
        ->mutable_fields()
        ->at("tcbLevels")
        .mutable_list_value()
        ->mutable_values(0)
        ->mutable_struct_value()
        ->mutable_fields()
        ->at("tcb")
        .mutable_struct_value()
        ->mutable_fields()
        ->erase("sgxtcbcomp09svn");
    EXPECT_THAT(TcbInfoFromJson(JsonToString(pair.first)),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbInfoFromJsonTest, TcbJsonWithNonIntegerSgxTcbComponentSvnFailsToParse) {
  for (auto &pair : CreateValidTcbInfoPairsOfVersions({1, 2})) {
    pair.first.mutable_struct_value()
        ->mutable_fields()
        ->at("tcbLevels")
        .mutable_list_value()
        ->mutable_values(0)
        ->mutable_struct_value()
        ->mutable_fields()
        ->at("tcb")
        .mutable_struct_value()
        ->mutable_fields()
        ->at("sgxtcbcomp06svn")
        .mutable_list_value();
    EXPECT_THAT(TcbInfoFromJson(JsonToString(pair.first)),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbInfoFromJsonTest,
     TcbJsonWithOutOfBoundsSgxTcbComponentSvnFailsToParse) {
  for (auto &pair : CreateValidTcbInfoPairsOfVersions({1, 2})) {
    pair.first.mutable_struct_value()
        ->mutable_fields()
        ->at("tcbLevels")
        .mutable_list_value()
        ->mutable_values(0)
        ->mutable_struct_value()
        ->mutable_fields()
        ->at("tcb")
        .mutable_struct_value()
        ->mutable_fields()
        ->at("sgxtcbcomp15svn")
        .set_number_value(-7.0);
    EXPECT_THAT(TcbInfoFromJson(JsonToString(pair.first)),
                StatusIs(absl::StatusCode::kInvalidArgument));

    pair.first.mutable_struct_value()
        ->mutable_fields()
        ->at("tcbLevels")
        .mutable_list_value()
        ->mutable_values(0)
        ->mutable_struct_value()
        ->mutable_fields()
        ->at("tcb")
        .mutable_struct_value()
        ->mutable_fields()
        ->at("sgxtcbcomp15svn")
        .set_number_value(1000.0);
    EXPECT_THAT(TcbInfoFromJson(JsonToString(pair.first)),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbInfoFromJsonTest, TcbJsonWithoutPceSvnFieldFailsToParse) {
  for (auto &pair : CreateValidTcbInfoPairsOfVersions({1, 2})) {
    pair.first.mutable_struct_value()
        ->mutable_fields()
        ->at("tcbLevels")
        .mutable_list_value()
        ->mutable_values(0)
        ->mutable_struct_value()
        ->mutable_fields()
        ->at("tcb")
        .mutable_struct_value()
        ->mutable_fields()
        ->erase("pcesvn");
    EXPECT_THAT(TcbInfoFromJson(JsonToString(pair.first)),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbInfoFromJsonTest, TcbJsonWithNonIntegerPceSvnFieldFailsToParse) {
  for (auto &pair : CreateValidTcbInfoPairsOfVersions({1, 2})) {
    pair.first.mutable_struct_value()
        ->mutable_fields()
        ->at("tcbLevels")
        .mutable_list_value()
        ->mutable_values(0)
        ->mutable_struct_value()
        ->mutable_fields()
        ->at("tcb")
        .mutable_struct_value()
        ->mutable_fields()
        ->at("pcesvn")
        .set_string_value("");
    EXPECT_THAT(TcbInfoFromJson(JsonToString(pair.first)),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbInfoFromJsonTest, TcbJsonWithOutOfBoundsPceSvnFieldFailsToParse) {
  for (auto &pair : CreateValidTcbInfoPairsOfVersions({1, 2})) {
    pair.first.mutable_struct_value()
        ->mutable_fields()
        ->at("tcbLevels")
        .mutable_list_value()
        ->mutable_values(0)
        ->mutable_struct_value()
        ->mutable_fields()
        ->at("tcb")
        .mutable_struct_value()
        ->mutable_fields()
        ->at("pcesvn")
        .set_number_value(-15);
    EXPECT_THAT(TcbInfoFromJson(JsonToString(pair.first)),
                StatusIs(absl::StatusCode::kInvalidArgument));

    pair.first.mutable_struct_value()
        ->mutable_fields()
        ->at("tcbLevels")
        .mutable_list_value()
        ->mutable_values(0)
        ->mutable_struct_value()
        ->mutable_fields()
        ->at("tcb")
        .mutable_struct_value()
        ->mutable_fields()
        ->at("pcesvn")
        .set_number_value(70000);
    EXPECT_THAT(TcbInfoFromJson(JsonToString(pair.first)),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbInfoFromJsonTest,
     TcbLevelJsonInV2TcbInfoWithoutTcbDateFieldFailsToParse) {
  for (auto &pair : CreateValidTcbInfoPairsOfVersions({2})) {
    pair.first.mutable_struct_value()
        ->mutable_fields()
        ->at("tcbLevels")
        .mutable_list_value()
        ->mutable_values(0)
        ->mutable_struct_value()
        ->mutable_fields()
        ->erase("tcbDate");
    EXPECT_THAT(TcbInfoFromJson(JsonToString(pair.first)),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbInfoFromJsonTest,
     TcbLevelJsonInV2TcbInfoWithNonStringTcbDateFieldFailsToParse) {
  for (auto &pair : CreateValidTcbInfoPairsOfVersions({2})) {
    pair.first.mutable_struct_value()
        ->mutable_fields()
        ->at("tcbLevels")
        .mutable_list_value()
        ->mutable_values(0)
        ->mutable_struct_value()
        ->mutable_fields()
        ->at("tcbDate")
        .mutable_list_value();
    EXPECT_THAT(TcbInfoFromJson(JsonToString(pair.first)),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbInfoFromJsonTest,
     TcbLevelJsonInV2TcbInfoWithGarbledTcbDateFieldFailsToParse) {
  for (auto &pair : CreateValidTcbInfoPairsOfVersions({2})) {
    pair.first.mutable_struct_value()
        ->mutable_fields()
        ->at("tcbLevels")
        .mutable_list_value()
        ->mutable_values(0)
        ->mutable_struct_value()
        ->mutable_fields()
        ->at("tcbDate")
        .set_string_value("2000-01-01T00:00:0whatisthemeaningoflifeZ");
    EXPECT_THAT(TcbInfoFromJson(JsonToString(pair.first)),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbInfoFromJsonTest,
     TcbLevelJsonInV2TcbInfoWithOutOfRangeTcbDateFieldFailsToParse) {
  for (auto &pair : CreateValidTcbInfoPairsOfVersions({2})) {
    pair.first.mutable_struct_value()
        ->mutable_fields()
        ->at("tcbLevels")
        .mutable_list_value()
        ->mutable_values(0)
        ->mutable_struct_value()
        ->mutable_fields()
        ->at("tcbDate")
        .set_string_value("10000-01-01T00:00:00Z");
    EXPECT_THAT(TcbInfoFromJson(JsonToString(pair.first)),
                StatusIs(absl::StatusCode::kOutOfRange));
  }
}

TEST(TcbInfoFromJsonTest, TcbLevelJsonWithoutStatusFieldFailsToParse) {
  for (auto &pair : CreateValidTcbInfoPairsOfVersions({1, 2})) {
    pair.first.mutable_struct_value()
        ->mutable_fields()
        ->at("tcbLevels")
        .mutable_list_value()
        ->mutable_values(0)
        ->mutable_struct_value()
        ->mutable_fields()
        ->erase(StatusFieldName(pair.first));
    EXPECT_THAT(TcbInfoFromJson(JsonToString(pair.first)),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbInfoFromJsonTest, TcbLevelJsonWithNonStringStatusFailsToParse) {
  for (auto &pair : CreateValidTcbInfoPairsOfVersions({1, 2})) {
    pair.first.mutable_struct_value()
        ->mutable_fields()
        ->at("tcbLevels")
        .mutable_list_value()
        ->mutable_values(0)
        ->mutable_struct_value()
        ->mutable_fields()
        ->at(StatusFieldName(pair.first))
        .mutable_list_value();
    EXPECT_THAT(TcbInfoFromJson(JsonToString(pair.first)),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbInfoFromJsonTest,
     TcbLevelJsonInV2TcbInfoWithNonListAdvisoryIdsFieldFailsToParse) {
  for (auto &pair : CreateValidTcbInfoPairsOfVersions({2})) {
    pair.first.mutable_struct_value()
        ->mutable_fields()
        ->at("tcbLevels")
        .mutable_list_value()
        ->mutable_values(0)
        ->mutable_struct_value()
        ->mutable_fields()
        ->at("advisoryIDs")
        .set_string_value("not a list");
    EXPECT_THAT(TcbInfoFromJson(JsonToString(pair.first)),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbInfoFromJsonTest,
     TcbLevelJsonInV2TcbInfoWithEmptyAdvisoryIdsFieldFailsToParse) {
  for (auto &pair : CreateValidTcbInfoPairsOfVersions({2})) {
    pair.first.mutable_struct_value()
        ->mutable_fields()
        ->at("tcbLevels")
        .mutable_list_value()
        ->mutable_values(0)
        ->mutable_struct_value()
        ->mutable_fields()
        ->at("advisoryIDs")
        .mutable_list_value()
        ->Clear();
    EXPECT_THAT(TcbInfoFromJson(JsonToString(pair.first)),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbInfoFromJsonTest,
     TcbLevelJsonInV2TcbInfoWithNonStringAdvisoryIdFailsToParse) {
  for (auto &pair : CreateValidTcbInfoPairsOfVersions({2})) {
    pair.first.mutable_struct_value()
        ->mutable_fields()
        ->at("tcbLevels")
        .mutable_list_value()
        ->mutable_values(0)
        ->mutable_struct_value()
        ->mutable_fields()
        ->at("advisoryIDs")
        .mutable_list_value()
        ->mutable_values(0)
        ->mutable_list_value();
    EXPECT_THAT(TcbInfoFromJson(JsonToString(pair.first)),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbInfoFromJsonTest,
     TcbInfoJsonWithDuplicateTcbsWithDifferentStatusesFailsToParse) {
  for (auto &pair : CreateValidTcbInfoPairsOfVersions({1, 2})) {
    google::protobuf::ListValue *tcb_levels = pair.first.mutable_struct_value()
                                                  ->mutable_fields()
                                                  ->at("tcbLevels")
                                                  .mutable_list_value();
    google::protobuf::Value *new_level = tcb_levels->add_values();
    *new_level = tcb_levels->values(0);
    new_level->mutable_struct_value()
        ->mutable_fields()
        ->at(StatusFieldName(pair.first))
        .set_string_value("OutOfDate");
    EXPECT_THAT(TcbInfoFromJson(JsonToString(pair.first)),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbInfoFromJsonTest, CorrectTcbInfoJsonParsesSuccessfully) {
  for (const auto &pair : CreateValidTcbInfoPairsOfVersions({1, 2})) {
    TcbInfo tcb_info;
    ASYLO_ASSERT_OK_AND_ASSIGN(tcb_info,
                               TcbInfoFromJson(JsonToString(pair.first)));
    ASYLO_ASSERT_OK(ValidateTcbInfo(tcb_info));
    EXPECT_THAT(tcb_info, EqualsProto(pair.second));
  }
}

TEST(TcbInfoFromJsonTest, TcbInfoJsonWithNonZeroPceIdParsesSuccessfully) {
  for (auto &pair : CreateValidTcbInfoPairsOfVersions({1, 2})) {
    pair.first.mutable_struct_value()
        ->mutable_fields()
        ->at("pceId")
        .set_string_value("2301");

    TcbInfo tcb_info;
    ASYLO_ASSERT_OK_AND_ASSIGN(tcb_info,
                               TcbInfoFromJson(JsonToString(pair.first)));
    ASYLO_ASSERT_OK(ValidateTcbInfo(tcb_info));
    EXPECT_THAT(tcb_info.impl().pce_id().value(), Eq(0x0123));
  }
}

TEST(TcbInfoFromJsonTest,
     TcbInfoV2JsonWithNoAdvisoryIdsFieldParsesSuccessfully) {
  for (auto &pair : CreateValidTcbInfoPairsOfVersions({2})) {
    pair.first.mutable_struct_value()
        ->mutable_fields()
        ->at("tcbLevels")
        .mutable_list_value()
        ->mutable_values(0)
        ->mutable_struct_value()
        ->mutable_fields()
        ->erase("advisoryIDs");
    pair.second.mutable_impl()->mutable_tcb_levels(0)->clear_advisory_ids();
    TcbInfo tcb_info;
    ASYLO_ASSERT_OK_AND_ASSIGN(tcb_info,
                               TcbInfoFromJson(JsonToString(pair.first)));
    ASYLO_ASSERT_OK(ValidateTcbInfo(tcb_info));
    EXPECT_THAT(tcb_info, EqualsProto(pair.second));
  }
}

TEST(TcbInfoFromJsonTest,
     TcbLevelJsonWithDifferentKnownStatusValuesParseSuccessfully) {
  constexpr absl::string_view kKnownStatusStrings[] = {
      "UpToDate", "ConfigurationNeeded", "OutOfDate", "Revoked"};
  constexpr TcbStatus::StatusType kKnownStatusValues[] = {
      TcbStatus::UP_TO_DATE, TcbStatus::CONFIGURATION_NEEDED,
      TcbStatus::OUT_OF_DATE, TcbStatus::REVOKED};

  for (const auto &pair : CreateValidTcbInfoPairsOfVersions({1, 2})) {
    for (int i = 0; i < ABSL_ARRAYSIZE(kKnownStatusValues); ++i) {
      google::protobuf::Value json_copy = pair.first;
      json_copy.mutable_struct_value()
          ->mutable_fields()
          ->at("tcbLevels")
          .mutable_list_value()
          ->mutable_values(0)
          ->mutable_struct_value()
          ->mutable_fields()
          ->at(StatusFieldName(json_copy))
          .set_string_value(kKnownStatusStrings[i].data(),
                            kKnownStatusStrings[i].size());

      TcbInfo tcb_info;
      ASYLO_ASSERT_OK_AND_ASSIGN(tcb_info,
                                 TcbInfoFromJson(JsonToString(json_copy)));
      ASYLO_ASSERT_OK(ValidateTcbInfo(tcb_info));
      const TcbStatus &tcb_status = tcb_info.impl().tcb_levels(0).status();
      ASSERT_THAT(tcb_status.value_case(), Eq(TcbStatus::kKnownStatus));
      EXPECT_THAT(tcb_status.known_status(), Eq(kKnownStatusValues[i]));
    }
  }
}

TEST(TcbInfoFromJsonTest,
     TcbLevelJsonWithRepeatedTcbLevelsIsDeduplicatedAndCausesLogWarning) {
  for (auto &pair : CreateValidTcbInfoPairsOfVersions({1, 2})) {
    google::protobuf::ListValue *tcb_levels = pair.first.mutable_struct_value()
                                                  ->mutable_fields()
                                                  ->at("tcbLevels")
                                                  .mutable_list_value();
    *tcb_levels->add_values() = tcb_levels->values(0);

    TcbInfo tcb_info;
    OutputCollector warning_collector(kCollectStdout);
    ASYLO_ASSERT_OK_AND_ASSIGN(tcb_info,
                               TcbInfoFromJson(JsonToString(pair.first)));
    ASYLO_ASSERT_OK(ValidateTcbInfo(tcb_info));
    EXPECT_THAT(tcb_info.impl().tcb_levels(), SizeIs(1));
    EXPECT_THAT(warning_collector.CollectOutputSoFar(),
                IsOkAndHolds(ContainsRegex(kLogWarningRegex)));
  }
}

TEST(TcbInfoFromJsonTest, TcbInfoJsonWithExtraFieldsCausesLogWarning) {
  for (auto &pair : CreateValidTcbInfoPairsOfVersions({1, 2})) {
    google::protobuf::Value value;
    value.set_number_value(0.0);
    pair.first.mutable_struct_value()->mutable_fields()->insert(
        {"veryExtra", value});

    TcbInfo tcb_info;
    OutputCollector warning_collector(kCollectStdout);
    ASYLO_ASSERT_OK_AND_ASSIGN(tcb_info,
                               TcbInfoFromJson(JsonToString(pair.first)));
    ASYLO_ASSERT_OK(ValidateTcbInfo(tcb_info));
    EXPECT_THAT(warning_collector.CollectOutputSoFar(),
                IsOkAndHolds(ContainsRegex(kLogWarningRegex)));
  }
}

TEST(TcbInfoFromJsonTest, TcbLevelJsonWithExtraFieldsCausesLogWarning) {
  for (auto &pair : CreateValidTcbInfoPairsOfVersions({1, 2})) {
    google::protobuf::Value value;
    value.set_number_value(0.0);
    pair.first.mutable_struct_value()
        ->mutable_fields()
        ->at("tcbLevels")
        .mutable_list_value()
        ->mutable_values(0)
        ->mutable_struct_value()
        ->mutable_fields()
        ->insert({"veryExtra", value});

    TcbInfo tcb_info;
    OutputCollector warning_collector(kCollectStdout);
    ASYLO_ASSERT_OK_AND_ASSIGN(tcb_info,
                               TcbInfoFromJson(JsonToString(pair.first)));
    ASYLO_ASSERT_OK(ValidateTcbInfo(tcb_info));
    EXPECT_THAT(warning_collector.CollectOutputSoFar(),
                IsOkAndHolds(ContainsRegex(kLogWarningRegex)));
  }
}

TEST(TcbInfoFromJsonTest, TcbJsonWithExtraFieldsCausesLogWarning) {
  for (auto &pair : CreateValidTcbInfoPairsOfVersions({1, 2})) {
    google::protobuf::Value value;
    value.set_number_value(0.0);
    pair.first.mutable_struct_value()
        ->mutable_fields()
        ->at("tcbLevels")
        .mutable_list_value()
        ->mutable_values(0)
        ->mutable_struct_value()
        ->mutable_fields()
        ->at("tcb")
        .mutable_struct_value()
        ->mutable_fields()
        ->insert({"veryExtra", value});

    TcbInfo tcb_info;
    OutputCollector warning_collector(kCollectStdout);
    ASYLO_ASSERT_OK_AND_ASSIGN(tcb_info,
                               TcbInfoFromJson(JsonToString(pair.first)));
    ASYLO_ASSERT_OK(ValidateTcbInfo(tcb_info));
    EXPECT_THAT(warning_collector.CollectOutputSoFar(),
                IsOkAndHolds(ContainsRegex(kLogWarningRegex)));
  }
}

}  // namespace
}  // namespace sgx
}  // namespace asylo
