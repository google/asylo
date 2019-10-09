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

#include "google/protobuf/struct.pb.h"
#include <google/protobuf/text_format.h>
#include <google/protobuf/util/json_util.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/base/macros.h"
#include "absl/strings/string_view.h"
#include "absl/time/civil_time.h"
#include "absl/time/time.h"
#include "asylo/util/logging.h"
#include "asylo/identity/sgx/platform_provisioning.pb.h"
#include "asylo/identity/sgx/tcb.h"
#include "asylo/identity/sgx/tcb.pb.h"
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

// Returns a valid TCB info JSON object with one TCB level.
google::protobuf::Value CreateValidTcbInfoJson() {
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
          "status": "UpToDate"
        }]
      })json";

  google::protobuf::Value tcb_info;
  ASYLO_CHECK_OK(
      Status(google::protobuf::util::JsonStringToMessage(kValidTcbInfoJson, &tcb_info)));
  return tcb_info;
}

// Returns a string representation of |json|.
std::string JsonToString(const google::protobuf::Value &json) {
  std::string json_string;
  ASYLO_CHECK_OK(Status(google::protobuf::util::MessageToJsonString(json, &json_string)));
  return json_string;
}

TEST(TcbFromJsonValueTest, ImproperJsonFailsToParse) {
  EXPECT_THAT(TcbFromJson("} Wait a minute! This isn't proper JSON!"),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbFromJsonTest, NonObjectJsonValueFailsToParse) {
  EXPECT_THAT(TcbFromJson("[\"An array, not an object\"]"),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbFromJsonTest, MissingSgxTcbComponentSvnFailsToParse) {
  google::protobuf::Value json = CreateValidTcbJson();
  json.mutable_struct_value()->mutable_fields()->erase("sgxtcbcomp09svn");
  EXPECT_THAT(TcbFromJson(JsonToString(json)),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbFromJsonTest, NonIntegerSgxTcbComponentSvnFailsToParse) {
  google::protobuf::Value json = CreateValidTcbJson();
  json.mutable_struct_value()
      ->mutable_fields()
      ->at("sgxtcbcomp06svn")
      .mutable_list_value();
  EXPECT_THAT(TcbFromJson(JsonToString(json)),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbFromJsonTest, OutOfBoundsSgxTcbComponentSvnFailsToParse) {
  google::protobuf::Value json = CreateValidTcbJson();
  json.mutable_struct_value()
      ->mutable_fields()
      ->at("sgxtcbcomp15svn")
      .set_number_value(-7.);
  EXPECT_THAT(TcbFromJson(JsonToString(json)),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));

  json.mutable_struct_value()
      ->mutable_fields()
      ->at("sgxtcbcomp15svn")
      .set_number_value(1000.);
  EXPECT_THAT(TcbFromJson(JsonToString(json)),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbFromJsonTest, WithoutPceSvnFieldFailsToParse) {
  google::protobuf::Value json = CreateValidTcbJson();
  json.mutable_struct_value()->mutable_fields()->erase("pcesvn");
  EXPECT_THAT(TcbFromJson(JsonToString(json)),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbFromJsonTest, NonIntegerPceSvnFieldFailsToParse) {
  google::protobuf::Value json = CreateValidTcbJson();
  json.mutable_struct_value()->mutable_fields()->at("pcesvn").set_string_value(
      "");
  EXPECT_THAT(TcbFromJson(JsonToString(json)),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbFromJsonTest, OutOfBoundsPceSvnFieldFailsToParse) {
  google::protobuf::Value json = CreateValidTcbJson();
  json.mutable_struct_value()->mutable_fields()->at("pcesvn").set_number_value(
      -15);
  EXPECT_THAT(TcbFromJson(JsonToString(json)),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));

  json.mutable_struct_value()->mutable_fields()->at("pcesvn").set_number_value(
      70000);
  EXPECT_THAT(TcbFromJson(JsonToString(json)),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
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
  value.set_number_value(0.);
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
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbInfoFromJsonTest, NonObjectJsonValueFailsToParse) {
  EXPECT_THAT(TcbInfoFromJson("[\"An array, not an object\"]"),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbInfoFromJsonTest, TcbInfoJsonWithoutVersionFieldFailsToParse) {
  google::protobuf::Value json = CreateValidTcbInfoJson();
  json.mutable_struct_value()->mutable_fields()->erase("version");
  EXPECT_THAT(TcbInfoFromJson(JsonToString(json)),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbInfoFromJsonTest, TcbInfoJsonWithNonIntegerVersionFailsToParse) {
  google::protobuf::Value json = CreateValidTcbInfoJson();
  json.mutable_struct_value()
      ->mutable_fields()
      ->at("version")
      .mutable_list_value();
  EXPECT_THAT(TcbInfoFromJson(JsonToString(json)),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbInfoFromJsonTest, TcbInfoJsonWithOutOfRangeVersionFailsToParse) {
  google::protobuf::Value json = CreateValidTcbInfoJson();
  json.mutable_struct_value()->mutable_fields()->at("version").set_number_value(
      10000000000.);
  EXPECT_THAT(TcbInfoFromJson(JsonToString(json)),
              StatusIs(error::GoogleError::OUT_OF_RANGE));
}

TEST(TcbInfoFromJsonTest, TcbInfoJsonWithUnknownVersionFailsToParse) {
  google::protobuf::Value json = CreateValidTcbInfoJson();
  json.mutable_struct_value()->mutable_fields()->at("version").set_number_value(
      73.);
  EXPECT_THAT(TcbInfoFromJson(JsonToString(json)),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbInfoFromJsonTest, TcbInfoJsonWithoutIssueDateFieldFailsToParse) {
  google::protobuf::Value json = CreateValidTcbInfoJson();
  json.mutable_struct_value()->mutable_fields()->erase("issueDate");
  EXPECT_THAT(TcbInfoFromJson(JsonToString(json)),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbInfoFromJsonTest, TcbInfoJsonWithNonStringIssueDateFailsToParse) {
  google::protobuf::Value json = CreateValidTcbInfoJson();
  json.mutable_struct_value()
      ->mutable_fields()
      ->at("issueDate")
      .mutable_list_value();
  EXPECT_THAT(TcbInfoFromJson(JsonToString(json)),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbInfoFromJsonTest, TcbInfoJsonWithGarbledIssueDateFailsToParse) {
  google::protobuf::Value json = CreateValidTcbInfoJson();
  json.mutable_struct_value()
      ->mutable_fields()
      ->at("issueDate")
      .set_string_value("2000-01-01T00:00:0whatisthemeaningoflifeZ");
  EXPECT_THAT(TcbInfoFromJson(JsonToString(json)),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbInfoFromJsonTest, TcbInfoJsonWithOutOfRangeIssueDateFailsToParse) {
  google::protobuf::Value json = CreateValidTcbInfoJson();
  json.mutable_struct_value()
      ->mutable_fields()
      ->at("issueDate")
      .set_string_value("10000-01-01T00:00:00Z");
  EXPECT_THAT(TcbInfoFromJson(JsonToString(json)),
              StatusIs(error::GoogleError::OUT_OF_RANGE));
}

TEST(TcbInfoFromJsonTest, TcbInfoJsonWithoutNextUpdateFieldFailsToParse) {
  google::protobuf::Value json = CreateValidTcbInfoJson();
  json.mutable_struct_value()->mutable_fields()->erase("nextUpdate");
  EXPECT_THAT(TcbInfoFromJson(JsonToString(json)),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbInfoFromJsonTest, TcbInfoJsonWithNonStringNextUpdateFailsToParse) {
  google::protobuf::Value json = CreateValidTcbInfoJson();
  json.mutable_struct_value()
      ->mutable_fields()
      ->at("nextUpdate")
      .mutable_list_value();
  EXPECT_THAT(TcbInfoFromJson(JsonToString(json)),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbInfoFromJsonTest, TcbInfoJsonWithGarbledNextUpdateFailsToParse) {
  google::protobuf::Value json = CreateValidTcbInfoJson();
  json.mutable_struct_value()
      ->mutable_fields()
      ->at("nextUpdate")
      .set_string_value("2000-01-01T00:00:0whatisthemeaningoflifeZ");
  EXPECT_THAT(TcbInfoFromJson(JsonToString(json)),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbInfoFromJsonTest, TcbInfoJsonWithOutOfRangeNextUpdateFailsToParse) {
  google::protobuf::Value json = CreateValidTcbInfoJson();
  json.mutable_struct_value()
      ->mutable_fields()
      ->at("nextUpdate")
      .set_string_value("10000-01-01T00:00:00Z");
  EXPECT_THAT(TcbInfoFromJson(JsonToString(json)),
              StatusIs(error::GoogleError::OUT_OF_RANGE));
}

TEST(TcbInfoFromJsonTest, TcbInfoJsonWithIssueDateAfterNextUpdateFailsToParse) {
  google::protobuf::Value json = CreateValidTcbInfoJson();
  json.mutable_struct_value()
      ->mutable_fields()
      ->at("issueDate")
      .set_string_value("3000-01-01T00:00:00Z");
  json.mutable_struct_value()
      ->mutable_fields()
      ->at("nextUpdate")
      .set_string_value("2000-01-01T00:00:00Z");
  EXPECT_THAT(TcbInfoFromJson(JsonToString(json)),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbInfoFromJsonTest, TcbInfoJsonWithoutFmspcFieldFailsToParse) {
  google::protobuf::Value json = CreateValidTcbInfoJson();
  json.mutable_struct_value()->mutable_fields()->erase("fmspc");
  EXPECT_THAT(TcbInfoFromJson(JsonToString(json)),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbInfoFromJsonTest, TcbInfoJsonWithNonStringFmspcFailsToParse) {
  google::protobuf::Value json = CreateValidTcbInfoJson();
  json.mutable_struct_value()
      ->mutable_fields()
      ->at("fmspc")
      .mutable_list_value();
  EXPECT_THAT(TcbInfoFromJson(JsonToString(json)),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbInfoFromJsonTest, TcbInfoJsonWithBadHexInFmspcFailsToParse) {
  google::protobuf::Value json = CreateValidTcbInfoJson();
  json.mutable_struct_value()->mutable_fields()->at("fmspc").set_string_value(
      "00000000000z");
  EXPECT_THAT(TcbInfoFromJson(JsonToString(json)),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbInfoFromJsonTest, TcbInfoJsonWithWrongSizeOfFmspcFailsToParse) {
  google::protobuf::Value json = CreateValidTcbInfoJson();
  json.mutable_struct_value()->mutable_fields()->at("fmspc").set_string_value(
      "00ab");
  EXPECT_THAT(TcbInfoFromJson(JsonToString(json)),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbInfoFromJsonTest, TcbInfoJsonWithoutPceIdFieldFailsToParse) {
  google::protobuf::Value json = CreateValidTcbInfoJson();
  json.mutable_struct_value()->mutable_fields()->erase("pceId");
  EXPECT_THAT(TcbInfoFromJson(JsonToString(json)),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbInfoFromJsonTest, TcbInfoJsonWithNonStringPceIdFailsToParse) {
  google::protobuf::Value json = CreateValidTcbInfoJson();
  json.mutable_struct_value()
      ->mutable_fields()
      ->at("pceId")
      .mutable_list_value();
  EXPECT_THAT(TcbInfoFromJson(JsonToString(json)),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbInfoFromJsonTest, TcbInfoJsonWithBadHexInPceIdFailsToParse) {
  google::protobuf::Value json = CreateValidTcbInfoJson();
  json.mutable_struct_value()->mutable_fields()->at("pceId").set_string_value(
      "000z");
  EXPECT_THAT(TcbInfoFromJson(JsonToString(json)),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbInfoFromJsonTest, TcbInfoJsonWithWrongSizeOfPceIdFailsToParse) {
  google::protobuf::Value json = CreateValidTcbInfoJson();
  json.mutable_struct_value()->mutable_fields()->at("pceId").set_string_value(
      "00ab00");
  EXPECT_THAT(TcbInfoFromJson(JsonToString(json)),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbInfoFromJsonTest, TcbInfoJsonWithoutTcbLevelsFieldFailsToParse) {
  google::protobuf::Value json = CreateValidTcbInfoJson();
  json.mutable_struct_value()->mutable_fields()->erase("tcbLevels");
  EXPECT_THAT(TcbInfoFromJson(JsonToString(json)),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbInfoFromJsonTest, TcbInfoJsonWithNonArrayTcbLevelsFailsToParse) {
  google::protobuf::Value json = CreateValidTcbInfoJson();
  json.mutable_struct_value()
      ->mutable_fields()
      ->at("tcbLevels")
      .mutable_struct_value();
  EXPECT_THAT(TcbInfoFromJson(JsonToString(json)),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbInfoFromJsonTest, TcbLevelJsonWithoutTcbFieldFailsToParse) {
  google::protobuf::Value json = CreateValidTcbInfoJson();
  json.mutable_struct_value()
      ->mutable_fields()
      ->at("tcbLevels")
      .mutable_list_value()
      ->mutable_values(0)
      ->mutable_struct_value()
      ->mutable_fields()
      ->erase("tcb");
  EXPECT_THAT(TcbInfoFromJson(JsonToString(json)),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbInfoFromJsonTest, TcbLevelJsonWithNonObjectTcbFailsToParse) {
  google::protobuf::Value json = CreateValidTcbInfoJson();
  json.mutable_struct_value()
      ->mutable_fields()
      ->at("tcbLevels")
      .mutable_list_value()
      ->mutable_values(0)
      ->mutable_struct_value()
      ->mutable_fields()
      ->at("tcb")
      .mutable_list_value();
  EXPECT_THAT(TcbInfoFromJson(JsonToString(json)),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbInfoFromJsonTest, TcbJsonWithMissingSgxTcbComponentSvnFailsToParse) {
  google::protobuf::Value json = CreateValidTcbInfoJson();
  json.mutable_struct_value()
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
  EXPECT_THAT(TcbInfoFromJson(JsonToString(json)),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbInfoFromJsonTest, TcbJsonWithNonIntegerSgxTcbComponentSvnFailsToParse) {
  google::protobuf::Value json = CreateValidTcbInfoJson();
  json.mutable_struct_value()
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
  EXPECT_THAT(TcbInfoFromJson(JsonToString(json)),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbInfoFromJsonTest,
     TcbJsonWithOutOfBoundsSgxTcbComponentSvnFailsToParse) {
  google::protobuf::Value json = CreateValidTcbInfoJson();
  json.mutable_struct_value()
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
      .set_number_value(-7.);
  EXPECT_THAT(TcbInfoFromJson(JsonToString(json)),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));

  json.mutable_struct_value()
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
      .set_number_value(1000.);
  EXPECT_THAT(TcbInfoFromJson(JsonToString(json)),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbInfoFromJsonTest, TcbJsonWithoutPceSvnFieldFailsToParse) {
  google::protobuf::Value json = CreateValidTcbInfoJson();
  json.mutable_struct_value()
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
  EXPECT_THAT(TcbInfoFromJson(JsonToString(json)),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbInfoFromJsonTest, TcbJsonWithNonIntegerPceSvnFieldFailsToParse) {
  google::protobuf::Value json = CreateValidTcbInfoJson();
  json.mutable_struct_value()
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
  EXPECT_THAT(TcbInfoFromJson(JsonToString(json)),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbInfoFromJsonTest, TcbJsonWithOutOfBoundsPceSvnFieldFailsToParse) {
  google::protobuf::Value json = CreateValidTcbInfoJson();
  json.mutable_struct_value()
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
  EXPECT_THAT(TcbInfoFromJson(JsonToString(json)),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));

  json.mutable_struct_value()
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
  EXPECT_THAT(TcbInfoFromJson(JsonToString(json)),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbInfoFromJsonTest, TcbLevelJsonWithoutStatusFieldFailsToParse) {
  google::protobuf::Value json = CreateValidTcbInfoJson();
  json.mutable_struct_value()
      ->mutable_fields()
      ->at("tcbLevels")
      .mutable_list_value()
      ->mutable_values(0)
      ->mutable_struct_value()
      ->mutable_fields()
      ->erase("status");
  EXPECT_THAT(TcbInfoFromJson(JsonToString(json)),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbInfoFromJsonTest, TcbLevelJsonWithNonStringStatusFailsToParse) {
  google::protobuf::Value json = CreateValidTcbInfoJson();
  json.mutable_struct_value()
      ->mutable_fields()
      ->at("tcbLevels")
      .mutable_list_value()
      ->mutable_values(0)
      ->mutable_struct_value()
      ->mutable_fields()
      ->at("status")
      .mutable_list_value();
  EXPECT_THAT(TcbInfoFromJson(JsonToString(json)),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbInfoFromJsonTest,
     TcbInfoJsonWithDuplicateTcbsWithDifferentStatusesFailsToParse) {
  google::protobuf::Value json = CreateValidTcbInfoJson();
  google::protobuf::ListValue *tcb_levels = json.mutable_struct_value()
                                                ->mutable_fields()
                                                ->at("tcbLevels")
                                                .mutable_list_value();
  google::protobuf::Value *new_level = tcb_levels->add_values();
  *new_level = tcb_levels->values(0);
  new_level->mutable_struct_value()
      ->mutable_fields()
      ->at("status")
      .set_string_value("OutOfDate");
  EXPECT_THAT(TcbInfoFromJson(JsonToString(json)),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbInfoFromJsonTest, CorrectTcbInfoJsonParsesSuccessfully) {
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
        status { known_status: UP_TO_DATE }
      }
    }
  )proto";

  TcbInfo tcb_info;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      tcb_info, TcbInfoFromJson(JsonToString(CreateValidTcbInfoJson())));
  ASYLO_ASSERT_OK(ValidateTcbInfo(tcb_info));

  TcbInfo expected_tcb_info;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(kExpectedTcbInfoProto,
                                                  &expected_tcb_info));
  EXPECT_THAT(tcb_info, EqualsProto(expected_tcb_info));
}

TEST(TcbInfoFromJsonTest, TcbInfoJsonWithNonZeroPceIdParsesSuccessfully) {
  google::protobuf::Value json = CreateValidTcbInfoJson();
  json.mutable_struct_value()->mutable_fields()->at("pceId").set_string_value(
      "2301");

  TcbInfo tcb_info;
  ASYLO_ASSERT_OK_AND_ASSIGN(tcb_info, TcbInfoFromJson(JsonToString(json)));
  ASYLO_ASSERT_OK(ValidateTcbInfo(tcb_info));
  EXPECT_THAT(tcb_info.impl().pce_id().value(), Eq(0x0123));
}

TEST(TcbInfoFromJsonTest,
     TcbLevelJsonWithDifferentKnownStatusValuesParseSuccessfully) {
  constexpr absl::string_view kKnownStatusStrings[] = {
      "UpToDate", "ConfigurationNeeded", "OutOfDate", "Revoked"};
  constexpr TcbStatus::StatusType kKnownStatusValues[] = {
      TcbStatus::UP_TO_DATE, TcbStatus::CONFIGURATION_NEEDED,
      TcbStatus::OUT_OF_DATE, TcbStatus::REVOKED};

  google::protobuf::Value json = CreateValidTcbInfoJson();
  TcbInfo tcb_info;

  for (int i = 0; i < ABSL_ARRAYSIZE(kKnownStatusValues); ++i) {
    json.mutable_struct_value()
        ->mutable_fields()
        ->at("tcbLevels")
        .mutable_list_value()
        ->mutable_values(0)
        ->mutable_struct_value()
        ->mutable_fields()
        ->at("status")
        .set_string_value(kKnownStatusStrings[i].data(),
                          kKnownStatusStrings[i].size());

    ASYLO_ASSERT_OK_AND_ASSIGN(tcb_info, TcbInfoFromJson(JsonToString(json)));
    ASYLO_ASSERT_OK(ValidateTcbInfo(tcb_info));
    const TcbStatus &tcb_status = tcb_info.impl().tcb_levels(0).status();
    ASSERT_THAT(tcb_status.value_case(), Eq(TcbStatus::kKnownStatus));
    EXPECT_THAT(tcb_status.known_status(), Eq(kKnownStatusValues[i]));
  }
}

TEST(TcbInfoFromJsonTest,
     TcbLevelJsonWithRepeatedTcbLevelsIsDeduplicatedAndCausesLogWarning) {
  google::protobuf::Value json = CreateValidTcbInfoJson();
  google::protobuf::ListValue *tcb_levels = json.mutable_struct_value()
                                                ->mutable_fields()
                                                ->at("tcbLevels")
                                                .mutable_list_value();
  *tcb_levels->add_values() = tcb_levels->values(0);

  TcbInfo tcb_info;
  OutputCollector warning_collector(kCollectStdout);
  ASYLO_ASSERT_OK_AND_ASSIGN(tcb_info, TcbInfoFromJson(JsonToString(json)));
  ASYLO_ASSERT_OK(ValidateTcbInfo(tcb_info));
  EXPECT_THAT(tcb_info.impl().tcb_levels(), SizeIs(1));
  EXPECT_THAT(warning_collector.CollectOutputSoFar(),
              IsOkAndHolds(ContainsRegex(kLogWarningRegex)));
}

TEST(TcbInfoFromJsonTest, TcbInfoJsonWithExtraFieldsCausesLogWarning) {
  google::protobuf::Value json = CreateValidTcbInfoJson();
  google::protobuf::Value value;
  value.set_number_value(0.);
  json.mutable_struct_value()->mutable_fields()->insert({"veryExtra", value});

  TcbInfo tcb_info;
  OutputCollector warning_collector(kCollectStdout);
  ASYLO_ASSERT_OK_AND_ASSIGN(tcb_info, TcbInfoFromJson(JsonToString(json)));
  ASYLO_ASSERT_OK(ValidateTcbInfo(tcb_info));
  EXPECT_THAT(warning_collector.CollectOutputSoFar(),
              IsOkAndHolds(ContainsRegex(kLogWarningRegex)));
}

TEST(TcbInfoFromJsonTest, TcbLevelJsonWithExtraFieldsCausesLogWarning) {
  google::protobuf::Value json = CreateValidTcbInfoJson();
  google::protobuf::Value value;
  value.set_number_value(0.);
  json.mutable_struct_value()
      ->mutable_fields()
      ->at("tcbLevels")
      .mutable_list_value()
      ->mutable_values(0)
      ->mutable_struct_value()
      ->mutable_fields()
      ->insert({"veryExtra", value});

  TcbInfo tcb_info;
  OutputCollector warning_collector(kCollectStdout);
  ASYLO_ASSERT_OK_AND_ASSIGN(tcb_info, TcbInfoFromJson(JsonToString(json)));
  ASYLO_ASSERT_OK(ValidateTcbInfo(tcb_info));
  EXPECT_THAT(warning_collector.CollectOutputSoFar(),
              IsOkAndHolds(ContainsRegex(kLogWarningRegex)));
}

TEST(TcbInfoFromJsonTest, TcbJsonWithExtraFieldsCausesLogWarning) {
  google::protobuf::Value json = CreateValidTcbInfoJson();
  google::protobuf::Value value;
  value.set_number_value(0.);
  json.mutable_struct_value()
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
  ASYLO_ASSERT_OK_AND_ASSIGN(tcb_info, TcbInfoFromJson(JsonToString(json)));
  ASYLO_ASSERT_OK(ValidateTcbInfo(tcb_info));
  EXPECT_THAT(warning_collector.CollectOutputSoFar(),
              IsOkAndHolds(ContainsRegex(kLogWarningRegex)));
}

}  // namespace
}  // namespace sgx
}  // namespace asylo
