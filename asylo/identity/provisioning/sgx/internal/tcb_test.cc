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

#include <tuple>
#include <vector>

#include "google/protobuf/timestamp.pb.h"
#include <gtest/gtest.h>
#include "absl/base/macros.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "absl/types/span.h"
#include "asylo/util/logging.h"
#include "asylo/identity/platform/sgx/machine_configuration.pb.h"
#include "asylo/identity/provisioning/sgx/internal/platform_provisioning.pb.h"
#include "asylo/identity/provisioning/sgx/internal/tcb.pb.h"
#include "asylo/test/util/proto_matchers.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status.h"

namespace asylo {
namespace sgx {
namespace {

// Returns a valid Tcb message.
Tcb CreateValidTcb() {
  Tcb tcb;
  tcb.set_components("0123456789abcdef");
  tcb.mutable_pce_svn()->set_value(7);
  return tcb;
}

// Returns a valid RawTcb message.
RawTcb CreateValidRawTcb() {
  RawTcb raw_tcb;
  raw_tcb.mutable_cpu_svn()->set_value("0123456789abcdef");
  raw_tcb.mutable_pce_svn()->set_value(7);
  return raw_tcb;
}

// Returns a valid TcbInfo message at version 1 with a single TCB level.
TcbInfo CreateValidTcbInfoV1() {
  absl::Time now = absl::Now();
  absl::Time later = now + absl::Hours(24 * 30);

  TcbInfo tcb_info;
  TcbInfoImpl *impl = tcb_info.mutable_impl();
  impl->set_version(1);

  google::protobuf::Timestamp *issue_date = impl->mutable_issue_date();
  issue_date->set_seconds(absl::ToInt64Seconds(now - absl::UnixEpoch()));
  issue_date->set_nanos(0);

  google::protobuf::Timestamp *next_update = impl->mutable_next_update();
  next_update->set_seconds(absl::ToInt64Seconds(later - absl::UnixEpoch()));
  next_update->set_nanos(0);

  impl->mutable_fmspc()->set_value("abcdef");
  impl->mutable_pce_id()->set_value(0);

  TcbLevel *tcb_level = impl->add_tcb_levels();
  *tcb_level->mutable_tcb() = CreateValidTcb();
  tcb_level->mutable_status()->set_known_status(TcbStatus::UP_TO_DATE);

  return tcb_info;
}

// Returns a valid TcbInfo message at version 2 with a single TCB level.
TcbInfo CreateValidTcbInfoV2() {
  TcbInfo tcb_info = CreateValidTcbInfoV1();
  TcbInfoImpl *impl = tcb_info.mutable_impl();
  impl->set_version(2);
  impl->set_tcb_type(TcbType::TCB_TYPE_0);
  impl->set_tcb_evaluation_data_number(17);

  TcbLevel *tcb_level = impl->mutable_tcb_levels(0);
  google::protobuf::Timestamp *tcb_date = tcb_level->mutable_tcb_date();
  tcb_date->set_seconds(absl::ToInt64Seconds(absl::Now() - absl::UnixEpoch()));
  tcb_date->set_nanos(0);
  *tcb_level->add_advisory_ids() = "Vulnerable to flattery";

  return tcb_info;
}

// Returns a valid TcbInfo message of each version in |versions|.
std::vector<TcbInfo> CreateTcbInfosOfVersions(absl::Span<const int> versions) {
  std::vector<TcbInfo> tcb_infos;
  for (int version : versions) {
    switch (version) {
      case 1:
        tcb_infos.push_back(CreateValidTcbInfoV1());
        break;
      case 2:
        tcb_infos.push_back(CreateValidTcbInfoV2());
        break;
      default:
        LOG(FATAL) << "Unknown TCB info version: " << version;
    }
  }
  return tcb_infos;
}

TEST(TcbTest, TcbWithoutComponentsFieldIsInvalid) {
  Tcb tcb = CreateValidTcb();
  tcb.clear_components();
  EXPECT_THAT(ValidateTcb(tcb), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(TcbTest, TcbWithoutPceSvnFieldIsInvalid) {
  Tcb tcb = CreateValidTcb();
  tcb.clear_pce_svn();
  EXPECT_THAT(ValidateTcb(tcb), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(TcbTest, TcbWithComponentsFieldOfBadLengthIsInvalid) {
  Tcb tcb = CreateValidTcb();
  tcb.set_components("short");
  EXPECT_THAT(ValidateTcb(tcb), StatusIs(absl::StatusCode::kInvalidArgument));

  tcb.set_components("waaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaytoolong");
  EXPECT_THAT(ValidateTcb(tcb), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(TcbTest, TcbWithInvalidPceSvnFieldIsInvalid) {
  Tcb tcb = CreateValidTcb();
  tcb.mutable_pce_svn()->clear_value();
  EXPECT_THAT(ValidateTcb(tcb), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(TcbTest, ValidTcbIsValid) {
  ASYLO_EXPECT_OK(ValidateTcb(CreateValidTcb()));
}

TEST(TcbTest, RawTcbWithoutCpuSvnFieldIsInvalid) {
  RawTcb raw_tcb = CreateValidRawTcb();
  raw_tcb.clear_cpu_svn();
  EXPECT_THAT(ValidateRawTcb(raw_tcb),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(TcbTest, RawTcbWithoutPceSvnFieldIsInvalid) {
  RawTcb raw_tcb = CreateValidRawTcb();
  raw_tcb.clear_pce_svn();
  EXPECT_THAT(ValidateRawTcb(raw_tcb),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(TcbTest, RawTcbWithInvalidCpuSvnFieldIsInvalid) {
  RawTcb raw_tcb = CreateValidRawTcb();
  raw_tcb.mutable_cpu_svn()->clear_value();
  EXPECT_THAT(ValidateRawTcb(raw_tcb),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(TcbTest, RawTcbWithInvalidPceSvnFieldIsInvalid) {
  RawTcb raw_tcb = CreateValidRawTcb();
  raw_tcb.mutable_pce_svn()->clear_value();
  EXPECT_THAT(ValidateRawTcb(raw_tcb),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(TcbTest, ValidRawTcbIsValid) {
  ASYLO_EXPECT_OK(ValidateRawTcb(CreateValidRawTcb()));
}

TEST(TcbTest, TcbInfoWithoutValueVariantIsInvalid) {
  EXPECT_THAT(ValidateTcbInfo(TcbInfo()),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(TcbTest, TcbInfoImplWithoutVersionFieldIsInvalid) {
  for (auto &tcb_info : CreateTcbInfosOfVersions({1, 2})) {
    tcb_info.mutable_impl()->clear_version();
    EXPECT_THAT(ValidateTcbInfo(tcb_info),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbTest, TcbInfoImplWithoutIssueDateFieldIsInvalid) {
  for (auto &tcb_info : CreateTcbInfosOfVersions({1, 2})) {
    tcb_info.mutable_impl()->clear_issue_date();
    EXPECT_THAT(ValidateTcbInfo(tcb_info),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbTest, TcbInfoImplWithoutNextUpdateFieldIsInvalid) {
  for (auto &tcb_info : CreateTcbInfosOfVersions({1, 2})) {
    tcb_info.mutable_impl()->clear_issue_date();
    EXPECT_THAT(ValidateTcbInfo(tcb_info),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbTest, TcbInfoImplWithoutFmspcFieldIsInvalid) {
  for (auto &tcb_info : CreateTcbInfosOfVersions({1, 2})) {
    tcb_info.mutable_impl()->clear_fmspc();
    EXPECT_THAT(ValidateTcbInfo(tcb_info),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbTest, TcbInfoImplWithoutPceIdFieldIsInvalid) {
  for (auto &tcb_info : CreateTcbInfosOfVersions({1, 2})) {
    tcb_info.mutable_impl()->clear_pce_id();
    EXPECT_THAT(ValidateTcbInfo(tcb_info),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbTest, TcbInfoImplV1WithTcbTypeFieldIsInvalid) {
  TcbInfo tcb_info = CreateValidTcbInfoV1();
  tcb_info.mutable_impl()->set_tcb_type(TcbType::TCB_TYPE_0);
  EXPECT_THAT(ValidateTcbInfo(tcb_info),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(TcbTest, TcbInfoImplV2WithoutTcbTypeFieldIsInvalid) {
  TcbInfo tcb_info = CreateValidTcbInfoV2();
  tcb_info.mutable_impl()->clear_tcb_type();
  EXPECT_THAT(ValidateTcbInfo(tcb_info),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(TcbTest, TcbInfoImplV2WithInvalidTcbTypeFieldIsInvalid) {
  TcbInfo tcb_info = CreateValidTcbInfoV2();
  tcb_info.mutable_impl()->set_tcb_type(TcbType::TCB_TYPE_UNKNOWN);
  EXPECT_THAT(ValidateTcbInfo(tcb_info),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(TcbTest, TcbInfoImplV1WithTcbDataEvaluationNumberFieldIsInvalid) {
  TcbInfo tcb_info = CreateValidTcbInfoV1();
  tcb_info.mutable_impl()->set_tcb_evaluation_data_number(16);
  EXPECT_THAT(ValidateTcbInfo(tcb_info),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(TcbTest, TcbInfoImplV2WithoutTcbDataEvaluationNumberFieldIsInvalid) {
  TcbInfo tcb_info = CreateValidTcbInfoV2();
  tcb_info.mutable_impl()->clear_tcb_evaluation_data_number();
  EXPECT_THAT(ValidateTcbInfo(tcb_info),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(TcbTest, TcbInfoImplWithUnknownVersionIsInvalid) {
  for (auto &tcb_info : CreateTcbInfosOfVersions({1, 2})) {
    tcb_info.mutable_impl()->set_version(12);
    EXPECT_THAT(ValidateTcbInfo(tcb_info),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbTest, TcbInfoImplWithInvalidIssueDateIsInvalid) {
  for (auto &tcb_info : CreateTcbInfosOfVersions({1, 2})) {
    tcb_info.mutable_impl()->mutable_issue_date()->set_seconds(-100000000000);
    EXPECT_THAT(ValidateTcbInfo(tcb_info),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbTest, TcbInfoImplWithInvalidNextUpdateIsInvalid) {
  for (auto &tcb_info : CreateTcbInfosOfVersions({1, 2})) {
    tcb_info.mutable_impl()->mutable_next_update()->set_seconds(-100000000000);
    EXPECT_THAT(ValidateTcbInfo(tcb_info),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbTest, TcbInfoImplWithInvalidFmspcIsInvalid) {
  for (auto &tcb_info : CreateTcbInfosOfVersions({1, 2})) {
    tcb_info.mutable_impl()->mutable_fmspc()->clear_value();
    EXPECT_THAT(ValidateTcbInfo(tcb_info),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbTest, TcbInfoImplWithInvalidPceIdIsInvalid) {
  for (auto &tcb_info : CreateTcbInfosOfVersions({1, 2})) {
    tcb_info.mutable_impl()->mutable_pce_id()->clear_value();
    EXPECT_THAT(ValidateTcbInfo(tcb_info),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbTest, TcbLevelWithoutTcbFieldIsInvalid) {
  for (auto &tcb_info : CreateTcbInfosOfVersions({1, 2})) {
    tcb_info.mutable_impl()->mutable_tcb_levels(0)->clear_tcb();
    EXPECT_THAT(ValidateTcbInfo(tcb_info),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbTest, TcbLevelInV1TcbInfoWithTcbDateFieldIsInvalid) {
  TcbInfo tcb_info = CreateValidTcbInfoV1();
  google::protobuf::Timestamp *tcb_date =
      tcb_info.mutable_impl()->mutable_tcb_levels(0)->mutable_tcb_date();
  tcb_date->set_seconds(absl::ToInt64Seconds(absl::Now() - absl::UnixEpoch()));
  tcb_date->set_nanos(0);
  EXPECT_THAT(ValidateTcbInfo(tcb_info),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(TcbTest, TcbLevelInV2TcbInfoWithoutTcbDateFieldIsInvalid) {
  TcbInfo tcb_info = CreateValidTcbInfoV2();
  tcb_info.mutable_impl()->mutable_tcb_levels(0)->clear_tcb_date();
  EXPECT_THAT(ValidateTcbInfo(tcb_info),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(TcbTest, TcbLevelInV1TcbInfoWithNonEmptyAdvisoryIdsIsInvalid) {
  TcbInfo tcb_info = CreateValidTcbInfoV1();
  *tcb_info.mutable_impl()->mutable_tcb_levels(0)->add_advisory_ids() =
      "This shouldn't be here";
  EXPECT_THAT(ValidateTcbInfo(tcb_info),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(TcbTest, TcbLevelWithoutStatusFieldIsInvalid) {
  for (auto &tcb_info : CreateTcbInfosOfVersions({1, 2})) {
    tcb_info.mutable_impl()->mutable_tcb_levels(0)->clear_status();
    EXPECT_THAT(ValidateTcbInfo(tcb_info),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbTest, TcbLevelWithInvalidTcbIsInvalid) {
  for (auto &tcb_info : CreateTcbInfosOfVersions({1, 2})) {
    tcb_info.mutable_impl()
        ->mutable_tcb_levels(0)
        ->mutable_tcb()
        ->clear_pce_svn();
    EXPECT_THAT(ValidateTcbInfo(tcb_info),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbTest, TcbStatusWithoutValueVariantIsInvalid) {
  for (auto &tcb_info : CreateTcbInfosOfVersions({1, 2})) {
    tcb_info.mutable_impl()
        ->mutable_tcb_levels(0)
        ->mutable_status()
        ->clear_value();
    EXPECT_THAT(ValidateTcbInfo(tcb_info),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbTest, TcbStatusWithUnknownKnownStatusVariantIsInvalid) {
  for (auto &tcb_info : CreateTcbInfosOfVersions({1, 2})) {
    tcb_info.mutable_impl()
        ->mutable_tcb_levels(0)
        ->mutable_status()
        ->set_known_status(TcbStatus::INVALID);
    EXPECT_THAT(ValidateTcbInfo(tcb_info),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbTest,
     TcbInfoImplWithMultipleTcbLevelsWithSameTcbButDifferentStatusesIsInvalid) {
  for (auto &tcb_info : CreateTcbInfosOfVersions({1, 2})) {
    *tcb_info.mutable_impl()->add_tcb_levels() = tcb_info.impl().tcb_levels(0);
    tcb_info.mutable_impl()
        ->mutable_tcb_levels(1)
        ->mutable_status()
        ->set_known_status(TcbStatus::OUT_OF_DATE);
    EXPECT_THAT(ValidateTcbInfo(tcb_info),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TcbTest, ValidTcbInfoIsValid) {
  for (const auto &tcb_info : CreateTcbInfosOfVersions({1, 2})) {
    ASYLO_EXPECT_OK(ValidateTcbInfo(tcb_info));
  }
}

TEST(TcbTest,
     TcbInfoImplWithMultipleTcbLevelsWithSameTcbAnsSameStatusesIsValid) {
  for (auto &tcb_info : CreateTcbInfosOfVersions({1, 2})) {
    *tcb_info.mutable_impl()->add_tcb_levels() = tcb_info.impl().tcb_levels(0);
    ASYLO_EXPECT_OK(ValidateTcbInfo(tcb_info));
  }
}

TEST(TcbTest, CompareTcbsFailsWithUnknownTcbType) {
  EXPECT_THAT(CompareTcbs(TcbType::TCB_TYPE_UNKNOWN, CreateValidTcb(),
                          CreateValidTcb()),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(TcbTest, CompareTcbsComparesArgumentsCorrectly) {
  constexpr absl::string_view kBaseComponents = "0123456789abcdef";
  constexpr int kBasePceSvn = 5;

  constexpr absl::string_view kLessComponents = "0011223344556677";
  constexpr absl::string_view kEqualComponents = kBaseComponents;
  constexpr absl::string_view kGreaterComponents = "8899aabbccddeeff";
  constexpr absl::string_view kIncomparableComponents = "fedcba9876543210";

  constexpr int kLessPceSvn = 2;
  constexpr int kEqualPceSvn = kBasePceSvn;
  constexpr int kGreaterPceSvn = 8;

  const std::tuple<absl::string_view, int, PartialOrder> test_cases[12] = {
      std::make_tuple(kLessComponents, kLessPceSvn, PartialOrder::kLess),
      std::make_tuple(kLessComponents, kEqualPceSvn, PartialOrder::kLess),
      std::make_tuple(kLessComponents, kGreaterPceSvn,
                      PartialOrder::kIncomparable),
      std::make_tuple(kEqualComponents, kLessPceSvn, PartialOrder::kLess),
      std::make_tuple(kEqualComponents, kEqualPceSvn, PartialOrder::kEqual),
      std::make_tuple(kEqualComponents, kGreaterPceSvn, PartialOrder::kGreater),
      std::make_tuple(kGreaterComponents, kLessPceSvn,
                      PartialOrder::kIncomparable),
      std::make_tuple(kGreaterComponents, kEqualPceSvn, PartialOrder::kGreater),
      std::make_tuple(kGreaterComponents, kGreaterPceSvn,
                      PartialOrder::kGreater),
      std::make_tuple(kIncomparableComponents, kLessPceSvn,
                      PartialOrder::kIncomparable),
      std::make_tuple(kIncomparableComponents, kEqualPceSvn,
                      PartialOrder::kIncomparable),
      std::make_tuple(kIncomparableComponents, kGreaterPceSvn,
                      PartialOrder::kIncomparable)};

  Tcb rhs;
  rhs.set_components(kBaseComponents.data(), kBaseComponents.size());
  rhs.mutable_pce_svn()->set_value(kBasePceSvn);
  for (int i = 0; i < ABSL_ARRAYSIZE(test_cases); ++i) {
    Tcb lhs;
    absl::string_view components = std::get<0>(test_cases[i]);
    lhs.set_components(components.data(), components.size());
    lhs.mutable_pce_svn()->set_value(std::get<1>(test_cases[i]));
    EXPECT_THAT(CompareTcbs(TcbType::TCB_TYPE_0, lhs, rhs),
                IsOkAndHolds(std::get<2>(test_cases[i])));
  }
}

TEST(TcbTest, ParseRawTcbHex_ValidRawTcbHexParseSuccessfully) {
  RawTcb expected_raw_tcb;
  expected_raw_tcb.mutable_cpu_svn()->set_value(
      "\x01\x01\x02\x03\x04\x05\x06\x07"
      "\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f");
  expected_raw_tcb.mutable_pce_svn()->set_value(7);
  EXPECT_THAT(ParseRawTcbHex("010102030405060708090a0b0c0d0e0f0700"),
              asylo::IsOkAndHolds(EqualsProto(expected_raw_tcb)));
}

TEST(TcbTest, ParseRawTcbHex_NonHexStringFailsToParse) {
  EXPECT_THAT(ParseRawTcbHex("not a hex string"),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(TcbTest, ParseRawTcbHex_WrongSizedStringFailsToParse) {
  EXPECT_THAT(ParseRawTcbHex("1234567890"),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(TcbTest, TcbStatusToStringSucceedsOnUnknownStatuses) {
  TcbStatus status;
  status.set_unknown_status("");
  EXPECT_THAT(TcbStatusToString(status), IsOkAndHolds(""));

  status.set_unknown_status("foobar");
  EXPECT_THAT(TcbStatusToString(status), IsOkAndHolds("foobar"));
}

TEST(TcbTest, TcbStatusToStringSucceedsOnValidKnownStatusValues) {
  TcbStatus status;
  status.set_known_status(TcbStatus::UP_TO_DATE);
  EXPECT_THAT(TcbStatusToString(status), IsOkAndHolds("UpToDate"));

  status.set_known_status(TcbStatus::OUT_OF_DATE);
  EXPECT_THAT(TcbStatusToString(status), IsOkAndHolds("OutOfDate"));

  status.set_known_status(TcbStatus::CONFIGURATION_NEEDED);
  EXPECT_THAT(TcbStatusToString(status), IsOkAndHolds("ConfigurationNeeded"));

  status.set_known_status(TcbStatus::REVOKED);
  EXPECT_THAT(TcbStatusToString(status), IsOkAndHolds("Revoked"));
}

TEST(TcbTest, TcbStatusToStringFailsOnBadInputs) {
  TcbStatus status;
  EXPECT_THAT(TcbStatusToString(status),
              StatusIs(absl::StatusCode::kInvalidArgument));

  status.set_known_status(TcbStatus::INVALID);
  EXPECT_THAT(TcbStatusToString(status),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace
}  // namespace sgx
}  // namespace asylo
