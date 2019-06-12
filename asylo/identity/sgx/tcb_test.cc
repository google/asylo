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

#include <tuple>

#include "google/protobuf/timestamp.pb.h"
#include <gtest/gtest.h>
#include "absl/base/macros.h"
#include "absl/strings/string_view.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "asylo/identity/sgx/platform_provisioning.pb.h"
#include "asylo/identity/sgx/tcb.pb.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status.h"

namespace asylo {
namespace sgx {
namespace {

using ::testing::Eq;

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

// Returns a valid TcbInfo message with a single TCB level.
TcbInfo CreateValidTcbInfo() {
  absl::Time now = absl::Now();
  absl::Time later = now + absl::Hours(24 * 30);

  TcbInfo tcb_info;
  TcbInfoImpl *impl = tcb_info.mutable_impl();
  impl->set_version(1);

  google::protobuf::Timestamp *issue_date = impl->mutable_issue_date();
  issue_date->set_seconds((now - absl::UnixEpoch()) / absl::Seconds(1));
  issue_date->set_nanos(0);

  google::protobuf::Timestamp *next_update = impl->mutable_next_update();
  next_update->set_seconds((later - absl::UnixEpoch()) / absl::Seconds(1));
  next_update->set_nanos(0);

  impl->mutable_fmspc()->set_value("abcdef");
  impl->mutable_pce_id()->set_value(0);

  TcbLevel *tcb_level = impl->add_tcb_levels();
  *tcb_level->mutable_tcb() = CreateValidTcb();
  tcb_level->mutable_status()->set_known_status(TcbStatus::UP_TO_DATE);

  return tcb_info;
}

TEST(TcbTest, TcbWithoutComponentsFieldIsInvalid) {
  Tcb tcb = CreateValidTcb();
  tcb.clear_components();
  EXPECT_THAT(ValidateTcb(tcb), StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbTest, TcbWithoutPceSvnFieldIsInvalid) {
  Tcb tcb = CreateValidTcb();
  tcb.clear_pce_svn();
  EXPECT_THAT(ValidateTcb(tcb), StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbTest, TcbWithComponentsFieldOfBadLengthIsInvalid) {
  Tcb tcb = CreateValidTcb();
  tcb.set_components("short");
  EXPECT_THAT(ValidateTcb(tcb), StatusIs(error::GoogleError::INVALID_ARGUMENT));

  tcb.set_components("waaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaytoolong");
  EXPECT_THAT(ValidateTcb(tcb), StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbTest, TcbWithInvalidPceSvnFieldIsInvalid) {
  Tcb tcb = CreateValidTcb();
  tcb.mutable_pce_svn()->clear_value();
  EXPECT_THAT(ValidateTcb(tcb), StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbTest, ValidTcbIsValid) {
  ASYLO_EXPECT_OK(ValidateTcb(CreateValidTcb()));
}

TEST(TcbTest, RawTcbWithoutCpuSvnFieldIsInvalid) {
  RawTcb raw_tcb = CreateValidRawTcb();
  raw_tcb.clear_cpu_svn();
  EXPECT_THAT(ValidateRawTcb(raw_tcb),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbTest, RawTcbWithoutPceSvnFieldIsInvalid) {
  RawTcb raw_tcb = CreateValidRawTcb();
  raw_tcb.clear_pce_svn();
  EXPECT_THAT(ValidateRawTcb(raw_tcb),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbTest, RawTcbWithInvalidCpuSvnFieldIsInvalid) {
  RawTcb raw_tcb = CreateValidRawTcb();
  raw_tcb.mutable_cpu_svn()->clear_value();
  EXPECT_THAT(ValidateRawTcb(raw_tcb),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbTest, RawTcbWithInvalidPceSvnFieldIsInvalid) {
  RawTcb raw_tcb = CreateValidRawTcb();
  raw_tcb.mutable_pce_svn()->clear_value();
  EXPECT_THAT(ValidateRawTcb(raw_tcb),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbTest, ValidRawTcbIsValid) {
  ASYLO_EXPECT_OK(ValidateRawTcb(CreateValidRawTcb()));
}

TEST(TcbTest, TcbInfoWithoutValueVariantIsInvalid) {
  EXPECT_THAT(ValidateTcbInfo(TcbInfo()),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbTest, TcbInfoImplWithoutVersionFieldIsInvalid) {
  TcbInfo tcb_info = CreateValidTcbInfo();
  tcb_info.mutable_impl()->clear_version();
  EXPECT_THAT(ValidateTcbInfo(tcb_info),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbTest, TcbInfoImplWithoutIssueDateFieldIsInvalid) {
  TcbInfo tcb_info = CreateValidTcbInfo();
  tcb_info.mutable_impl()->clear_issue_date();
  EXPECT_THAT(ValidateTcbInfo(tcb_info),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbTest, TcbInfoImplWithoutNextUpdateFieldIsInvalid) {
  TcbInfo tcb_info = CreateValidTcbInfo();
  tcb_info.mutable_impl()->clear_next_update();
  EXPECT_THAT(ValidateTcbInfo(tcb_info),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbTest, TcbInfoImplWithoutFmspcFieldIsInvalid) {
  TcbInfo tcb_info = CreateValidTcbInfo();
  tcb_info.mutable_impl()->clear_fmspc();
  EXPECT_THAT(ValidateTcbInfo(tcb_info),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbTest, TcbInfoImplWithoutPceIdFieldIsInvalid) {
  TcbInfo tcb_info = CreateValidTcbInfo();
  tcb_info.mutable_impl()->clear_pce_id();
  EXPECT_THAT(ValidateTcbInfo(tcb_info),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbTest, TcbInfoImplWithUnknownVersionIsInvalid) {
  TcbInfo tcb_info = CreateValidTcbInfo();
  tcb_info.mutable_impl()->set_version(12);
  EXPECT_THAT(ValidateTcbInfo(tcb_info),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbTest, TcbInfoImplWithInvalidIssueDateIsInvalid) {
  TcbInfo tcb_info = CreateValidTcbInfo();
  tcb_info.mutable_impl()->mutable_issue_date()->set_seconds(-100000000000);
  EXPECT_THAT(ValidateTcbInfo(tcb_info),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbTest, TcbInfoImplWithInvalidNextUpdateIsInvalid) {
  TcbInfo tcb_info = CreateValidTcbInfo();
  tcb_info.mutable_impl()->mutable_next_update()->set_seconds(-100000000000);
  EXPECT_THAT(ValidateTcbInfo(tcb_info),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbTest, TcbInfoImplWithInvalidFmspcIsInvalid) {
  TcbInfo tcb_info = CreateValidTcbInfo();
  tcb_info.mutable_impl()->mutable_fmspc()->clear_value();
  EXPECT_THAT(ValidateTcbInfo(tcb_info),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbTest, TcbInfoImplWithInvalidPceIdIsInvalid) {
  TcbInfo tcb_info = CreateValidTcbInfo();
  tcb_info.mutable_impl()->mutable_pce_id()->clear_value();
  EXPECT_THAT(ValidateTcbInfo(tcb_info),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbTest, TcbLevelWithoutTcbFieldIsInvalid) {
  TcbInfo tcb_info = CreateValidTcbInfo();
  tcb_info.mutable_impl()->mutable_tcb_levels(0)->clear_tcb();
  EXPECT_THAT(ValidateTcbInfo(tcb_info),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbTest, TcbLevelWithoutStatusFieldIsInvalid) {
  TcbInfo tcb_info = CreateValidTcbInfo();
  tcb_info.mutable_impl()->mutable_tcb_levels(0)->clear_status();
  EXPECT_THAT(ValidateTcbInfo(tcb_info),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbTest, TcbLevelWithInvalidTcbIsInvalid) {
  TcbInfo tcb_info = CreateValidTcbInfo();
  tcb_info.mutable_impl()
      ->mutable_tcb_levels(0)
      ->mutable_tcb()
      ->clear_pce_svn();
  EXPECT_THAT(ValidateTcbInfo(tcb_info),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbTest, TcbStatusWithoutValueVariantIsInvalid) {
  TcbInfo tcb_info = CreateValidTcbInfo();
  tcb_info.mutable_impl()
      ->mutable_tcb_levels(0)
      ->mutable_status()
      ->clear_value();
  EXPECT_THAT(ValidateTcbInfo(tcb_info),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbTest, TcbStatusWithUnknownKnownStatusVariantIsInvalid) {
  TcbInfo tcb_info = CreateValidTcbInfo();
  tcb_info.mutable_impl()
      ->mutable_tcb_levels(0)
      ->mutable_status()
      ->set_known_status(TcbStatus::INVALID);
  EXPECT_THAT(ValidateTcbInfo(tcb_info),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbTest,
     TcbInfoImplWithMultipleTcbLevelsWithSameTcbButDifferentStatusesIsInvalid) {
  TcbInfo tcb_info = CreateValidTcbInfo();
  *tcb_info.mutable_impl()->add_tcb_levels() = tcb_info.impl().tcb_levels(0);
  tcb_info.mutable_impl()
      ->mutable_tcb_levels(1)
      ->mutable_status()
      ->set_known_status(TcbStatus::OUT_OF_DATE);
  EXPECT_THAT(ValidateTcbInfo(tcb_info),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(TcbTest, ValidTcbInfoIsValid) {
  ASYLO_EXPECT_OK(ValidateTcbInfo(CreateValidTcbInfo()));
}

TEST(TcbTest,
     TcbInfoImplWithMultipleTcbLevelsWithSameTcbAnsSameStatusesIsValid) {
  TcbInfo tcb_info = CreateValidTcbInfo();
  *tcb_info.mutable_impl()->add_tcb_levels() = tcb_info.impl().tcb_levels(0);
  ASYLO_EXPECT_OK(ValidateTcbInfo(tcb_info));
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
    EXPECT_THAT(CompareTcbs(lhs, rhs), Eq(std::get<2>(test_cases[i])));
  }
}

}  // namespace
}  // namespace sgx
}  // namespace asylo
