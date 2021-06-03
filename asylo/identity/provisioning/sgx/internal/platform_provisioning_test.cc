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

#include "asylo/identity/provisioning/sgx/internal/platform_provisioning.h"

#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/status/status.h"
#include "asylo/crypto/util/bytes.h"
#include "asylo/crypto/util/trivial_object_util.h"
#include "asylo/identity/platform/sgx/internal/identity_key_management_structs.h"
#include "asylo/identity/provisioning/sgx/internal/platform_provisioning.pb.h"
#include "asylo/test/util/proto_matchers.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status.h"

namespace asylo {
namespace sgx {
namespace {

using ::testing::Eq;

TEST(ProvisioningPlatformTest, ConfigurationIdWithoutValueFieldIsInvalid) {
  EXPECT_THAT(ValidateConfigurationId(ConfigurationId()),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(ProvisioningPlatformTest, ValidConfigurationIdIsValid) {
  ConfigurationId id;
  id.set_value(1000);
  ASYLO_EXPECT_OK(ValidateConfigurationId(id));
}

TEST(PlatformProvisioningTest, PpidWithoutValueFieldIsInvalid) {
  EXPECT_THAT(ValidatePpid(Ppid()),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PlatformProvisioningTest, PpidWithValueFieldOfBadLengthIsInvalid) {
  Ppid ppid;
  *ppid.mutable_value() = "short";
  EXPECT_THAT(ValidatePpid(ppid), StatusIs(absl::StatusCode::kInvalidArgument));

  *ppid.mutable_value() = "waaaaaaaaaaaaaaaaaaaaaaaaaaytoolong";
  EXPECT_THAT(ValidatePpid(ppid), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PlatformProvisioningTest, ValidPpidIsValid) {
  Ppid ppid;
  *ppid.mutable_value() = "0123456789abcdef";
  ASYLO_EXPECT_OK(ValidatePpid(ppid));
}

TEST(PlatformProvisioningTest, CpuSvnWithoutValueFieldIsInvalid) {
  EXPECT_THAT(ValidateCpuSvn(CpuSvn()),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PlatformProvisioningTest, CpuSvnWithValueFieldOfBadLengthIsInvalid) {
  CpuSvn cpu_svn;
  *cpu_svn.mutable_value() = "short";
  EXPECT_THAT(ValidateCpuSvn(cpu_svn),
              StatusIs(absl::StatusCode::kInvalidArgument));

  *cpu_svn.mutable_value() = "waaaaaaaaaaaaaaaaaaaaaaaaaaytoolong";
  EXPECT_THAT(ValidateCpuSvn(cpu_svn),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PlatformProvisioningTest, ValidCpuSvnIsValid) {
  CpuSvn cpu_svn;
  *cpu_svn.mutable_value() = "0123456789abcdef";
  ASYLO_EXPECT_OK(ValidateCpuSvn(cpu_svn));
}

TEST(PlatformProvisioningTest, PceSvnWithoutValueFieldIsInvalid) {
  EXPECT_THAT(ValidatePceSvn(PceSvn()),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PlatformProvisioningTest, PceSvnWithTooLargeValueFieldIsInvalid) {
  PceSvn pce_svn;
  pce_svn.set_value(100000);
  EXPECT_THAT(ValidatePceSvn(pce_svn),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PlatformProvisioningTest, ValidPceSvnIsValid) {
  PceSvn pce_svn;
  pce_svn.set_value(10000);
  ASYLO_EXPECT_OK(ValidatePceSvn(pce_svn));
}

TEST(PlatformProvisioningTest, PceIdWithoutValueFieldIsInvalid) {
  EXPECT_THAT(ValidatePceId(PceId()),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PlatformProvisioningTest, PceIdWithTooLargeValueFieldIsInvalid) {
  PceId pce_id;
  pce_id.set_value(100000);
  EXPECT_THAT(ValidatePceId(pce_id),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PlatformProvisioningTest, ValidPceIdIsValid) {
  PceId pce_id;
  pce_id.set_value(10000);
  ASYLO_EXPECT_OK(ValidatePceId(pce_id));
}

TEST(PlatformProvisioningTest, FmspcWithoutValueFieldIsInvalid) {
  EXPECT_THAT(ValidateFmspc(Fmspc()),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PlatformProvisioningTest, FmspcWithValueFieldOfBadLengthIsInvalid) {
  Fmspc fmspc;
  fmspc.set_value("short");
  EXPECT_THAT(ValidateFmspc(fmspc),
              StatusIs(absl::StatusCode::kInvalidArgument));

  fmspc.set_value("toolong");
  EXPECT_THAT(ValidateFmspc(fmspc),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PlatformProvisioningTest, ValidFmspcIsValid) {
  Fmspc fmspc;
  fmspc.set_value("000000");
  ASYLO_EXPECT_OK(ValidateFmspc(fmspc));
}

TEST(PlatformProvisioningTest, ReportProtoWithoutValueFieldIsInvalid) {
  ReportProto report_proto;
  EXPECT_THAT(ValidateReportProto(report_proto),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(ConvertReportProtoToHardwareReport(report_proto),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PlatformProvisioningTest, ReportProtoWithValueFieldOfBadLengthIsInvalid) {
  ReportProto report_proto;
  report_proto.set_value("short");
  EXPECT_THAT(ValidateReportProto(report_proto),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(ConvertReportProtoToHardwareReport(report_proto),
              StatusIs(absl::StatusCode::kInvalidArgument));

  Report report = TrivialRandomObject<Report>();
  std::string report_bin = ConvertTrivialObjectToBinaryString(report);
  // One byte too long.
  report_bin.push_back('a');
  report_proto.set_value(report_bin);
  EXPECT_THAT(ValidateReportProto(report_proto),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(ConvertReportProtoToHardwareReport(report_proto),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PlatformProvisioningTest, TargetInfoProtoWithoutValueFieldIsInvalid) {
  TargetInfoProto target_info_proto;
  EXPECT_THAT(ValidateTargetInfoProto(target_info_proto),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(ConvertTargetInfoProtoToTargetinfo(target_info_proto),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PlatformProvisioningTest,
     TargetInfoProtoWithValueFieldOfBadLengthIsInvalid) {
  TargetInfoProto target_info_proto;
  target_info_proto.set_value("short");
  EXPECT_THAT(ValidateTargetInfoProto(target_info_proto),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(ConvertTargetInfoProtoToTargetinfo(target_info_proto),
              StatusIs(absl::StatusCode::kInvalidArgument));

  Targetinfo targetinfo = TrivialRandomObject<Targetinfo>();
  std::string targetinfo_bin = ConvertTrivialObjectToBinaryString(targetinfo);
  // One byte too long.
  targetinfo_bin.push_back('a');
  target_info_proto.set_value(targetinfo_bin);
  EXPECT_THAT(ValidateTargetInfoProto(target_info_proto),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(ConvertTargetInfoProtoToTargetinfo(target_info_proto),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PlatformProvisioningTest, ValidReportCanBeConvertedToHardwareReport) {
  Report expected = TrivialRandomObject<Report>();

  ReportProto report_proto;
  report_proto.set_value(ConvertTrivialObjectToBinaryString(expected));

  auto report_result = ConvertReportProtoToHardwareReport(report_proto);
  ASYLO_ASSERT_OK(report_result);

  std::string expected_hex = ConvertTrivialObjectToHexString<Report>(expected);
  std::string actual_hex =
      ConvertTrivialObjectToHexString(report_result.value());
  EXPECT_THAT(actual_hex, Eq(expected_hex));
}

TEST(PlatformProvisioningTest, ValidTargetInfoProtoCanBeConvertedToTargetinfo) {
  Targetinfo expected = TrivialRandomObject<Targetinfo>();

  TargetInfoProto target_info_proto;
  target_info_proto.set_value(ConvertTrivialObjectToBinaryString(expected));

  auto targetinfo_result =
      ConvertTargetInfoProtoToTargetinfo(target_info_proto);
  ASYLO_ASSERT_OK(targetinfo_result);

  std::string expected_hex =
      ConvertTrivialObjectToHexString<Targetinfo>(expected);
  std::string actual_hex =
      ConvertTrivialObjectToHexString(targetinfo_result.value());
  EXPECT_THAT(actual_hex, Eq(expected_hex));
}

TEST(PlatformProvisioningTest, CpuSvnFromReportProtoSuccess) {
  const std::string kCpusvn = "123456abcdef1234";

  Report report;
  report.body.cpusvn = kCpusvn;

  ReportProto report_proto;
  report_proto.set_value(ConvertTrivialObjectToBinaryString(report));

  CpuSvn expected_cpu_svn;
  expected_cpu_svn.set_value(kCpusvn);

  EXPECT_THAT(CpuSvnFromReportProto(report_proto),
              IsOkAndHolds(EqualsProto(expected_cpu_svn)));
}

TEST(PlatformProvisioningTest, CpuSvnFromReportProtoFailure) {
  ReportProto bad_report;
  bad_report.set_value("abc");

  EXPECT_THAT(CpuSvnFromReportProto(bad_report),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace
}  // namespace sgx
}  // namespace asylo
