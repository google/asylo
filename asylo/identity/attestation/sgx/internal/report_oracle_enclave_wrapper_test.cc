/*
 *
 * Copyright 2020 Asylo authors
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

#include "asylo/identity/attestation/sgx/internal/report_oracle_enclave_wrapper.h"

#include <memory>
#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/flags/flag.h"
#include "absl/status/status.h"
#include "asylo/crypto/util/trivial_object_util.h"
#include "asylo/identity/platform/sgx/internal/identity_key_management_structs.h"
#include "asylo/platform/primitives/sgx/sgx_error_matchers.h"
#include "asylo/test/util/memory_matchers.h"
#include "asylo/test/util/status_matchers.h"

ABSL_FLAG(std::string, report_oracle_enclave_path, "",
          "Path to the report oracle enclave binary.");

namespace asylo {
namespace sgx {
namespace {

constexpr char kReportOracleSectionName[] = "report_oracle";

TEST(ReportOracleEnclaveWrapperTest, LoadFromFileFailsWithInvalidPath) {
  EXPECT_THAT(ReportOracleEnclaveWrapper::LoadFromFile("/bad/path"),
              SgxErrorIs(SGX_ERROR_ENCLAVE_FILE_ACCESS));
}

TEST(ReportOracleEnclaveWrapperTest, LoadFromFileThenGetReport) {
  std::unique_ptr<ReportOracleEnclaveWrapper> report_oracle;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      report_oracle, ReportOracleEnclaveWrapper::LoadFromFile(
                         absl::GetFlag(FLAGS_report_oracle_enclave_path)));

  Targetinfo targetinfo = TrivialRandomObject<Targetinfo>();
  const Reportdata reportdata = TrivialRandomObject<Reportdata>();
  Report report;
  ASYLO_ASSERT_OK_AND_ASSIGN(report,
                             report_oracle->GetReport(targetinfo, reportdata));

  EXPECT_THAT(report.body.reportdata, TrivialObjectEq(reportdata));
}

TEST(ReportOracleEnclaveWrapperTest, LoadFromSectionFailsWithInvalidPath) {
  EXPECT_THAT(ReportOracleEnclaveWrapper::LoadFromSection("totally bogus"),
              StatusIs(absl::StatusCode::kNotFound));
}

TEST(ReportOracleEnclaveWrapperTest, GetReport) {
  std::unique_ptr<ReportOracleEnclaveWrapper> report_oracle;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      report_oracle,
      ReportOracleEnclaveWrapper::LoadFromSection(kReportOracleSectionName));

  Targetinfo targetinfo = TrivialRandomObject<Targetinfo>();
  const Reportdata reportdata = TrivialRandomObject<Reportdata>();
  Report report;
  ASYLO_ASSERT_OK_AND_ASSIGN(report,
                             report_oracle->GetReport(targetinfo, reportdata));

  EXPECT_THAT(report.body.reportdata, TrivialObjectEq(reportdata));
}

}  // namespace
}  // namespace sgx
}  // namespace asylo
