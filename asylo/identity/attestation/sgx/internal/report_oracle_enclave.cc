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

#include <memory>

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "asylo/crypto/util/trivial_object_util.h"
#include "asylo/identity/attestation/sgx/internal/report_oracle_enclave.pb.h"
#include "asylo/identity/platform/sgx/internal/hardware_interface.h"
#include "asylo/identity/platform/sgx/internal/identity_key_management_structs.h"
#include "asylo/identity/provisioning/sgx/internal/platform_provisioning.h"
#include "asylo/platform/core/trusted_application.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"

namespace asylo {
namespace sgx {
namespace {

// Test enclave that generates reports given an arbitrary input report data.
class ReportOracleEnclave : public TrustedApplication {
 public:
  Status Run(const EnclaveInput &input, EnclaveOutput *output) override {
    if (!input.HasExtension(report_oracle_enclave_input)) {
      return absl::InvalidArgumentError("Expected ReportOracleEnclaveInput.");
    }

    const ReportOracleEnclaveInput &enclave_input =
        input.GetExtension(report_oracle_enclave_input);
    ReportOracleEnclaveOutput *enclave_output =
        output->MutableExtension(report_oracle_enclave_output);

    switch (enclave_input.input_case()) {
      case ReportOracleEnclaveInput::kGetReport:
        return GetReport(enclave_input.get_report(),
                         enclave_output->mutable_get_report());
      case ReportOracleEnclaveInput::INPUT_NOT_SET:
        break;
    }

    return absl::InvalidArgumentError(
        absl::StrCat("Invalid input case: ", enclave_input.input_case()));
  }

  Status GetReport(const ReportOracleEnclaveInput::GetReport &input,
                   ReportOracleEnclaveOutput::GetReport *output) {
    AlignedTargetinfoPtr target_info;
    ASYLO_ASSIGN_OR_RETURN(
        *target_info, ConvertTargetInfoProtoToTargetinfo(input.target_info()));

    if (input.reportdata().size() != kReportdataSize) {
      return absl::InvalidArgumentError(absl::StrCat(
          "Invalid report data size: ", input.reportdata().size()));
    }

    AlignedReportdataPtr reportdata;
    if (reportdata->data.assign(input.reportdata()) != kReportdataSize) {
      return absl::InternalError(
          "Error copying data into to report data container");
    }

    Report report;
    ASYLO_ASSIGN_OR_RETURN(
        report, HardwareInterface::CreateDefault()->GetReport(*target_info,
                                                              *reportdata));

    output->mutable_report()->set_value(
        ConvertTrivialObjectToBinaryString(report));

    return absl::OkStatus();
  }
};

}  // namespace
}  // namespace sgx

TrustedApplication *BuildTrustedApplication() {
  return new asylo::sgx::ReportOracleEnclave;
}

}  // namespace asylo
