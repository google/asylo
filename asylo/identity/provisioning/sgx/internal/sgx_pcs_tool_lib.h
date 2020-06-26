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

#ifndef ASYLO_IDENTITY_PROVISIONING_SGX_INTERNAL_SGX_PCS_TOOL_LIB_H_
#define ASYLO_IDENTITY_PROVISIONING_SGX_INTERNAL_SGX_PCS_TOOL_LIB_H_

#include <stdint.h>

#include <memory>
#include <string>

#include "absl/flags/declare.h"
#include "absl/strings/string_view.h"
#include "asylo/identity/platform/sgx/machine_configuration.pb.h"
#include "asylo/identity/provisioning/sgx/internal/platform_provisioning.pb.h"
#include "asylo/identity/provisioning/sgx/internal/sgx_pcs_client.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

// Various flags that help determine the platform identifiers for the tool.
ABSL_DECLARE_FLAG(std::string, ppid);
ABSL_DECLARE_FLAG(std::string, cpu_svn);
ABSL_DECLARE_FLAG(int, pce_svn);

// The API key used to authenticate to the Intel PCS.
ABSL_DECLARE_FLAG(std::string, api_key);

// Where output is written.
ABSL_DECLARE_FLAG(std::string, outfile);

// How the output is written.
ABSL_DECLARE_FLAG(std::string, outfmt);

namespace asylo {
namespace sgx {

#if __cplusplus >= 201703L
inline constexpr uint32_t kSupportedPceId = 0;
inline constexpr int kInvalidPceSvn = -1;
inline constexpr char kReportOracleElfSectionName[] = "report_oracle";
#else
constexpr uint32_t kSupportedPceId = 0;
constexpr int kInvalidPceSvn = -1;
constexpr char kReportOracleElfSectionName[] = "report_oracle";
#endif

struct PlatformInfo {
  Ppid ppid;
  CpuSvn cpu_svn;
  PceSvn pce_svn;
  PceId pce_id;

  // Fills in any fields of this object that are empty with the values in
  // |info|.
  void FillEmptyFields(const PlatformInfo &info);
};

// Fetch the information about the platform from command-line flags.
StatusOr<PlatformInfo> GetPlatformInfoFromFlags();

// Fetch the information about the platform from the DCAP library. This function
// requires that the report oracle enclave has been embedded in the calling
// binary. The section holding the report oracle is specified by
// |report_oracle_enclave_section_name|.
StatusOr<PlatformInfo> GetPlatformInfoFromDcap(
    absl::string_view report_oracle_enclave_section_name);

// Create a client object for requesting data from the Intel PCS from
// command-line flags.
StatusOr<std::unique_ptr<SgxPcsClient>> CreateSgxPcsClientFromFlags();

// Write the results of a PCK certificate fetch to disk as directed by
// command-line flags.
Status WriteOutputAccordingToFlags(GetPckCertificateResult cert_result);

}  // namespace sgx
}  // namespace asylo

#endif  // ASYLO_IDENTITY_PROVISIONING_SGX_INTERNAL_SGX_PCS_TOOL_LIB_H_
