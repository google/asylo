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

#include <iostream>
#include <memory>
#include <string>
#include <utility>

#include "absl/flags/flag.h"
#include "absl/strings/string_view.h"
#include "asylo/util/logging.h"
#include "asylo/identity/attestation/sgx/internal/dcap_intel_architectural_enclave_interface.h"
#include "asylo/identity/attestation/sgx/internal/dcap_library_interface.h"
#include "asylo/identity/attestation/sgx/internal/host_dcap_library_interface.h"
#include "asylo/identity/platform/sgx/machine_configuration.pb.h"
#include "asylo/identity/provisioning/sgx/internal/platform_provisioning.h"
#include "asylo/identity/provisioning/sgx/internal/platform_provisioning.pb.h"
#include "asylo/identity/provisioning/sgx/internal/sgx_pcs_client.h"
#include "asylo/identity/provisioning/sgx/internal/sgx_pcs_tool_lib.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

ABSL_FLAG(std::string, dcap_enclave_dir, ".",
          "Directory containing the Intel PCE and QE binaries.");

int main(int argc, char *argv[]) {
  absl::ParseCommandLine(argc, argv);

  auto client_result = asylo::sgx::CreateSgxPcsClientFromFlags();

  asylo::sgx::PlatformInfo platform_info;
  auto platform_info_result = asylo::sgx::GetPlatformInfoFromFlags();
  if (platform_info_result.ok()) {
    platform_info = std::move(platform_info_result).value();
  }

  // Fill any missing fields that were not explicitly passed via flags from the
  // local system.
  if (!platform_info.ppid.has_value() || !platform_info.cpu_svn.has_value() ||
      !platform_info.pce_svn.has_value() || !platform_info.pce_id.has_value()) {
    std::cout << "Not all fields passed on command line. Attempting to "
                 "automatically fetch local system identifiers."
              << std::endl;
    asylo::sgx::DcapIntelArchitecturalEnclaveInterface dcap(
        absl::make_unique<asylo::sgx::HostDcapLibraryInterface>());
    ASYLO_CHECK_OK(dcap.SetEnclaveDir(absl::GetFlag(FLAGS_dcap_enclave_dir)));

    platform_info_result = asylo::sgx::GetPlatformInfoFromDcap("report_oracle");
    ASYLO_CHECK_OK(platform_info_result.status());

    platform_info.FillEmptyFields(platform_info_result.value());

    QCHECK(platform_info.ppid.has_value()) << "Missing PPID";
    QCHECK(platform_info.cpu_svn.has_value()) << "Missing CPUSVN";
    QCHECK(platform_info.pce_svn.has_value()) << "Missing PCESVN";
    QCHECK(platform_info.pce_id.has_value()) << "Missing PCEID";
  }

  auto cert_result = client_result.value()->GetPckCertificate(
      platform_info.ppid, platform_info.cpu_svn, platform_info.pce_svn,
      platform_info.pce_id);
  ASYLO_CHECK_OK(cert_result.status()) << "Error fetching certificate(s).";

  ASYLO_CHECK_OK(
      asylo::sgx::WriteOutputAccordingToFlags(std::move(cert_result).value()));

  return 0;
}
