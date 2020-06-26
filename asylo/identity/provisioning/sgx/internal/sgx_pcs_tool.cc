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

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <cstdint>
#include <cstdio>
#include <fstream>
#include <string>

#include "asylo/util/logging.h"
#include "asylo/identity/provisioning/sgx/internal/sgx_pcs_tool_lib.h"
#include "asylo/util/status.h"

int main(int argc, char *argv[]) {
  absl::ParseCommandLine(argc, argv);

  auto client_result = asylo::sgx::CreateSgxPcsClientFromFlags();

  asylo::sgx::PlatformInfo platform_info =
      asylo::sgx::GetPlatformInfoFromFlags().ValueOrDie();
  auto cert_result = client_result.ValueOrDie()->GetPckCertificate(
      platform_info.ppid, platform_info.cpu_svn, platform_info.pce_svn,
      platform_info.pce_id);
  ASYLO_CHECK_OK(cert_result.status()) << "Error fetching certificate(s).";

  ASYLO_CHECK_OK(asylo::sgx::WriteOutputAccordingToFlags(
      std::move(cert_result).ValueOrDie()));

  return 0;
}
