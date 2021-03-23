/*
 *
 * Copyright 2017 Asylo authors
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

#include "asylo/test/util/enclave_test_launcher.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "asylo/enclave.pb.h"
#include "asylo/util/logging.h"
#include "asylo/platform/primitives/sgx/loader.pb.h"
#include "asylo/test/util/test_string.pb.h"
#include "asylo/util/posix_errors.h"
#include "asylo/util/status_macros.h"

namespace asylo {

EnclaveTestLauncher::EnclaveTestLauncher()
    : manager_(nullptr), client_(nullptr), loader_(nullptr) {}

Status EnclaveTestLauncher::SetUp(const std::string &enclave_path,
                                  const EnclaveConfig &econfig,
                                  const std::string &enclave_url) {
  EnclaveManager::Configure(EnclaveManagerOptions());
  ASYLO_ASSIGN_OR_RETURN(manager_, EnclaveManager::Instance());

  // Create an EnclaveLoadConfig object.
  EnclaveLoadConfig load_config;
  load_config.set_name(enclave_url);
  *load_config.mutable_config() = econfig;

  // Create an SgxLoadConfig object.
  SgxLoadConfig sgx_config;
  SgxLoadConfig::FileEnclaveConfig file_enclave_config;
  file_enclave_config.set_enclave_path(enclave_path);
  *sgx_config.mutable_file_enclave_config() = file_enclave_config;
  sgx_config.set_debug(true);

  // Set an SGX message extension to load_config.
  *load_config.MutableExtension(sgx_load_config) = sgx_config;

  ASYLO_RETURN_IF_ERROR(manager_->LoadEnclave(load_config));

  client_ = manager_->GetClient(enclave_url);
  if (!client_) {
    Status status = PosixError(ENOENT, "Client is null");
    LOG(ERROR) << "SetUp failed:" << status;
    return status;
  }
  return absl::OkStatus();
}

Status EnclaveTestLauncher::Run(const EnclaveInput &input,
                                EnclaveOutput *output) {
  if (!client_) {
    return absl::FailedPreconditionError("No EnclaveClient available");
  }
  return client_->EnterAndRun(input, output);
}

Status EnclaveTestLauncher::TearDown(const EnclaveFinal &efinal,
                                     bool skipTearDown) {
  if (!client_) {
    return absl::OkStatus();
  }
  if (!manager_) {
    EnclaveManager::Configure(EnclaveManagerOptions());
    ASYLO_ASSIGN_OR_RETURN(manager_, EnclaveManager::Instance());
  }
  return manager_->DestroyEnclave(client_, efinal, skipTearDown);
}

void EnclaveTestLauncher::SetEnclaveInputTestString(
    EnclaveInput *enclave_input, const std::string &str_test) {
  enclave_input->MutableExtension(enclave_input_test_string)
      ->set_test_string(str_test);
}

const std::string &EnclaveTestLauncher::GetEnclaveOutputTestString(
    const EnclaveOutput &output) {
  return output.GetExtension(enclave_output_test_string).test_string();
}

}  // namespace asylo
