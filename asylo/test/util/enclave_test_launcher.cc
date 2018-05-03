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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "absl/memory/memory.h"
#include "asylo/util/logging.h"
#include "asylo/test/util/test_string.pb.h"
#include "asylo/util/posix_error_space.h"

namespace asylo {

Status EnclaveTestLauncher::SetUp(const std::string &enclave_path,
                                  const EnclaveConfig &econfig,
                                  const std::string &enclave_url) {
  EnclaveManager::Configure(EnclaveManagerOptions());
  StatusOr<EnclaveManager *> manager_result = EnclaveManager::Instance();
  if (!manager_result.ok()) {
    return manager_result.status();
  }

  manager_ = manager_result.ValueOrDie();

  loader_ = absl::make_unique<SGXLoader>(enclave_path, /*debug=*/true);
  Status status = manager_->LoadEnclave(enclave_url, *loader_, econfig);
  if (!status.ok()) return status;

  client_ = manager_->GetClient(enclave_url);
  if (!client_) {
    Status status(error::PosixError::P_ENOENT, "Client is null");
    LOG(ERROR) << "SetUp failed:" << status;
    return status;
  }
  return Status::OkStatus();
}

Status EnclaveTestLauncher::Run(const EnclaveInput &input,
                                EnclaveOutput *output) {
  return client_->EnterAndRun(input, output);
}

Status EnclaveTestLauncher::TearDown(const EnclaveFinal &efinal,
                                     bool skipTearDown) {
  if (!client_) {
    return Status::OkStatus();
  }
  return manager_->DestroyEnclave(client_, efinal, skipTearDown);
}

void EnclaveTestLauncher::SetEnclaveInputTestString(EnclaveInput *enclave_input,
                                                    const std::string &str_test) {
  enclave_input->MutableExtension(enclave_input_test_string)
      ->set_test_string(str_test);
}

const std::string &EnclaveTestLauncher::GetEnclaveOutputTestString(
    const EnclaveOutput &output) {
  return output.GetExtension(enclave_output_test_string).test_string();
}

}  // namespace asylo
