/*
 *
 * Copyright 2018 Asylo authors
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

#include "asylo/bazel/application_wrapper/application_wrapper_driver_main.h"

#include "absl/status/status.h"
#include "asylo/bazel/application_wrapper/application_wrapper.pb.h"
#include "asylo/bazel/application_wrapper/argv.h"
#include "asylo/client.h"
#include "asylo/util/logging.h"
#include "asylo/util/cleanup.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"

namespace asylo {

StatusOr<int> ApplicationWrapperDriverMain(const EnclaveLoader &loader,
                                           const std::string &enclave_name,
                                           int argc, char *argv[]) {
  // Retrieve the EnclaveManager instance.
  EnclaveManager *manager;
  ASYLO_ASSIGN_OR_RETURN(manager, EnclaveManager::Instance());

  // Marshal the command-line arguments into the EnclaveConfig.
  EnclaveConfig config = GetApplicationConfig();
  Argv::WriteArgvToRepeatedStringField(
      argc, argv,
      config.MutableExtension(command_line_args)->mutable_arguments());
  config.set_enable_fork(true);

  // Load the enclave.
  ASYLO_RETURN_IF_ERROR(manager->LoadEnclave(enclave_name, loader, config));
  EnclaveClient *client = manager->GetClient(enclave_name);

  // Ensure that the enclave is properly destroyed in the event of an early
  // return.
  Cleanup destroy_enclave([manager, client]() {
    // Log any failure from DestroyEnclave() since, in the event of an early
    // return, there is already another Status object to return.
    Status status = manager->DestroyEnclave(client, EnclaveFinal());
    LOG_IF(ERROR, !status.ok())
        << "Failed to destroy the application enclave: " << status;
  });

  // Run the application and retrieve its return value.
  EnclaveOutput output;
  ASYLO_RETURN_IF_ERROR(client->EnterAndRun(EnclaveInput(), &output));
  if (!output.HasExtension(main_return_value)) {
    return Status(absl::StatusCode::kInternal,
                  "EnclaveOutput does not have a main_return_value extension");
  }
  int main_return = output.GetExtension(main_return_value);

  // Destroy the enclave.
  destroy_enclave.release();
  ASYLO_RETURN_IF_ERROR(manager->DestroyEnclave(client, EnclaveFinal()));

  return main_return;
}

}  // namespace asylo
