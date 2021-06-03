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

#include <unistd.h>

#include <climits>
#include <cstdlib>
#include <iostream>
#include <string>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "asylo/client.h"
#include "asylo/examples/remote/quickstart/demo.pb.h"
#include "asylo/util/logging.h"
#include "asylo/platform/primitives/sgx/loader.pb.h"
#include "asylo/util/remote/provision.h"
#include "asylo/util/remote/remote_loader.pb.h"
#include "asylo/util/remote/remote_proxy_config.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"

ABSL_FLAG(std::string, enclave_path, "",
          "Path to enclave binary image to load");
ABSL_FLAG(std::string, message, "", "Message to encrypt");

using ::asylo::RemoteProvision;
using ::asylo::RemoteProxyClientConfig;
using ::asylo::Status;

// Populates |enclave_input|->value() with |user_message|.
void SetEnclaveUserMessage(asylo::EnclaveInput *enclave_input,
                           const std::string &user_message) {
  guide::asylo::Demo *user_input =
      enclave_input->MutableExtension(guide::asylo::quickstart_input);
  user_input->set_value(user_message);
}

// Retrieves encrypted message from |output|. Intended to be used by the reader
// for completing the exercise.
const std::string GetEnclaveOutputMessage(const asylo::EnclaveOutput &output) {
  return output.GetExtension(guide::asylo::quickstart_output).value();
}

int main(int argc, char *argv[]) {
  absl::ParseCommandLine(argc, argv);

  constexpr char kEnclaveName[] = "demo_enclave";

  const std::string message = absl::GetFlag(FLAGS_message);
  LOG_IF(QFATAL, message.empty()) << "Empty --message flag.";

  const std::string enclave_path = absl::GetFlag(FLAGS_enclave_path);
  LOG_IF(QFATAL, enclave_path.empty()) << "Empty --enclave_path flag.";

  // Part 1: Initialization

  // Prepare |EnclaveManager| with default |EnclaveManagerOptions|
  asylo::EnclaveManager::Configure(asylo::EnclaveManagerOptions());
  auto manager_result = asylo::EnclaveManager::Instance();
  LOG_IF(QFATAL, !manager_result.ok()) << "Could not obtain EnclaveManager";

  // Prepare |load_config| message.
  asylo::EnclaveLoadConfig load_config;
  load_config.set_name(kEnclaveName);

  // Prepare |remote_config| message.
  auto proxy_config_result = RemoteProxyClientConfig::DefaultsWithProvision(
      RemoteProvision::Instantiate());
  LOG_IF(QFATAL, !proxy_config_result.ok())
      << "Could not build RemoteProxyClientConfig";

  auto remote_config = load_config.MutableExtension(asylo::remote_load_config);
  remote_config->set_remote_proxy_config(
      reinterpret_cast<uintptr_t>(proxy_config_result.value().release()));

  // Prepare |sgx_config| message.
  auto sgx_config = remote_config->mutable_sgx_load_config();
  sgx_config->set_debug(true);
  auto file_enclave_config = sgx_config->mutable_file_enclave_config();
  file_enclave_config->set_enclave_path(enclave_path);

  // Load Enclave with prepared |EnclaveManager| and |load_config| message.
  asylo::EnclaveManager *manager = manager_result.value();
  auto status = manager->LoadEnclave(load_config);
  LOG_IF(QFATAL, !status.ok()) << "LoadEnclave failed with: " << status;

  // Part 2: Secure execution

  // Prepare |input| with |message| and create |output| to retrieve response
  // from enclave.
  asylo::EnclaveInput input;
  SetEnclaveUserMessage(&input, message);
  asylo::EnclaveOutput output;

  // Get |EnclaveClient| for loaded enclave and execute |EnterAndRun|.
  asylo::EnclaveClient *const client = manager->GetClient(kEnclaveName);
  status = client->EnterAndRun(input, &output);
  LOG_IF(QFATAL, !status.ok()) << "EnterAndRun failed with: " << status;

  // Print the encyrpted message locally.
  std::cout << "Encrypted message:" << std::endl
            << output.GetExtension(guide::asylo::quickstart_output).value()
            << std::endl;

  // Part 3: Finalization

  // |DestroyEnclave| before exiting program.
  asylo::EnclaveFinal empty_final_input;
  status = manager->DestroyEnclave(client, empty_final_input, false);
  LOG_IF(QFATAL, !status.ok()) << "DestroyEnclave failed with: " << status;

  return 0;
}
