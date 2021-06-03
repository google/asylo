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

#include <iostream>
#include <string>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "asylo/client.h"
#include "asylo/enclave.pb.h"
#include "asylo/examples/quickstart/solution/demo.pb.h"
#include "asylo/util/logging.h"
#include "asylo/platform/primitives/sgx/loader.pb.h"

ABSL_FLAG(std::string, enclave_path, "", "Path to enclave to load");
ABSL_FLAG(std::string, message1, "", "The first message to encrypt");
ABSL_FLAG(std::string, message2, "", "The second message to encrypt");
ABSL_FLAG(std::string, ciphertext, "", "The ciphertext message to decrypt");

// Populates |enclave_input|->value() with |user_message|.
void SetEnclaveUserMessage(asylo::EnclaveInput *enclave_input,
                           const std::string &user_message,
                           guide::asylo::Demo::Action action) {
  guide::asylo::Demo *user_input =
      enclave_input->MutableExtension(guide::asylo::quickstart_input);
  user_input->set_value(user_message);
  user_input->set_action(action);
}

// Retrieves encrypted message from |output|. Intended to be used by the reader
// for completing the exercise.
const std::string GetEnclaveOutputMessage(const asylo::EnclaveOutput &output) {
  return output.GetExtension(guide::asylo::quickstart_output).value();
}

int main(int argc, char *argv[]) {
  absl::ParseCommandLine(argc, argv);

  LOG_IF(QFATAL, absl::GetFlag(FLAGS_message1).empty() &&
                     absl::GetFlag(FLAGS_message2).empty() &&
                     absl::GetFlag(FLAGS_ciphertext).empty())
      << "Must specify at least one of --message1, --message2, or --ciphertext "
         "flag values";

  // Part 1: Initialization

  asylo::EnclaveManager::Configure(asylo::EnclaveManagerOptions());
  auto manager_result = asylo::EnclaveManager::Instance();
  LOG_IF(QFATAL, !manager_result.ok()) << "Could not obtain EnclaveManager";

  // Create an EnclaveLoadConfig object.
  asylo::EnclaveLoadConfig load_config;
  load_config.set_name("demo_enclave");

  // Create an SgxLoadConfig object.
  asylo::SgxLoadConfig sgx_config;
  asylo::SgxLoadConfig::FileEnclaveConfig file_enclave_config;
  file_enclave_config.set_enclave_path(absl::GetFlag(FLAGS_enclave_path));
  *sgx_config.mutable_file_enclave_config() = file_enclave_config;
  sgx_config.set_debug(true);

  // Set an SGX message extension to load_config.
  *load_config.MutableExtension(asylo::sgx_load_config) = sgx_config;

  asylo::EnclaveManager *manager = manager_result.value();
  asylo::Status status = manager->LoadEnclave(load_config);
  LOG_IF(QFATAL, !status.ok()) << "LoadEnclave failed with: " << status;

  // Part 2: Secure execution

  asylo::EnclaveClient *client = manager->GetClient("demo_enclave");
  asylo::EnclaveInput input;
  asylo::EnclaveOutput output;

  if (!absl::GetFlag(FLAGS_message1).empty()) {
    SetEnclaveUserMessage(&input, absl::GetFlag(FLAGS_message1),
                          guide::asylo::Demo::ENCRYPT);
    status = client->EnterAndRun(input, &output);
    LOG_IF(QFATAL, !status.ok()) << "EnterAndRun failed with: " << status;
    std::cout << "Encrypted message1 from driver:" << std::endl
              << GetEnclaveOutputMessage(output) << std::endl;
  }

  if (!absl::GetFlag(FLAGS_message2).empty()) {
    SetEnclaveUserMessage(&input, absl::GetFlag(FLAGS_message2),
                          guide::asylo::Demo::ENCRYPT);
    status = client->EnterAndRun(input, &output);
    LOG_IF(QFATAL, !status.ok()) << "EnterAndRun failed with: " << status;
    std::cout << "Encrypted message2 from driver:" << std::endl
              << GetEnclaveOutputMessage(output) << std::endl;
  }

  if (!absl::GetFlag(FLAGS_ciphertext).empty()) {
    SetEnclaveUserMessage(&input, absl::GetFlag(FLAGS_ciphertext),
                          guide::asylo::Demo::DECRYPT);
    status = client->EnterAndRun(input, &output);
    LOG_IF(QFATAL, !status.ok()) << "EnterAndRun failed with: " << status;
    std::cout << "Decrypted ciphertext from driver:" << std::endl
              << GetEnclaveOutputMessage(output) << std::endl;
  }

  // Part 3: Finalization

  asylo::EnclaveFinal empty_final_input;
  status = manager->DestroyEnclave(client, empty_final_input);
  LOG_IF(QFATAL, !status.ok()) << "DestroyEnclave failed with: " << status;

  return 0;
}
