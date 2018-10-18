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

#include <cstdlib>

#include "asylo/bazel/test_shim_enclave.pb.h"
#include "asylo/client.h"
#include "gflags/gflags.h"
#include "asylo/util/logging.h"
#include "asylo/test/util/test_flags.h"

DEFINE_string(enclave_path, "", "Path to enclave to load");
DEFINE_bool(test_in_initialize, false,
            "Run tests in Initialize, rather than Run");

namespace {

constexpr char kEnclaveName[] = "/test_shim_enclave";

}  // namespace

int main(int argc, char *argv[]) {
  google::ParseCommandLineFlags(&argc, &argv, true);

  // If provided in the environment, pass the test output file into the enclave.
  asylo::EnclaveConfig config;
  char *output_file = std::getenv("GTEST_OUTPUT");
  if (output_file != nullptr && output_file[0] != '\0') {
    asylo::TestShimEnclaveConfig *shim_config =
        config.MutableExtension(asylo::test_shim_enclave_config);
    shim_config->set_output_file(output_file);
  }

  // If provided, pass the test temporary files directory into the enclave.
  if (!FLAGS_test_tmpdir.empty()) {
    asylo::TestShimEnclaveConfig *shim_config =
        config.MutableExtension(asylo::test_shim_enclave_config);
    shim_config->set_test_tmpdir(FLAGS_test_tmpdir);
  }

  // Pass |test_in_initialize| value to enclave.
  asylo::TestShimEnclaveConfig *shim_config =
      config.MutableExtension(asylo::test_shim_enclave_config);
  shim_config->set_test_in_initialize(FLAGS_test_in_initialize);

  // Load the enclave
  asylo::EnclaveManager::Configure(asylo::EnclaveManagerOptions());
  auto manager_result = asylo::EnclaveManager::Instance();
  if (!manager_result.ok()) {
    LOG(QFATAL) << "Instance returned status: " << manager_result.status();
  }
  asylo::EnclaveManager *manager = manager_result.ValueOrDie();
  asylo::SgxLoader loader(FLAGS_enclave_path, /*debug*/ true);
  asylo::Status status = manager->LoadEnclave(kEnclaveName, loader, config);
  if (!status.ok()) {
    LOG(QFATAL) << "LoadEnclave returned status: " << status;
  }

  // Run the enclave
  asylo::EnclaveClient *client = manager->GetClient(kEnclaveName);
  asylo::EnclaveInput input;
  status = client->EnterAndRun(input, /*output*/ nullptr);
  if (!status.ok()) {
    LOG(QFATAL) << "EnterAndRun returned status: " << status;
  }

  // Destroy the enclave
  asylo::EnclaveFinal final_input;
  status = manager->DestroyEnclave(client, final_input);
  if (!status.ok()) {
    LOG(QFATAL) << "DestroyEnclave returned status: " << status;
  }

  return 0;
}
