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

#include <cstdint>
#include <cstdlib>
#include <string>

#include <gtest/gtest.h>
#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "asylo/bazel/test_shim_enclave.pb.h"
#include "asylo/client.h"
#include "asylo/enclave.pb.h"
#include "asylo/util/logging.h"
#include "asylo/platform/primitives/sgx/loader.pb.h"
#include "asylo/test/util/test_flags.h"

ABSL_FLAG(std::string, enclave_path, "", "Path to enclave to load");
ABSL_FLAG(bool, test_in_initialize, false,
          "Run tests in Initialize, rather than Run");
ABSL_FLAG(std::string, benchmarks, "",
          "A regular expression that specifies the set of benchmarks "
          "to execute.  If this flag is empty, no benchmarks are run. "
          "If this flag is the string \"all\", all benchmarks linked "
          "into the process are run.");
ABSL_FLAG(int32_t, v, 0, "Logging verbosity level");

namespace {

constexpr char kEnclaveName[] = "/test_shim_enclave";

}  // namespace

int main(int argc, char *argv[]) {
  absl::ParseCommandLine(argc, argv);

  // If provided in the environment, pass the test output file into the enclave.
  asylo::EnclaveConfig config;
  config.mutable_logging_config()->set_vlog_level(absl::GetFlag(FLAGS_v));
  char *output_file = std::getenv("GTEST_OUTPUT");
  if (output_file != nullptr && output_file[0] != '\0') {
    asylo::TestShimEnclaveConfig *shim_config =
        config.MutableExtension(asylo::test_shim_enclave_config);
    shim_config->set_output_file(output_file);
  }

  // If provided, pass the test temporary files directory into the enclave.
  if (!absl::GetFlag(FLAGS_test_tmpdir).empty()) {
    asylo::TestShimEnclaveConfig *shim_config =
        config.MutableExtension(asylo::test_shim_enclave_config);
    shim_config->set_test_tmpdir(absl::GetFlag(FLAGS_test_tmpdir));
  }

  // Pass |test_in_initialize| value to enclave.
  asylo::TestShimEnclaveConfig *shim_config =
      config.MutableExtension(asylo::test_shim_enclave_config);
  shim_config->set_test_in_initialize(absl::GetFlag(FLAGS_test_in_initialize));

  // Pass the value of the benchmarks flag to the enclave.
  shim_config->set_benchmarks(absl::GetFlag(FLAGS_benchmarks));

  // Load the enclave
  asylo::EnclaveManager::Configure(asylo::EnclaveManagerOptions());
  auto manager_result = asylo::EnclaveManager::Instance();
  if (!manager_result.ok()) {
    LOG(QFATAL) << "Instance returned status: " << manager_result.status();
  }
  asylo::EnclaveManager *manager = manager_result.value();

  // Create an EnclaveLoadConfig object.
  asylo::EnclaveLoadConfig load_config;
  load_config.set_name(kEnclaveName);
  *load_config.mutable_config() = config;

  // Create an SgxLoadConfig object.
  asylo::SgxLoadConfig sgx_config;
  asylo::SgxLoadConfig::FileEnclaveConfig file_enclave_config;
  file_enclave_config.set_enclave_path(absl::GetFlag(FLAGS_enclave_path));
  *sgx_config.mutable_file_enclave_config() = file_enclave_config;
  sgx_config.set_debug(true);

  // Set an SGX message extension to load_config.
  *load_config.MutableExtension(asylo::sgx_load_config) = sgx_config;

  asylo::Status status = manager->LoadEnclave(load_config);
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
