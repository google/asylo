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

#include <cstdint>
#include <string>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "asylo/client.h"
#include "asylo/enclave.pb.h"
#include "asylo/examples/grpc_server/grpc_server_config.pb.h"
#include "asylo/util/logging.h"
#include "asylo/platform/primitives/sgx/loader.pb.h"

ABSL_FLAG(std::string, enclave_path, "", "Path to enclave to load");

// By default, let the server run for five minutes.
ABSL_FLAG(int32_t, server_max_lifetime, 300,
          "The longest amount of time (in seconds) that the server should be "
          "allowed to run");
ABSL_FLAG(int32_t, server_lifetime, -1,
          "Deprecated alias for server_max_lifetime");

// Default value 0 is used to indicate that the system should choose an
// available port.
ABSL_FLAG(int32_t, port, 0, "Port that the server listens to");

constexpr char kServerAddress[] = "[::1]";

int main(int argc, char *argv[]) {
  // Parse command-line arguments.
  absl::ParseCommandLine(argc, argv);

  // Create an EnclaveLoadConfig object.
  asylo::EnclaveLoadConfig load_config;
  load_config.set_name("grpc_example");

  // Build an EnclaveConfig object with the address that the gRPC server will
  // run on.
  asylo::EnclaveConfig config;
  config.SetExtension(examples::grpc_server::server_address, kServerAddress);
  config.SetExtension(examples::grpc_server::server_max_lifetime,
                      absl::GetFlag(FLAGS_server_lifetime) >= 0
                          ? absl::GetFlag(FLAGS_server_lifetime)
                          : absl::GetFlag(FLAGS_server_max_lifetime));
  config.SetExtension(examples::grpc_server::port, absl::GetFlag(FLAGS_port));
  *load_config.mutable_config() = config;

  // Create an SgxLoadConfig object.
  asylo::SgxLoadConfig sgx_config;
  asylo::SgxLoadConfig::FileEnclaveConfig file_enclave_config;
  file_enclave_config.set_enclave_path(absl::GetFlag(FLAGS_enclave_path));
  *sgx_config.mutable_file_enclave_config() = file_enclave_config;
  sgx_config.set_debug(true);

  // Set an SGX message extension to load_config.
  *load_config.MutableExtension(asylo::sgx_load_config) = sgx_config;

  // Configure and retrieve the EnclaveManager.
  asylo::EnclaveManager::Configure(asylo::EnclaveManagerOptions());
  auto manager_result = asylo::EnclaveManager::Instance();
  LOG_IF(QFATAL, !manager_result.ok())
      << "Failed to retrieve EnclaveManager instance: "
      << manager_result.status();
  asylo::EnclaveManager *manager = manager_result.ValueOrDie();

  // Load the enclave. Calling LoadEnclave() triggers a call to the Initialize()
  // method of the TrustedApplication.
  asylo::Status status = manager->LoadEnclave(load_config);
  LOG_IF(QFATAL, !status.ok())
      << "Load " << absl::GetFlag(FLAGS_enclave_path) << " failed: " << status;

  // Wait up to FLAGS_server_max_lifetime seconds or for the server to receive
  // the shutdown RPC, whichever happens first.
  asylo::EnclaveClient *client = manager->GetClient("grpc_example");
  asylo::EnclaveInput input;
  status = client->EnterAndRun(input, nullptr);
  LOG_IF(QFATAL, !status.ok())
      << "Running " << absl::GetFlag(FLAGS_enclave_path)
      << " failed: " << status;

  // Destroy the enclave.
  asylo::EnclaveFinal final_input;
  status = manager->DestroyEnclave(client, final_input);
  LOG_IF(QFATAL, !status.ok())
      << "Destroy " << absl::GetFlag(FLAGS_enclave_path)
      << " failed: " << status;

  return 0;
}
