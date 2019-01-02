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
#include "asylo/client.h"
#include "asylo/examples/grpc_server/grpc_server_config.pb.h"
#include "gflags/gflags.h"
#include "asylo/util/logging.h"

DEFINE_string(enclave_path, "", "Path to enclave to load");

// By default, let the server run for five minutes.
DEFINE_int32(server_max_lifetime, 300,
             "The longest amount of time (in seconds) that the server should "
             "be allowed to run");
DEFINE_int32(server_lifetime, -1, "Deprecated alias for server_max_lifetime");

// A port of 0 is used to indicate that the system should choose an available
// port.
constexpr char kServerAddress[] = "[::1]:0";

int main(int argc, char *argv[]) {
  // Parse command-line arguments.
  google::ParseCommandLineFlags(
      &argc, &argv, /*remove_flags=*/true);

  // Create a loader object using the enclave_path flag.
  asylo::SimLoader loader(FLAGS_enclave_path, /*debug=*/true);

  // Build an EnclaveConfig object with the address that the gRPC server will
  // run on.
  asylo::EnclaveConfig config;
  config.SetExtension(examples::grpc_server::server_address, kServerAddress);
  config.SetExtension(examples::grpc_server::server_max_lifetime,
                      FLAGS_server_lifetime >= 0 ? FLAGS_server_lifetime
                                                 : FLAGS_server_max_lifetime);

  // Configure and retrieve the EnclaveManager.
  asylo::EnclaveManager::Configure(asylo::EnclaveManagerOptions());
  auto manager_result = asylo::EnclaveManager::Instance();
  LOG_IF(QFATAL, !manager_result.ok())
      << "Failed to retrieve EnclaveManager instance: "
      << manager_result.status();
  asylo::EnclaveManager *manager = manager_result.ValueOrDie();

  // Load the enclave. Calling LoadEnclave() triggers a call to the Initialize()
  // method of the TrustedApplication.
  asylo::Status status = manager->LoadEnclave("grpc_example", loader, config);
  LOG_IF(QFATAL, !status.ok())
      << "Load " << FLAGS_enclave_path << " failed: " << status;

  // Wait up to FLAGS_server_max_lifetime seconds or for the server to receive
  // the shutdown RPC, whichever happens first.
  asylo::EnclaveClient *client = manager->GetClient("grpc_example");
  asylo::EnclaveInput input;
  status = client->EnterAndRun(input, nullptr);
  LOG_IF(QFATAL, !status.ok())
      << "Running " << FLAGS_enclave_path << " failed: " << status;

  // Destroy the enclave.
  asylo::EnclaveFinal final_input;
  status = manager->DestroyEnclave(client, final_input);
  LOG_IF(QFATAL, !status.ok())
      << "Destroy " << FLAGS_enclave_path << " failed: " << status;

  return 0;
}
