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

#include <cstdint>
#include <string>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/time/clock.h"
#include "asylo/enclave_manager.h"
#include "asylo/examples/grpc_server/grpc_server_util.h"
#include "asylo/util/logging.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

ABSL_FLAG(std::string, enclave_path, "", "Path to enclave to load");

// By default, let the server run for five minutes.
ABSL_FLAG(int32_t, server_max_lifetime, 300,
          "The longest amount of time (in seconds) that the server should be "
          "allowed to run");

// Default value 0 is used to indicate that the system should choose an
// available port.
ABSL_FLAG(int32_t, port, 0, "Port that the server listens to");
ABSL_FLAG(bool, debug, true, "Whether to use a debug enclave");

int main(int argc, char *argv[]) {
  // Parse command-line arguments.
  absl::ParseCommandLine(argc, argv);

  std::string enclave_path = absl::GetFlag(FLAGS_enclave_path);
  LOG_IF(QFATAL, enclave_path.empty()) << "--enclave_path cannot be empty";

  asylo::Status status =
      asylo::EnclaveManager::Configure(asylo::EnclaveManagerOptions());
  LOG_IF(QFATAL, !status.ok())
      << "Failed to configure EnclaveManager: " << status;

  status = examples::grpc_server::LoadGrpcServerEnclave(
      enclave_path, absl::GetFlag(FLAGS_port), absl::GetFlag(FLAGS_debug));
  LOG_IF(QFATAL, !status.ok())
      << "Loading " << enclave_path << " failed: " << status;

  asylo::StatusOr<int> port_result =
      examples::grpc_server::GrpcServerEnclaveGetPort();
  LOG_IF(QFATAL, !port_result.ok())
      << "Retrieving port failed: " << port_result.status();

  std::cout << "Server started on port " << port_result.value() << std::endl;

  absl::SleepFor(absl::Seconds(absl::GetFlag(FLAGS_server_max_lifetime)));

  status = examples::grpc_server::DestroyGrpcServerEnclave();
  LOG_IF(QFATAL, !status.ok())
      << "Destroy " << enclave_path << " failed: " << status;

  return 0;
}
