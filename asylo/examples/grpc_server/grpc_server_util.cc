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

#include "absl/strings/str_cat.h"
#include "asylo/client.h"
#include "asylo/enclave.pb.h"
#include "asylo/examples/grpc_server/grpc_server_config.pb.h"
#include "asylo/platform/primitives/sgx/loader.pb.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"

namespace examples {
namespace grpc_server {
namespace {

constexpr char kServerAddress[] = "localhost";
constexpr char kEnclaveName[] = "grpc_server";

}  // namespace

asylo::Status LoadGrpcServerEnclave(const std::string &enclave_path,
                                    int server_port, bool debug_enclave) {
  // The EnclaveLoadConfig contains all configurations passed to the enclave for
  // initialization.
  asylo::EnclaveLoadConfig load_config;
  load_config.set_name(kEnclaveName);

  // The EnclaveConfig contains the address that the gRPC server will run on.
  asylo::EnclaveConfig *config = load_config.mutable_config();
  config->SetExtension(server_address, kServerAddress);
  config->SetExtension(port, server_port);

  // The SgxLoadConfig sets up configuration specific to an SGX enclave,
  // including the location of the enclave binary and whether to run in debug
  // mode.
  asylo::SgxLoadConfig *sgx_config =
      load_config.MutableExtension(asylo::sgx_load_config);
  sgx_config->mutable_file_enclave_config()->set_enclave_path(enclave_path);
  sgx_config->set_debug(debug_enclave);

  asylo::EnclaveManager *manager = nullptr;
  ASYLO_ASSIGN_OR_RETURN(manager, asylo::EnclaveManager::Instance());

  // Load the enclave. Calling LoadEnclave() triggers a call to the Initialize()
  // method of the TrustedApplication.
  return manager->LoadEnclave(load_config);
}

asylo::StatusOr<int> GrpcServerEnclaveGetPort() {
  asylo::EnclaveManager *manager = nullptr;
  ASYLO_ASSIGN_OR_RETURN(manager, asylo::EnclaveManager::Instance());

  asylo::EnclaveClient *client = manager->GetClient(kEnclaveName);
  if (!client) {
    return asylo::Status(asylo::error::FAILED_PRECONDITION,
                         absl::StrCat(kEnclaveName, " not running"));
  }

  asylo::EnclaveInput enclave_input;
  asylo::EnclaveOutput enclave_output;
  ASYLO_RETURN_IF_ERROR(client->EnterAndRun(enclave_input, &enclave_output));
  if (!enclave_output.HasExtension(actual_server_port)) {
    return asylo::Status(asylo::error::INTERNAL,
                         "Server output missing server_port extension");
  }
  return enclave_output.GetExtension(actual_server_port);
}

asylo::Status DestroyGrpcServerEnclave() {
  asylo::EnclaveManager *manager = nullptr;
  ASYLO_ASSIGN_OR_RETURN(manager, asylo::EnclaveManager::Instance());

  asylo::EnclaveClient *client = manager->GetClient(kEnclaveName);
  if (!client) {
    return asylo::Status(asylo::error::FAILED_PRECONDITION,
                         absl::StrCat(kEnclaveName, " not running"));
  }

  asylo::EnclaveFinal final_input;
  return manager->DestroyEnclave(client, final_input);
}

}  // namespace grpc_server
}  // namespace examples
