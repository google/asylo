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

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "asylo/client.h"
#include "asylo/enclave.pb.h"
#include "asylo/examples/grpc_server/translator_server.grpc.pb.h"
#include "asylo/examples/secure_grpc/attestation_domain.h"
#include "asylo/examples/secure_grpc/grpc_client_enclave.pb.h"
#include "asylo/identity/enclave_assertion_authority_config.pb.h"
#include "asylo/identity/enclave_assertion_authority_configs.h"
#include "asylo/platform/primitives/sgx/loader.pb.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"

namespace examples {
namespace secure_grpc {
namespace {

constexpr char kEnclaveName[] = "secure_grpc_client";

}  // namespace

asylo::Status LoadGrpcClientEnclave(const std::string &enclave_path,
                                    bool debug_enclave) {
  // The EnclaveLoadConfig contains all configurations passed to the enclave for
  // initialization.
  asylo::EnclaveLoadConfig load_config;
  load_config.set_name(kEnclaveName);

  // Create a config that initializes the SGX assertion authority.
  ASYLO_ASSIGN_OR_RETURN(
      *load_config.mutable_config()->add_enclave_assertion_authority_configs(),
      asylo::CreateSgxLocalAssertionAuthorityConfig(kAttestationDomain));

  // The SgxLoadConfig sets up configuration specific to an SGX enclave,
  // including the location of the enclave binary and whether to run in debug
  // mode.
  asylo::SgxLoadConfig *sgx_config =
      load_config.MutableExtension(asylo::sgx_load_config);
  sgx_config->mutable_file_enclave_config()->set_enclave_path(enclave_path);
  sgx_config->set_debug(debug_enclave);

  asylo::EnclaveManager *manager = nullptr;
  ASYLO_ASSIGN_OR_RETURN(manager, asylo::EnclaveManager::Instance());
  ASYLO_RETURN_IF_ERROR(manager->LoadEnclave(load_config));
  return absl::OkStatus();
}

asylo::StatusOr<std::string> GrpcClientEnclaveGetTranslation(
    const std::string &address, const std::string &word_to_translate) {
  asylo::EnclaveManager *manager = nullptr;
  ASYLO_ASSIGN_OR_RETURN(manager, asylo::EnclaveManager::Instance());

  asylo::EnclaveClient *client = manager->GetClient(kEnclaveName);
  if (!client) {
    return asylo::Status(asylo::error::FAILED_PRECONDITION,
                         absl::StrCat(kEnclaveName, " not running"));
  }

  // Make the client request a translation from the server.
  asylo::EnclaveInput enclave_input;
  GrpcClientEnclaveInput *input =
      enclave_input.MutableExtension(client_enclave_input);
  input->set_server_address(address);
  input->mutable_translation_request()->set_input_word(word_to_translate);

  asylo::EnclaveOutput enclave_output;
  ASYLO_RETURN_IF_ERROR(client->EnterAndRun(enclave_input, &enclave_output));

  if (!enclave_output.HasExtension(client_enclave_output)) {
    return asylo::Status(
        absl::StatusCode::kInternal,
        "EnclaveOutput missing expected client_enclave_output extension");
  }
  const GrpcClientEnclaveOutput &output =
      enclave_output.GetExtension(client_enclave_output);
  if (output.translation_response().translated_word().empty()) {
    return asylo::Status(absl::StatusCode::kInternal,
                         "GrpcClientEnclaveOutput is missing a translation");
  }
  return output.translation_response().translated_word();
}

asylo::Status DestroyGrpcClientEnclave() {
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

}  // namespace secure_grpc
}  // namespace examples
