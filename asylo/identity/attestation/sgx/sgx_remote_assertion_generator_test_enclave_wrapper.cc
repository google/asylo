/*
 *
 * Copyright 2020 Asylo authors
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

#include "asylo/identity/attestation/sgx/sgx_remote_assertion_generator_test_enclave_wrapper.h"

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "asylo/client.h"
#include "asylo/enclave.pb.h"
#include "asylo/enclave_manager.h"
#include "asylo/identity/attestation/sgx/sgx_remote_assertion_generator_test_enclave.pb.h"
#include "asylo/identity/platform/sgx/sgx_identity.pb.h"
#include "asylo/platform/core/enclave_client.h"
#include "asylo/platform/primitives/sgx/loader.pb.h"
#include "asylo/test/util/enclave_assertion_authority_configs.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace {

constexpr char kEnclaveName[] = "Remote Assertion Generator Enclave";

StatusOr<sgx::SgxRemoteAssertionGeneratorTestEnclaveOutput> CallTestEnclave(
    EnclaveClient *client,
    sgx::SgxRemoteAssertionGeneratorTestEnclaveInput input) {
  EnclaveInput enclave_input;
  *enclave_input.MutableExtension(
      sgx::sgx_remote_assertion_generator_test_enclave_input) =
      std::move(input);

  EnclaveOutput enclave_output;
  ASYLO_RETURN_IF_ERROR(client->EnterAndRun(enclave_input, &enclave_output));
  if (!enclave_output.HasExtension(
          sgx::sgx_remote_assertion_generator_test_enclave_output)) {
    return Status(absl::StatusCode::kNotFound,
                  absl::StrCat("The test enclave did not return the expected "
                               "extension to EnclaveOutput: ",
                               enclave_output.ShortDebugString()));
  }

  return enclave_output.GetExtension(
      sgx::sgx_remote_assertion_generator_test_enclave_output);
}

}  // namespace

StatusOr<std::unique_ptr<SgxRemoteAssertionGeneratorTestEnclaveWrapper>>
SgxRemoteAssertionGeneratorTestEnclaveWrapper::Load(
    asylo::EnclaveManager *enclave_manager, const std::string &enclave_path,
    sgx::SgxRemoteAssertionGeneratorTestEnclaveConfig test_enclave_config) {
  EnclaveLoadConfig load_config;
  load_config.set_name(kEnclaveName);

  EnclaveConfig *enclave_config = load_config.mutable_config();
  *enclave_config->add_enclave_assertion_authority_configs() =
      GetSgxLocalAssertionAuthorityTestConfig();
  *enclave_config->MutableExtension(
      sgx::sgx_remote_assertion_generator_test_enclave_config) =
      std::move(test_enclave_config);

  SgxLoadConfig *sgx_config = load_config.MutableExtension(sgx_load_config);
  sgx_config->mutable_file_enclave_config()->set_enclave_path(enclave_path);
  sgx_config->set_debug(true);

  ASYLO_RETURN_IF_ERROR(enclave_manager->LoadEnclave(load_config));
  return absl::make_unique<SgxRemoteAssertionGeneratorTestEnclaveWrapper>(
      enclave_manager, enclave_manager->GetClient(kEnclaveName));
}

SgxRemoteAssertionGeneratorTestEnclaveWrapper::
    SgxRemoteAssertionGeneratorTestEnclaveWrapper(
        EnclaveManager *enclave_manager, EnclaveClient *enclave_client)
    : enclave_manager_(enclave_manager), enclave_client_(enclave_client) {
  CHECK_NE(enclave_manager_, nullptr);
  CHECK_NE(enclave_client_, nullptr);
}

SgxRemoteAssertionGeneratorTestEnclaveWrapper::
    ~SgxRemoteAssertionGeneratorTestEnclaveWrapper() {
  enclave_manager_->DestroyEnclave(enclave_client_, EnclaveFinal{});
}

Status SgxRemoteAssertionGeneratorTestEnclaveWrapper::ResetGenerator() {
  sgx::SgxRemoteAssertionGeneratorTestEnclaveInput input;
  *input.mutable_reset_generator_input() = sgx::ResetGeneratorInput();
  return CallTestEnclave(enclave_client_, std::move(input)).status();
}

StatusOr<SgxIdentity>
SgxRemoteAssertionGeneratorTestEnclaveWrapper::GetSgxSelfIdentity() {
  sgx::SgxRemoteAssertionGeneratorTestEnclaveInput input;
  *input.mutable_sgx_self_identity_input() = sgx::SgxSelfIdentityInput();

  sgx::SgxRemoteAssertionGeneratorTestEnclaveOutput output;
  ASYLO_ASSIGN_OR_RETURN(output,
                         CallTestEnclave(enclave_client_, std::move(input)));
  return output.sgx_self_identity_output().identity();
}

StatusOr<bool> SgxRemoteAssertionGeneratorTestEnclaveWrapper::IsInitialized() {
  sgx::SgxRemoteAssertionGeneratorTestEnclaveInput input;
  *input.mutable_is_initialized_input() = sgx::IsInitializedInput();

  sgx::SgxRemoteAssertionGeneratorTestEnclaveOutput output;
  ASYLO_ASSIGN_OR_RETURN(output,
                         CallTestEnclave(enclave_client_, std::move(input)));
  return output.is_initialized_output().is_initialized();
}

Status SgxRemoteAssertionGeneratorTestEnclaveWrapper::Initialize(
    const std::string &config) {
  sgx::SgxRemoteAssertionGeneratorTestEnclaveInput input;
  input.mutable_initialize_input()->set_config(config);
  return CallTestEnclave(enclave_client_, std::move(input)).status();
}

StatusOr<AssertionOffer>
SgxRemoteAssertionGeneratorTestEnclaveWrapper::CreateAssertionOffer() {
  sgx::SgxRemoteAssertionGeneratorTestEnclaveInput input;
  *input.mutable_create_assertion_offer_input() =
      sgx::CreateAssertionOfferInput::default_instance();

  sgx::SgxRemoteAssertionGeneratorTestEnclaveOutput output;
  ASYLO_ASSIGN_OR_RETURN(output,
                         CallTestEnclave(enclave_client_, std::move(input)));
  return output.create_assertion_offer_output().offer();
}

StatusOr<bool> SgxRemoteAssertionGeneratorTestEnclaveWrapper::CanGenerate(
    AssertionRequest request) {
  sgx::SgxRemoteAssertionGeneratorTestEnclaveInput input;
  *input.mutable_can_generate_input()->mutable_request() = std::move(request);

  sgx::SgxRemoteAssertionGeneratorTestEnclaveOutput output;
  ASYLO_ASSIGN_OR_RETURN(output,
                         CallTestEnclave(enclave_client_, std::move(input)));
  return output.can_generate_output().can_generate();
}

StatusOr<Assertion> SgxRemoteAssertionGeneratorTestEnclaveWrapper::Generate(
    std::string user_data, AssertionRequest request) {
  sgx::SgxRemoteAssertionGeneratorTestEnclaveInput input;
  sgx::GenerateInput *generate_input = input.mutable_generate_input();
  generate_input->set_user_data(std::move(user_data));
  *generate_input->mutable_request() = std::move(request);

  sgx::SgxRemoteAssertionGeneratorTestEnclaveOutput output;
  ASYLO_ASSIGN_OR_RETURN(output,
                         CallTestEnclave(enclave_client_, std::move(input)));
  return output.generate_output().assertion();
}

}  // namespace asylo
