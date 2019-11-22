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

#include "asylo/identity/sgx/sgx_age_remote_assertion_generator.h"
#include "asylo/identity/sgx/sgx_age_remote_assertion_generator_test_enclave.pb.h"
#include "asylo/identity/sgx/sgx_identity_util.h"
#include "asylo/trusted_application.h"
#include "asylo/util/status_macros.h"

namespace asylo {
namespace sgx {

// The SgxAgeRemoteAssertionGeneratorTestEnclave contains multiple entrypoints
// to call different methods on the underlying SgxAgeRemoteAssertionGenerator.
class SgxAgeRemoteAssertionGeneratorTestEnclave final
    : public TrustedApplication {
 public:
  Status Run(const EnclaveInput &enclave_input,
             EnclaveOutput *enclave_output) override {
    if (!enclave_input.HasExtension(
            sgx_age_remote_assertion_generator_test_enclave_input)) {
      return Status(error::GoogleError::INVALID_ARGUMENT,
                    "EnclaveInput is missing "
                    "SgxAgeRemoteAssertionGeneratorTestEnclaveInput extension");
    }

    const SgxAgeRemoteAssertionGeneratorTestEnclaveInput &input =
        enclave_input.GetExtension(
            sgx_age_remote_assertion_generator_test_enclave_input);
    SgxAgeRemoteAssertionGeneratorTestEnclaveOutput *output =
        enclave_output->MutableExtension(
            sgx_age_remote_assertion_generator_test_enclave_output);

    switch (input.input_case()) {
      case SgxAgeRemoteAssertionGeneratorTestEnclaveInput::
          kSgxSelfIdentityInput:
        *output->mutable_sgx_self_identity_output()->mutable_identity() =
            GetSelfSgxIdentity();
        return Status::OkStatus();

      case SgxAgeRemoteAssertionGeneratorTestEnclaveInput::
          kResetGeneratorInput:
        generator_ = SgxAgeRemoteAssertionGenerator();
        return Status::OkStatus();

      case SgxAgeRemoteAssertionGeneratorTestEnclaveInput::kInitializeInput:
        return generator_.Initialize(input.initialize_input().config());

      case SgxAgeRemoteAssertionGeneratorTestEnclaveInput::kIsInitializedInput:
        output->mutable_is_initialized_output()->set_is_initialized(
            generator_.IsInitialized());
        return Status::OkStatus();

      case SgxAgeRemoteAssertionGeneratorTestEnclaveInput::
          kCreateAssertionOfferInput:
        return generator_.CreateAssertionOffer(
            output->mutable_create_assertion_offer_output()->mutable_offer());

      case SgxAgeRemoteAssertionGeneratorTestEnclaveInput::kCanGenerateInput: {
        bool can_generate;
        ASYLO_ASSIGN_OR_RETURN(
            can_generate,
            generator_.CanGenerate(input.can_generate_input().request()));
        output->mutable_can_generate_output()->set_can_generate(can_generate);
        return Status::OkStatus();
      }

      case SgxAgeRemoteAssertionGeneratorTestEnclaveInput::kGenerateInput:
        return generator_.Generate(
            input.generate_input().user_data(),
            input.generate_input().request(),
            output->mutable_generate_output()->mutable_assertion());

      default:
        return Status(error::GoogleError::INVALID_ARGUMENT,
                      "SgxAgeRemoteAssertionGeneratorTestEnclaveInput not set");
    }
  }

 private:
  SgxAgeRemoteAssertionGenerator generator_;
};

}  // namespace sgx

TrustedApplication *BuildTrustedApplication() {
  return new sgx::SgxAgeRemoteAssertionGeneratorTestEnclave();
}

}  // namespace asylo
