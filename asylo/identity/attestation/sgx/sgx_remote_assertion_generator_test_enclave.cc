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

#include <memory>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "asylo/identity/attestation/sgx/sgx_age_remote_assertion_generator.h"
#include "asylo/identity/attestation/sgx/sgx_intel_ecdsa_qe_remote_assertion_generator.h"
#include "asylo/identity/attestation/sgx/sgx_remote_assertion_generator_test_enclave.pb.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/identity/platform/sgx/internal/code_identity_constants.h"
#include "asylo/identity/platform/sgx/sgx_identity_util.h"
#include "asylo/trusted_application.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"

namespace asylo {
namespace sgx {
namespace {

// The SgxRemoteAssertionGeneratorTestEnclave contains multiple entrypoints
// to call different methods on the underlying EnclaveAssertionGenerator.
class SgxRemoteAssertionGeneratorTestEnclave final : public TrustedApplication {
 public:
  Status Initialize(const EnclaveConfig &config) override {
    if (!config.HasExtension(
            sgx_remote_assertion_generator_test_enclave_config)) {
      return absl::InvalidArgumentError(
          "EnclaveConfig is missing "
          "SgxRemoteAssertionGeneratorTestEnclaveConfig extension");
    }

    AssertionDescription assertion_description =
        config.GetExtension(sgx_remote_assertion_generator_test_enclave_config)
            .description();
    return ResetGenerator(assertion_description.identity_type(),
                          assertion_description.authority_type());
  }

  Status Run(const EnclaveInput &enclave_input,
             EnclaveOutput *enclave_output) override {
    if (!enclave_input.HasExtension(
            sgx_remote_assertion_generator_test_enclave_input)) {
      return absl::InvalidArgumentError(
          "EnclaveInput is missing "
          "SgxRemoteAssertionGeneratorTestEnclaveInput extension");
    }

    const SgxRemoteAssertionGeneratorTestEnclaveInput &input =
        enclave_input.GetExtension(
            sgx_remote_assertion_generator_test_enclave_input);
    SgxRemoteAssertionGeneratorTestEnclaveOutput *output =
        enclave_output->MutableExtension(
            sgx_remote_assertion_generator_test_enclave_output);

    switch (input.input_case()) {
      case SgxRemoteAssertionGeneratorTestEnclaveInput::kSgxSelfIdentityInput:
        *output->mutable_sgx_self_identity_output()->mutable_identity() =
            GetSelfSgxIdentity();
        return absl::OkStatus();

      case SgxRemoteAssertionGeneratorTestEnclaveInput::kResetGeneratorInput:
        return ResetGenerator(generator_->IdentityType(),
                              generator_->AuthorityType());

      case SgxRemoteAssertionGeneratorTestEnclaveInput::kInitializeInput:
        return generator_->Initialize(input.initialize_input().config());

      case SgxRemoteAssertionGeneratorTestEnclaveInput::kIsInitializedInput:
        output->mutable_is_initialized_output()->set_is_initialized(
            generator_->IsInitialized());
        return absl::OkStatus();

      case SgxRemoteAssertionGeneratorTestEnclaveInput::
          kCreateAssertionOfferInput:
        return generator_->CreateAssertionOffer(
            output->mutable_create_assertion_offer_output()->mutable_offer());

      case SgxRemoteAssertionGeneratorTestEnclaveInput::kCanGenerateInput: {
        bool can_generate;
        ASYLO_ASSIGN_OR_RETURN(
            can_generate,
            generator_->CanGenerate(input.can_generate_input().request()));
        output->mutable_can_generate_output()->set_can_generate(can_generate);
        return absl::OkStatus();
      }

      case SgxRemoteAssertionGeneratorTestEnclaveInput::kGenerateInput:
        return generator_->Generate(
            input.generate_input().user_data(),
            input.generate_input().request(),
            output->mutable_generate_output()->mutable_assertion());

      default:
        return absl::InvalidArgumentError(
            "SgxRemoteAssertionGeneratorTestEnclaveInput not set");
    }
  }

 private:
  Status ResetGenerator(EnclaveIdentityType identity_type,
                        absl::string_view authority_type) {
    if (identity_type == CODE_IDENTITY) {
      if (authority_type == kSgxAgeRemoteAssertionAuthority) {
        generator_ = absl::make_unique<SgxAgeRemoteAssertionGenerator>();
        return absl::OkStatus();
      } else if (authority_type == kSgxIntelEcdsaQeRemoteAssertionAuthority) {
        generator_ =
            absl::make_unique<SgxIntelEcdsaQeRemoteAssertionGenerator>();
        return absl::OkStatus();
      }
    }

    return absl::InvalidArgumentError(absl::StrFormat(
        R"(SgxRemoteAssertionGeneratorTestEnclave was configured with an "
            "unsupported assertion identity %d "%s" and type "%s")",
        identity_type, EnclaveIdentityType_Name(identity_type),
        authority_type));
  }

  std::unique_ptr<EnclaveAssertionGenerator> generator_;
};

}  // namespace
}  // namespace sgx

TrustedApplication *BuildTrustedApplication() {
  return new sgx::SgxRemoteAssertionGeneratorTestEnclave();
}

}  // namespace asylo
