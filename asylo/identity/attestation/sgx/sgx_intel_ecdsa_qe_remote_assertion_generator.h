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

#ifndef ASYLO_IDENTITY_ATTESTATION_SGX_SGX_INTEL_ECDSA_QE_REMOTE_ASSERTION_GENERATOR_H_
#define ASYLO_IDENTITY_ATTESTATION_SGX_SGX_INTEL_ECDSA_QE_REMOTE_ASSERTION_GENERATOR_H_

#include <memory>
#include <string>

#include "asylo/identity/additional_authenticated_data_generator.h"
#include "asylo/identity/attestation/enclave_assertion_generator.h"
#include "asylo/identity/attestation/sgx/internal/dcap_library_interface.h"
#include "asylo/identity/attestation/sgx/internal/intel_architectural_enclave_interface.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/identity/sgx/hardware_interface.h"
#include "asylo/util/mutex_guarded.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

namespace asylo {

class SgxIntelEcdsaQeRemoteAssertionGenerator
    : public EnclaveAssertionGenerator {
 public:
  static const char *const kDefaultConfig;

  // Constructs a new `SgxIntelEcdsaQeAssertionGenerator` that internally uses
  // the `EnclaveDcapLibraryInterface`, which uses ocalls to invoke all
  // Intel DCAP APIs. Default-constructed objects generate assertions suitable
  // for use with EKEP. `HardwareInterface` is used to invoke SGX-specific
  // hardware routines.
  SgxIntelEcdsaQeRemoteAssertionGenerator();

  // Constructs a new `SgxIntelEcdsaQeAssertionGenerator` that uses
  // |intel_enclaves| for invoking the Intel quoting software stack, and
  // generates authenticated data to include in the quote using |aad_generator|.
  // |hardware_interface| is used to invoke SGX-specific hardware routines.
  SgxIntelEcdsaQeRemoteAssertionGenerator(
      std::unique_ptr<AdditionalAuthenticatedDataGenerator> aad_generator,
      std::unique_ptr<asylo::sgx::IntelArchitecturalEnclaveInterface>
          intel_enclaves,
      std::unique_ptr<sgx::HardwareInterface> hardware_interface);

  ~SgxIntelEcdsaQeRemoteAssertionGenerator() override = default;

  Status Initialize(const std::string &config) override;

  bool IsInitialized() const override;

  EnclaveIdentityType IdentityType() const override;

  std::string AuthorityType() const override;

  Status CreateAssertionOffer(AssertionOffer *offer) const override;

  StatusOr<bool> CanGenerate(const AssertionRequest &request) const override;

  Status Generate(const std::string &user_data, const AssertionRequest &request,
                  Assertion *assertion) const override;

 private:
  MutexGuarded<bool> is_initialized_{false};
  std::unique_ptr<AdditionalAuthenticatedDataGenerator> aad_generator_;
  std::unique_ptr<asylo::sgx::IntelArchitecturalEnclaveInterface>
      intel_enclaves_;
  std::unique_ptr<sgx::HardwareInterface> hardware_interface_;
};

}  // namespace asylo

#endif  // ASYLO_IDENTITY_ATTESTATION_SGX_SGX_INTEL_ECDSA_QE_REMOTE_ASSERTION_GENERATOR_H_
