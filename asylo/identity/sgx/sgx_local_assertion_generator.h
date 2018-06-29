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

#ifndef ASYLO_IDENTITY_SGX_SGX_LOCAL_ASSERTION_GENERATOR_H_
#define ASYLO_IDENTITY_SGX_SGX_LOCAL_ASSERTION_GENERATOR_H_

#include "asylo/identity/enclave_assertion_generator.h"

#include "absl/synchronization/mutex.h"
#include "asylo/identity/sgx/local_assertion.pb.h"

namespace asylo {

/// An implementation of the EnclaveAssertionGenerator interface for SGX local
/// assertions.
///
/// An SgxLocalAssertionGenerator is capable of generating assertion offers and
/// assertions for SGX code identities that can be verified by SGX enclaves
/// running within the same local attestation domain.
class SgxLocalAssertionGenerator final : public EnclaveAssertionGenerator {
 public:
  /// Constructs an uninitialized SgxLocalAssertionGenerator.
  ///
  /// The generator can be initialized via a call to Initialize().
  SgxLocalAssertionGenerator();

  ///////////////////////////////////////////
  //   From AssertionAuthority interface.  //
  ///////////////////////////////////////////

  Status Initialize(const std::string &config) override;

  bool IsInitialized() const override;

  EnclaveIdentityType IdentityType() const override;

  std::string AuthorityType() const override;

  ///////////////////////////////////////////
  //   From AssertionGenerator interface.  //
  ///////////////////////////////////////////

  Status CreateAssertionOffer(AssertionOffer *offer) const override;

  StatusOr<bool> CanGenerate(const AssertionRequest &request) const override;

  Status Generate(const std::string &user_data, const AssertionRequest &request,
                  Assertion *assertion) const override;

 private:
  // Parses additional information from the given |request|. Returns the
  // LocalAssertionRequestAdditionalInfo on success. Returns a non-OK status on
  // parsing failure.
  StatusOr<sgx::LocalAssertionRequestAdditionalInfo> ParseAdditionalInfo(
      const AssertionRequest &request) const;

  // The identity type handled by this generator.
  static constexpr EnclaveIdentityType identity_type_ = CODE_IDENTITY;

  // The authority type handled by this generator.
  static const char *const authority_type_;

  // The attestation domain to which the enclave belongs.
  std::string attestation_domain_;

  // Indicates whether this generator has been initialized.
  bool initialized_ GUARDED_BY(initialized_mu_);

  // A mutex that guards the initialized_ member.
  mutable absl::Mutex initialized_mu_;
};

}  // namespace asylo

#endif  // ASYLO_IDENTITY_SGX_SGX_LOCAL_ASSERTION_GENERATOR_H_
