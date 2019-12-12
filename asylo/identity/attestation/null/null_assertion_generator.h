/*
 *
 * Copyright 2017 Asylo authors
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

#ifndef ASYLO_IDENTITY_ATTESTATION_NULL_NULL_ASSERTION_GENERATOR_H_
#define ASYLO_IDENTITY_ATTESTATION_NULL_NULL_ASSERTION_GENERATOR_H_

#include <string>

#include "absl/synchronization/mutex.h"
#include "asylo/identity/attestation/enclave_assertion_generator.h"

namespace asylo {

/// An implementation of the EnclaveAssertionGenerator interface for null
/// assertions.
///
/// NullAssertionGenerator generates assertions based on assertion requests from
/// a NullAssertionVerifier. The generated assertions have no cryptographic
/// bindings and are trivially verifiable by a NullAssertionVerifier.
class NullAssertionGenerator final : public EnclaveAssertionGenerator {
 public:
  /// Constructs an uninitialized NullAssertionGenerator.
  ///
  /// The generator can be initialized via a call to Initialize().
  NullAssertionGenerator();

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
  // Returns true if the given |request| is a valid AssertionRequest for this
  // generator.
  bool IsValidAssertionRequest(const AssertionRequest &request) const;

  // Indicates whether this generator has been initialized.
  bool initialized_ ABSL_GUARDED_BY(initialized_mu_);

  // A mutex that guards the initialized_ member.
  mutable absl::Mutex initialized_mu_;

  // The type of this assertion authority.
  static const char *const authority_type_;

  // The type of enclave identity handled by this generator.
  static constexpr EnclaveIdentityType identity_type_ = NULL_IDENTITY;
};

}  // namespace asylo

#endif  // ASYLO_IDENTITY_ATTESTATION_NULL_NULL_ASSERTION_GENERATOR_H_
