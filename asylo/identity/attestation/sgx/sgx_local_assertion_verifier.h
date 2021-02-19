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

#ifndef ASYLO_IDENTITY_ATTESTATION_SGX_SGX_LOCAL_ASSERTION_VERIFIER_H_
#define ASYLO_IDENTITY_ATTESTATION_SGX_SGX_LOCAL_ASSERTION_VERIFIER_H_

#include "absl/synchronization/mutex.h"
#include "asylo/identity/additional_authenticated_data_generator.h"
#include "asylo/identity/attestation/enclave_assertion_verifier.h"

namespace asylo {

/// An implemention of the EnclaveAssertionVerifier interface for SGX local
/// assertions.
///
/// An SgxLocalAssertionVerifier is capable of verifying assertions of SGX code
/// identity that originate from SGX enclaves running within the same local
/// attestation domain.
class SgxLocalAssertionVerifier final : public EnclaveAssertionVerifier {
 public:
  /// Constructs an uninitialized SgxLocalAssertionVerifier.
  ///
  /// The verifier can be initialized via a call to Initialize().
  SgxLocalAssertionVerifier();

  ///////////////////////////////////////////
  //   From AssertionAuthority interface.  //
  ///////////////////////////////////////////

  Status Initialize(const std::string &config) override;

  bool IsInitialized() const override;

  EnclaveIdentityType IdentityType() const override;

  std::string AuthorityType() const override;

  ///////////////////////////////////////////
  //    From AssertionVerifier interface.  //
  ///////////////////////////////////////////

  Status CreateAssertionRequest(AssertionRequest *request) const override;

  StatusOr<bool> CanVerify(const AssertionOffer &offer) const override;

  Status Verify(const std::string &user_data, const Assertion &assertion,
                EnclaveIdentity *peer_identity) const override;

 private:
  // The identity type handled by this verifier.
  static constexpr EnclaveIdentityType identity_type_ = CODE_IDENTITY;

  // The authority type handled by this verifier.
  static const char *const authority_type_;

  // The attestation domain to which the enclave belongs.
  std::string attestation_domain_;

  // Generates REPORTDATA that is verified as part of the attestation.
  std::unique_ptr<AdditionalAuthenticatedDataGenerator> aad_generator_;

  // Indicates whether this verifier has been initialized.
  bool initialized_ ABSL_GUARDED_BY(initialized_mu_);

  // A mutex that guards the initialized_ member.
  mutable absl::Mutex initialized_mu_;
};

}  // namespace asylo

#endif  // ASYLO_IDENTITY_ATTESTATION_SGX_SGX_LOCAL_ASSERTION_VERIFIER_H_
