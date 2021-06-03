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

#ifndef ASYLO_IDENTITY_ATTESTATION_ENCLAVE_ASSERTION_VERIFIER_H_
#define ASYLO_IDENTITY_ATTESTATION_ENCLAVE_ASSERTION_VERIFIER_H_

#include <string>

#include "asylo/identity/enclave_assertion_authority.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/platform/common/static_map.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

namespace asylo {

/// Defines an interface for assertion authorities that generate assertion
/// requests and verify assertions.
///
/// EnclaveAssertionVerifier cannot be instantiated; it is intended to be
/// derived from by classes that implement the EnclaveAssertionVerifier
/// interface for a particular identity type and authority type.
///
/// Derived classes of EnclaveAssertionVerifier must:
///   * Be marked final
///   * Be trivially default-constructible
///
/// Derived classes of EnclaveAssertionVerifier must also implement virtual
/// methods presented by EnclaveAssertionAuthority.
class EnclaveAssertionVerifier : public EnclaveAssertionAuthority {
 public:
  /// Creates an assertion request compatible with this verifier's identity type
  /// and authority type and places the result in `request`.
  ///
  /// \param[out] request The generated request.
  /// \return A Status indicating whether the request was created. Returns a
  ///         non-OK Status if this verifier is not initialized or if an
  ///         internal error occurs while attempting the operation.
  virtual Status CreateAssertionRequest(AssertionRequest *request) const = 0;

  /// Indicates whether the assertion offered in `offer` can be verified by this
  /// verifier.
  ///
  /// \return True if the offer can be verified, and false if no errors occurred
  ///         during the operation but `offer` cannot be fulfilled. Returns a
  ///         non-OK Status if the verifier is not initialized or if an internal
  ///         error occurs while attempting the operation.
  virtual StatusOr<bool> CanVerify(const AssertionOffer &offer) const = 0;

  /// Verifies an assertion that is compatible with this verifier's identity
  /// type and authority type.
  ///
  /// The verification operation verifies that the `assertion`'s identity claim
  /// is valid, and also checks that the assertion is bound to `user_data`. If
  /// verification succeeds, returns an OK Status and extracts the peer's
  /// identity into `peer_identity`. The caller cannot make any assumptions
  /// about the contents of `peer_identity` if verification fails.
  ///
  /// \param user_data User-provided binding data.
  /// \param assertion An assertion to verify.
  /// \param[out] peer_identity The identity extracted from the assertion.
  /// \return A Status indicating whether the assertion was verified
  ///         successfully. Returns a non-OK Status if this verifier is not
  ///         initialized or if an internal error occurs while attempting the
  ///         operation.
  virtual Status Verify(const std::string &user_data,
                        const Assertion &assertion,
                        EnclaveIdentity *peer_identity) const = 0;
};

// \cond Internal
template <>
struct Namer<EnclaveAssertionVerifier> {
  std::string operator()(const EnclaveAssertionVerifier &verifier) {
    return EnclaveAssertionAuthority::GenerateAuthorityId(
               verifier.IdentityType(), verifier.AuthorityType())
        .value();
  }
};

DEFINE_STATIC_MAP_OF_BASE_TYPE(AssertionVerifierMap, EnclaveAssertionVerifier);
// \endcond

}  // namespace asylo

#endif  // ASYLO_IDENTITY_ATTESTATION_ENCLAVE_ASSERTION_VERIFIER_H_
