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

#include "asylo/identity/attestation/null/null_assertion_verifier.h"

#include "absl/status/status.h"
#include "absl/synchronization/mutex.h"
#include "asylo/util/logging.h"
#include "asylo/identity/attestation/null/internal/null_assertion.pb.h"
#include "asylo/identity/attestation/null/internal/null_identity_constants.h"
#include "asylo/identity/attestation/null/null_identity_util.h"
#include "asylo/identity/descriptions.h"
#include "asylo/platform/common/static_map.h"

namespace asylo {

const char *const NullAssertionVerifier::authority_type_ =
    kNullAssertionAuthority;

NullAssertionVerifier::NullAssertionVerifier() : initialized_(false) {}

Status NullAssertionVerifier::Initialize(const std::string &config) {
  // Verify that this verifier has not already been initialized.
  if (IsInitialized()) {
    return absl::FailedPreconditionError("Already initialized");
  }

  absl::MutexLock lock(&initialized_mu_);
  initialized_ = true;
  return absl::OkStatus();
}

bool NullAssertionVerifier::IsInitialized() const {
  absl::MutexLock lock(&initialized_mu_);
  return initialized_;
}

EnclaveIdentityType NullAssertionVerifier::IdentityType() const {
  return identity_type_;
}

std::string NullAssertionVerifier::AuthorityType() const {
  return authority_type_;
}

Status NullAssertionVerifier::CreateAssertionRequest(
    AssertionRequest *request) const {
  // Verify that this verifier has been initialized.
  if (!IsInitialized()) {
    return absl::FailedPreconditionError("Not initialized");
  }

  // Set the identity type and authority type of the requested assertion to be
  // the identity type and authority type of this verifier.
  request->mutable_description()->set_identity_type(IdentityType());
  request->mutable_description()->set_authority_type(AuthorityType());

  // Assertion requests originating from a NullAssertionVerifier always contain
  // the same additional information. The fixed string is also known to
  // NullAssertionGenerator, which processes requests from this verifier.
  request->set_additional_information(kNullAssertionRequestAdditionalInfo);
  return absl::OkStatus();
}

StatusOr<bool> NullAssertionVerifier::CanVerify(
    const AssertionOffer &offer) const {
  // Verify that this verifier has been initialized.
  if (!IsInitialized()) {
    return Status(absl::StatusCode::kFailedPrecondition, "Not initialized");
  }

  // Check that the identity type and authority type of the offered assertion
  // match the identity type and authority type of this verifier.
  return IsCompatibleAssertionDescription(offer.description()) &&
         (offer.additional_information() == kNullAssertionOfferAdditionalInfo);
}

Status NullAssertionVerifier::Verify(const std::string &user_data,
                                     const Assertion &assertion,
                                     EnclaveIdentity *peer_identity) const {
  // Verify that this verifier has been initialized.
  if (!IsInitialized()) {
    return absl::FailedPreconditionError("Not initialized");
  }

  // Check that the assertion has the identity type and authority type of this
  // verifier.
  if (!IsCompatibleAssertionDescription(assertion.description())) {
    return absl::InvalidArgumentError("Invalid assertion description");
  }

  // Verify that the body of the assertion is a serialized NullAssertion
  // containing the user-provided data blob.
  NullAssertion null_assertion;
  if (!null_assertion.ParseFromString(assertion.assertion())) {
    return absl::InternalError("Assertion deserialization failed");
  }
  if (null_assertion.user_data() != user_data) {
    return absl::InvalidArgumentError(
        "Assertion verification failed: assertion is not bound to user_data");
  }

  // If verification of the assertion succeeds, then the identity is extracted.
  // Null assertions do not carry any specific identity information and,
  // consequently, the peer's identity is a fixed string that is constant
  // between all null assertions. In contrast, a non-trivial verifier would
  // extract some meaningful identity information from the assertion. Note that
  // the description of the extracted identity is different from the description
  // of the generator since the description represents an enclave identity, not
  // an assertion.
  SetNullIdentityDescription(peer_identity->mutable_description());
  peer_identity->set_identity(kNullIdentity);

  // Verification succeeded.
  return absl::OkStatus();
}

// Static registration of the NullAssertionVerifier library.
SET_STATIC_MAP_VALUE_OF_DERIVED_TYPE(AssertionVerifierMap,
                                     NullAssertionVerifier);

}  // namespace asylo
