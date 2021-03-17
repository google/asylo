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

#include "asylo/identity/attestation/null/null_assertion_generator.h"

#include "absl/status/status.h"
#include "absl/synchronization/mutex.h"
#include "asylo/util/logging.h"
#include "asylo/identity/attestation/null/internal/null_assertion.pb.h"
#include "asylo/identity/attestation/null/internal/null_identity_constants.h"
#include "asylo/platform/common/static_map.h"

namespace asylo {

const char *const NullAssertionGenerator::authority_type_ =
    kNullAssertionAuthority;

NullAssertionGenerator::NullAssertionGenerator() : initialized_(false) {}

Status NullAssertionGenerator::Initialize(const std::string &config) {
  // Verify that this generator has not already been initialized.
  if (IsInitialized()) {
    return absl::FailedPreconditionError("Already initialized");
  }

  absl::MutexLock lock(&initialized_mu_);
  initialized_ = true;
  return absl::OkStatus();
}

bool NullAssertionGenerator::IsInitialized() const {
  absl::MutexLock lock(&initialized_mu_);
  return initialized_;
}

EnclaveIdentityType NullAssertionGenerator::IdentityType() const {
  return identity_type_;
}

std::string NullAssertionGenerator::AuthorityType() const {
  return authority_type_;
}

Status NullAssertionGenerator::CreateAssertionOffer(
    AssertionOffer *offer) const {
  // Verify that this generator has been initialized.
  if (!IsInitialized()) {
    return absl::FailedPreconditionError("Not initialized");
  }

  // Set the identity type and authority type of the offered assertion to be
  // the identity type and authority type of this generator.
  offer->mutable_description()->set_identity_type(IdentityType());
  offer->mutable_description()->set_authority_type(AuthorityType());

  // Assertion offers originating from a NullAssertionGenerator always contain
  // the same additional information. The fixed string is also known to
  // NullAssertionVerifier, which processes offers from this generator.
  offer->set_additional_information(kNullAssertionOfferAdditionalInfo);
  return absl::OkStatus();
}

StatusOr<bool> NullAssertionGenerator::CanGenerate(
    const AssertionRequest &request) const {
  // Verify that this generator has been initialized.
  if (!IsInitialized()) {
    return Status(absl::StatusCode::kFailedPrecondition, "Not initialized");
  }

  return IsValidAssertionRequest(request);
}

Status NullAssertionGenerator::Generate(const std::string &user_data,
                                        const AssertionRequest &request,
                                        Assertion *assertion) const {
  // Verify that this generator has been initialized.
  if (!IsInitialized()) {
    return absl::FailedPreconditionError("Not initialized");
  }

  // This generator simply checks that |request| contains the expected identity
  // type, authority type, and additional information. A non-trivial generator
  // would perform the former two checks, but might also incorporate the
  // request's additional information into the generated assertion.
  if (!IsValidAssertionRequest(request)) {
    return absl::InvalidArgumentError("Invalid assertion request");
  }

  // Set the assertion's description to indicate the identity type and
  // assertion authority type.
  assertion->mutable_description()->set_identity_type(IdentityType());
  assertion->mutable_description()->set_authority_type(AuthorityType());

  // A null assertion is used by an identity with no cryptographic credentials.
  // A null assertion holds the raw data blob provided by the user when
  // generating the assertion. Note that this is not a cryptographic binding, as
  // the blob is stored in its raw form and there is no associated identity
  // binding. In non-trivial assertion types, the user-data should be
  // cryptographically bound to the assertion.
  NullAssertion null_assertion;
  null_assertion.set_user_data(user_data);
  if (!null_assertion.SerializeToString(assertion->mutable_assertion())) {
    return absl::InternalError("Assertion serialization failed");
  }
  return absl::OkStatus();
}

bool NullAssertionGenerator::IsValidAssertionRequest(
    const AssertionRequest &request) const {
  // Check that the identity type and authority type of the requested assertion
  // match the identity type and authority type of this generator.
  return IsCompatibleAssertionDescription(request.description()) &&
         (request.additional_information() ==
          kNullAssertionRequestAdditionalInfo);
}

// Static registration of the NullAssertionGenerator library.
SET_STATIC_MAP_VALUE_OF_DERIVED_TYPE(AssertionGeneratorMap,
                                     NullAssertionGenerator);

}  // namespace asylo
