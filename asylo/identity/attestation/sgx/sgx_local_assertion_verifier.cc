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

#include "asylo/identity/attestation/sgx/sgx_local_assertion_verifier.h"

#include <cstdint>
#include <string>
#include <vector>

#include "absl/status/status.h"
#include "absl/synchronization/mutex.h"
#include "asylo/crypto/util/bytes.h"
#include "asylo/crypto/util/trivial_object_util.h"
#include "asylo/identity/additional_authenticated_data_generator.h"
#include "asylo/identity/attestation/sgx/internal/local_assertion.pb.h"
#include "asylo/identity/attestation/sgx/sgx_local_assertion_authority_config.pb.h"
#include "asylo/identity/descriptions.h"
#include "asylo/identity/platform/sgx/internal/code_identity_constants.h"
#include "asylo/identity/platform/sgx/internal/identity_key_management_structs.h"
#include "asylo/identity/platform/sgx/internal/sgx_identity_util_internal.h"
#include "asylo/util/status_macros.h"

namespace asylo {

const char *const SgxLocalAssertionVerifier::authority_type_ =
    sgx::kSgxLocalAssertionAuthority;

SgxLocalAssertionVerifier::SgxLocalAssertionVerifier() : initialized_(false) {}

Status SgxLocalAssertionVerifier::Initialize(const std::string &config) {
  if (IsInitialized()) {
    return absl::FailedPreconditionError("Already initialized");
  }

  SgxLocalAssertionAuthorityConfig authority_config;
  if (!authority_config.ParseFromString(config)) {
    return absl::InvalidArgumentError("Could not parse input config");
  }

  if (!authority_config.has_attestation_domain()) {
    return absl::InvalidArgumentError("Config is missing attestation domain");
  }

  attestation_domain_ = authority_config.attestation_domain();

  aad_generator_ =
      AdditionalAuthenticatedDataGenerator::CreateEkepAadGenerator();

  absl::MutexLock lock(&initialized_mu_);
  initialized_ = true;

  return absl::OkStatus();
}

bool SgxLocalAssertionVerifier::IsInitialized() const {
  absl::MutexLock lock(&initialized_mu_);
  return initialized_;
}

EnclaveIdentityType SgxLocalAssertionVerifier::IdentityType() const {
  return identity_type_;
}

std::string SgxLocalAssertionVerifier::AuthorityType() const {
  return authority_type_;
}

Status SgxLocalAssertionVerifier::CreateAssertionRequest(
    AssertionRequest *request) const {
  if (!IsInitialized()) {
    return absl::FailedPreconditionError("Not initialized");
  }

  request->mutable_description()->set_identity_type(IdentityType());
  request->mutable_description()->set_authority_type(AuthorityType());

  sgx::LocalAssertionRequestAdditionalInfo additional_info;
  additional_info.set_local_attestation_domain(attestation_domain_);

  // The request contains a dump of the raw TARGETINFO structure, which
  // specifies the verifier as the target for the requested assertion. Note that
  // since the layout and endianness of the TARGETINFO structure is defined by
  // the Intel SGX architecture, it is safe to exchange the raw bytes of the
  // structure. An SGX enclave that receives the request can reconstruct the
  // original structure directly from the byte field in the AssertionRequest
  // proto.
  sgx::Targetinfo targetinfo;
  sgx::SetTargetinfoFromSelfIdentity(&targetinfo);
  additional_info.set_targetinfo(
      ConvertTrivialObjectToBinaryString(targetinfo));

  if (!additional_info.SerializeToString(
          request->mutable_additional_information())) {
    return absl::InternalError(
        "Failed to serialize LocalAssertionRequestAdditionalInfo");
  }

  return absl::OkStatus();
}

StatusOr<bool> SgxLocalAssertionVerifier::CanVerify(
    const AssertionOffer &offer) const {
  if (!IsInitialized()) {
    return Status(absl::StatusCode::kFailedPrecondition, "Not initialized");
  }

  if (!IsCompatibleAssertionDescription(offer.description())) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "AssertionOffer has incompatible assertion description");
  }

  sgx::LocalAssertionOfferAdditionalInfo additional_info;
  if (!additional_info.ParseFromString(offer.additional_information())) {
    return Status(absl::StatusCode::kInternal,
                  "Failed to parse offer additional information");
  }

  return additional_info.local_attestation_domain() == attestation_domain_;
}

Status SgxLocalAssertionVerifier::Verify(const std::string &user_data,
                                         const Assertion &assertion,
                                         EnclaveIdentity *peer_identity) const {
  if (!IsInitialized()) {
    return absl::FailedPreconditionError("Not initialized");
  }

  if (!IsCompatibleAssertionDescription(assertion.description())) {
    return absl::InvalidArgumentError(
        "Assertion has incompatible assertion description");
  }

  sgx::LocalAssertion local_assertion;
  if (!local_assertion.ParseFromString(assertion.assertion())) {
    return absl::InternalError("Failed to parse LocalAssertion");
  }

  // First, verify the hardware REPORT embedded in the assertion. This will only
  // succeed if the REPORT is targeted at this enclave. Note that since the
  // layout and endianness of the REPORT structure is defined by the Intel SGX
  // architecture, two SGX enclaves can exchange a REPORT by simply dumping the
  // raw bytes of a REPORT structure into a proto. This code assumes that the
  // assertion originates from a machine that supports the Intel SGX
  // architecture and was copied into the assertion byte-for-byte, so is safe to
  // restore the REPORT structure directly from the deserialized LocalAssertion.
  sgx::Report report;
  ASYLO_RETURN_IF_ERROR(SetTrivialObjectFromBinaryString<sgx::Report>(
      local_assertion.report(), &report));
  ASYLO_RETURN_IF_ERROR(sgx::VerifyHardwareReport(report));

  // Next, verify that the REPORT is cryptographically-bound to the provided
  // |user_data|. This is done by re-constructing the expected REPORTDATA (a
  // SHA256 hash of |user_data| concatenated with the purpose and uuid set by
  // the EKEP AAD specified at
  // asylo/identity/additional_authenticated_data_generator.cc.), and comparing
  // it to the actual REPORTDATA inside the REPORT.
  sgx::Reportdata expected_reportdata;
  UnsafeBytes<kAdditionalAuthenticatedDataSize> aad;
  ASYLO_ASSIGN_OR_RETURN(aad, aad_generator_->Generate(user_data));
  expected_reportdata.data = aad;

  if (expected_reportdata.data != report.body.reportdata.data) {
    return absl::InternalError(
        "Assertion is not bound to the provided user-data");
  }

  // Serialize the protobuf representation of the peer's SGX identity and save
  // it in |peer_identity|.
  SgxIdentity sgx_identity =
      sgx::ParseSgxIdentityFromHardwareReport(report.body);
  ASYLO_RETURN_IF_ERROR(sgx::SerializeSgxIdentity(sgx_identity, peer_identity));

  return absl::OkStatus();
}

// Static registration of the LocalAssertionVerifier library.
SET_STATIC_MAP_VALUE_OF_DERIVED_TYPE(AssertionVerifierMap,
                                     SgxLocalAssertionVerifier);

}  // namespace asylo
