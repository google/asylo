/*
 *
 * Copyright 2020 Asylo authors
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
#include "asylo/identity/attestation/sgx/sgx_age_remote_assertion_verifier.h"

#include <algorithm>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "asylo/crypto/certificate_util.h"
#include "asylo/crypto/x509_certificate.h"
#include "asylo/identity/attestation/sgx/internal/attestation_key_certificate_impl.h"
#include "asylo/identity/attestation/sgx/internal/certificate_util.h"
#include "asylo/identity/attestation/sgx/internal/remote_assertion.pb.h"
#include "asylo/identity/attestation/sgx/internal/remote_assertion_util.h"
#include "asylo/identity/attestation/sgx/sgx_age_remote_assertion_authority_config.pb.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/identity/platform/sgx/internal/code_identity_constants.h"
#include "asylo/identity/platform/sgx/sgx_identity_util.h"
#include "asylo/util/cleanup.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace {

StatusOr<sgx::RemoteAssertionOfferAdditionalInfo> ParseAdditionalInfo(
    const AssertionOffer &offer) {
  sgx::RemoteAssertionOfferAdditionalInfo offer_additional_info;
  if (!offer_additional_info.ParseFromString(offer.additional_information())) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "Failed to parse offer additional information");
  }

  return offer_additional_info;
}

}  // namespace

Status SgxAgeRemoteAssertionVerifier::Initialize(const std::string &config) {
  auto members_view = members_.Lock();
  if (members_view->initialized) {
    return absl::FailedPreconditionError("Already initialized");
  }

  SgxAgeRemoteAssertionAuthorityConfig authority_config;

  if (!authority_config.ParseFromString(config)) {
    return absl::InternalError("Could not parse input config");
  }

  if (!authority_config.has_intel_root_certificate()) {
    return absl::InvalidArgumentError(
        "Configuration must include the Intel root certificate");
  }

  if (!authority_config.has_age_identity_expectation()) {
    return absl::InvalidArgumentError(
        "Configuration must include identity expectation for the AGE");
  }

  Cleanup cleanup_members_view([&members_view]() { *members_view = {}; });

  ASYLO_ASSIGN_OR_RETURN(
      members_view->intel_root_certificate,
      CreateCertificateInterface(*sgx::GetSgxCertificateFactories(),
                                 authority_config.intel_root_certificate()));

  members_view->additional_root_certificates.reserve(
      authority_config.root_ca_certificates_size());
  for (const Certificate &cert_proto :
       authority_config.root_ca_certificates()) {
    std::unique_ptr<CertificateInterface> cert;
    ASYLO_ASSIGN_OR_RETURN(
        cert, CreateCertificateInterface(*sgx::GetSgxCertificateFactories(),
                                         cert_proto));
    members_view->additional_root_certificates.emplace_back(std::move(cert));
  }

  members_view->age_identity_expectation =
      authority_config.age_identity_expectation();

  members_view->assertion_request.mutable_description()->set_identity_type(
      IdentityType());
  members_view->assertion_request.mutable_description()->set_authority_type(
      AuthorityType());

  sgx::RemoteAssertionRequestAdditionalInfo additional_info;
  additional_info.mutable_root_ca_certificates()->CopyFrom(
      authority_config.root_ca_certificates());
  *additional_info.add_root_ca_certificates() =
      authority_config.intel_root_certificate();

  if (!additional_info.SerializeToString(
          members_view->assertion_request.mutable_additional_information())) {
    return absl::InternalError(
        "Failed to serialize RemoteAssertionRequestAdditionalInfo");
  }

  members_view->initialized = true;

  cleanup_members_view.release();

  return absl::OkStatus();
}

bool SgxAgeRemoteAssertionVerifier::IsInitialized() const {
  return members_.ReaderLock()->initialized;
}

EnclaveIdentityType SgxAgeRemoteAssertionVerifier::IdentityType() const {
  return CODE_IDENTITY;
}

std::string SgxAgeRemoteAssertionVerifier::AuthorityType() const {
  return sgx::kSgxAgeRemoteAssertionAuthority;
}

Status SgxAgeRemoteAssertionVerifier::CreateAssertionRequest(
    AssertionRequest *request) const {
  auto members_view = members_.ReaderLock();

  if (!members_view->initialized) {
    return absl::FailedPreconditionError("Not initialized");
  }

  *request = members_view->assertion_request;
  return absl::OkStatus();
}

StatusOr<bool> SgxAgeRemoteAssertionVerifier::CanVerify(
    const AssertionOffer &offer) const {
  auto members_view = members_.ReaderLock();

  if (!members_view->initialized) {
    return Status(absl::StatusCode::kFailedPrecondition, "Not initialized");
  }

  if (!IsCompatibleAssertionDescription(offer.description())) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "AssertionOffer has incompatible assertion description");
  }
  sgx::RemoteAssertionOfferAdditionalInfo offer_additional_info;
  ASYLO_ASSIGN_OR_RETURN(offer_additional_info, ParseAdditionalInfo(offer));

  if (offer_additional_info.root_ca_certificates_size() <=
      members_view->additional_root_certificates.size()) {
    return false;
  }

  // Ensure all certificates in additional_root_certificates and
  // intel_root_certificate_ are in |offer_additional_info|.
  CertificateInterfaceVector offered_roots;
  offered_roots.reserve(offer_additional_info.root_ca_certificates_size());
  for (const Certificate &info_cert_proto :
       offer_additional_info.root_ca_certificates()) {
    std::unique_ptr<CertificateInterface> info_cert;
    ASYLO_ASSIGN_OR_RETURN(
        info_cert, CreateCertificateInterface(
                       *sgx::GetSgxCertificateFactories(), info_cert_proto));
    offered_roots.push_back(std::move(info_cert));
  }

  for (const std::unique_ptr<CertificateInterface> &required_cert :
       members_view->additional_root_certificates) {
    if (std::none_of(
            offered_roots.begin(), offered_roots.end(),
            [&required_cert](
                const std::unique_ptr<CertificateInterface> &offered_root) {
              return *required_cert == *offered_root;
            })) {
      return false;
    }
  }
  const CertificateInterface *intel_root_cert =
      members_view->intel_root_certificate.get();
  return std::any_of(
      offered_roots.begin(), offered_roots.end(),
      [intel_root_cert](const std::unique_ptr<CertificateInterface> &other) {
        return *intel_root_cert == *other;
      });
}

Status SgxAgeRemoteAssertionVerifier::Verify(
    const std::string &user_data, const Assertion &assertion,
    EnclaveIdentity *peer_identity) const {
  auto members_view = members_.ReaderLock();

  if (!members_view->initialized) {
    return absl::FailedPreconditionError("Not initialized");
  }

  if (!IsCompatibleAssertionDescription(assertion.description())) {
    return absl::InvalidArgumentError(
        "Assertion has incompatible assertion description");
  }

  sgx::RemoteAssertion remote_assertion;
  if (!remote_assertion.ParseFromString(assertion.assertion())) {
    return absl::InvalidArgumentError("Error parsing assertion data");
  }

  SgxIdentity sgx_peer_identity;
  ASYLO_RETURN_IF_ERROR(sgx::VerifyRemoteAssertion(
      user_data, remote_assertion, *(members_view->intel_root_certificate),
      members_view->additional_root_certificates,
      members_view->age_identity_expectation, &sgx_peer_identity));

  ASYLO_ASSIGN_OR_RETURN(*peer_identity,
                         SerializeSgxIdentity(sgx_peer_identity));

  return absl::OkStatus();
}

// Static registration of the SgxAgeRemoteAssertionVerifier library.
SET_STATIC_MAP_VALUE_OF_DERIVED_TYPE(AssertionVerifierMap,
                                     SgxAgeRemoteAssertionVerifier);

}  // namespace asylo
