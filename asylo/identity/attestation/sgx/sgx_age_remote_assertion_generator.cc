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

#include "asylo/identity/attestation/sgx/sgx_age_remote_assertion_generator.h"

#include <algorithm>

#include <google/protobuf/repeated_field.h>
#include <google/protobuf/util/message_differencer.h>
#include "absl/memory/memory.h"
#include "absl/time/time.h"
#include "asylo/crypto/certificate_util.h"
#include "asylo/grpc/auth/enclave_channel_credentials.h"
#include "asylo/grpc/auth/enclave_credentials_options.h"
#include "asylo/grpc/auth/sgx_local_credentials_options.h"
#include "asylo/identity/attestation/sgx/internal/remote_assertion.pb.h"
#include "asylo/identity/attestation/sgx/internal/sgx_remote_assertion_generator_client.h"
#include "asylo/identity/attestation/sgx/sgx_age_remote_assertion_authority_config.pb.h"
#include "asylo/identity/platform/sgx/internal/code_identity_constants.h"
#include "asylo/util/status_macros.h"

namespace asylo {
namespace {

const int64_t kDeadlineMicros = absl::Seconds(1) / absl::Microseconds(1);

StatusOr<sgx::RemoteAssertionRequestAdditionalInfo> ParseAdditionalInfo(
    const AssertionRequest &request) {
  sgx::RemoteAssertionRequestAdditionalInfo additional_info;
  if (!additional_info.ParseFromString(request.additional_information())) {
    return Status(error::GoogleError::INTERNAL,
                  "Failed to parse request additional information");
  }

  return additional_info;
}

}  // namespace

const char *const SgxAgeRemoteAssertionGenerator::kAuthorityType =
    sgx::kSgxAgeRemoteAssertionAuthority;

SgxAgeRemoteAssertionGenerator::SgxAgeRemoteAssertionGenerator()
    : members_(Members()) {}

Status SgxAgeRemoteAssertionGenerator::Initialize(const std::string &config) {
  auto members_view = members_.Lock();
  if (members_view->initialized) {
    return Status(error::GoogleError::FAILED_PRECONDITION,
                  "Already initialized");
  }

  SgxAgeRemoteAssertionAuthorityConfig authority_config;

  if (!authority_config.ParseFromString(config)) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "Could not parse input config");
  }

  if (!authority_config.has_intel_root_certificate()) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "Config does not contain the Intel root certificate");
  }

  ASYLO_RETURN_IF_ERROR(
      ValidateCertificate(authority_config.intel_root_certificate()));

  for (const auto &certificate : authority_config.root_ca_certificates()) {
    ASYLO_RETURN_IF_ERROR(ValidateCertificate(certificate));
  }

  if (!authority_config.has_server_address()) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "Config is missing server address");
  }

  members_view->root_ca_certificates.reserve(
      authority_config.root_ca_certificates_size() + 1);
  members_view->root_ca_certificates.emplace_back(
      std::move(*authority_config.mutable_intel_root_certificate()));
  std::move(authority_config.root_ca_certificates().begin(),
            authority_config.root_ca_certificates().end(),
            std::back_inserter(members_view->root_ca_certificates));
  members_view->server_address = authority_config.server_address();
  members_view->initialized = true;

  return Status::OkStatus();
}

bool SgxAgeRemoteAssertionGenerator::IsInitialized() const {
  return members_.ReaderLock()->initialized;
}

EnclaveIdentityType SgxAgeRemoteAssertionGenerator::IdentityType() const {
  return kIdentityType;
}

std::string SgxAgeRemoteAssertionGenerator::AuthorityType() const {
  return kAuthorityType;
}

Status SgxAgeRemoteAssertionGenerator::CreateAssertionOffer(
    AssertionOffer *offer) const {
  auto members_view = members_.ReaderLock();

  if (!members_view->initialized) {
    return Status(error::GoogleError::FAILED_PRECONDITION, "Not initialized");
  }

  offer->mutable_description()->set_identity_type(IdentityType());
  offer->mutable_description()->set_authority_type(AuthorityType());

  sgx::RemoteAssertionOfferAdditionalInfo additional_info;
  for (const auto &certificate : members_view->root_ca_certificates) {
    *additional_info.add_root_ca_certificates() = certificate;
  }
  if (!additional_info.SerializeToString(
          offer->mutable_additional_information())) {
    return Status(error::GoogleError::INTERNAL,
                  "Failed to serialize RemoteAssertionOfferAdditionalInfo");
  }

  return Status::OkStatus();
}

StatusOr<bool> SgxAgeRemoteAssertionGenerator::CanGenerate(
    const AssertionRequest &request) const {
  auto members_view = members_.ReaderLock();

  if (!members_view->initialized) {
    return Status(error::GoogleError::FAILED_PRECONDITION, "Not initialized");
  }

  sgx::RemoteAssertionRequestAdditionalInfo additional_info;
  ASYLO_ASSIGN_OR_RETURN(additional_info, ParseAdditionalInfo(request));

  if (additional_info.root_ca_certificates_size() == 0) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "Assertion request must specify at least one CA.");
  }

  // Ensure all certificates in |additional_info| are in root_ca_certificates_.
  //
  // In almost all normal use cases, a generator will only have at most a couple
  // of root CA certificates. Because of this, just do a simple nested for-loop
  // instead of something more clever like a set lookup, which would require
  // hashing the certs and therefore be slower in practice anyways.
  for (const Certificate &info_cert : additional_info.root_ca_certificates()) {
    auto &certificates = members_view->root_ca_certificates;
    if (std::find_if(certificates.begin(), certificates.end(),
                     [info_cert](const Certificate &other) {
                       return google::protobuf::util::MessageDifferencer::Equals(
                           info_cert, other);
                     }) == certificates.end()) {
      return false;
    }
  }
  return true;
}

Status SgxAgeRemoteAssertionGenerator::Generate(const std::string &user_data,
                                                const AssertionRequest &request,
                                                Assertion *assertion) const {
  bool can_generate;
  ASYLO_ASSIGN_OR_RETURN(can_generate, CanGenerate(request));

  if (!can_generate) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "Cannot generate assertion for the given assertion request.");
  }

  auto members_view = members_.ReaderLock();

  sgx::RemoteAssertionRequestAdditionalInfo additional_info;
  ASYLO_ASSIGN_OR_RETURN(additional_info, ParseAdditionalInfo(request));

  auto channel_credentials =
      EnclaveChannelCredentials(BidirectionalSgxLocalCredentialsOptions());
  std::shared_ptr<::grpc::Channel> channel =
      ::grpc::CreateChannel(members_view->server_address, channel_credentials);

  gpr_timespec absolute_deadline =
      gpr_time_add(gpr_now(GPR_CLOCK_REALTIME),
                   gpr_time_from_micros(kDeadlineMicros, GPR_TIMESPAN));

  if (!channel->WaitForConnected(absolute_deadline)) {
    return Status(error::GoogleError::INTERNAL, "Failed to connect to server");
  }

  SgxRemoteAssertionGeneratorClient client(channel);
  sgx::RemoteAssertion remote_assertion;
  ASYLO_ASSIGN_OR_RETURN(remote_assertion,
                         client.GenerateSgxRemoteAssertion(user_data));

  if (!remote_assertion.SerializeToString(assertion->mutable_assertion())) {
    return Status(error::GoogleError::INTERNAL,
                  "Failed to serialize remote assertion");
  }

  assertion->mutable_description()->set_identity_type(IdentityType());
  assertion->mutable_description()->set_authority_type(AuthorityType());

  return Status::OkStatus();
}

// Static registration of the SgxAgeRemoteAssertionGenerator library.
SET_STATIC_MAP_VALUE_OF_DERIVED_TYPE(AssertionGeneratorMap,
                                     SgxAgeRemoteAssertionGenerator);

}  // namespace asylo
