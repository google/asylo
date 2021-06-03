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

#include "asylo/identity/attestation/sgx/sgx_local_assertion_generator.h"

#include <string>

#include "absl/status/status.h"
#include "asylo/crypto/util/bytes.h"
#include "asylo/crypto/util/trivial_object_util.h"
#include "asylo/identity/additional_authenticated_data_generator.h"
#include "asylo/identity/attestation/sgx/internal/local_assertion.pb.h"
#include "asylo/identity/attestation/sgx/sgx_local_assertion_authority_config.pb.h"
#include "asylo/identity/platform/sgx/internal/code_identity_constants.h"
#include "asylo/identity/platform/sgx/internal/hardware_interface.h"
#include "asylo/identity/platform/sgx/internal/identity_key_management_structs.h"
#include "asylo/util/status_macros.h"

namespace asylo {

const char *const SgxLocalAssertionGenerator::kAuthorityType =
    sgx::kSgxLocalAssertionAuthority;

SgxLocalAssertionGenerator::SgxLocalAssertionGenerator()
    : members_(Members()) {}

Status SgxLocalAssertionGenerator::Initialize(const std::string &config) {
  auto members_view = members_.Lock();
  if (members_view->initialized) {
    return absl::FailedPreconditionError("Already initialized");
  }

  SgxLocalAssertionAuthorityConfig authority_config;
  if (!authority_config.ParseFromString(config)) {
    return absl::InvalidArgumentError("Could not parse input config");
  }

  if (!authority_config.has_attestation_domain()) {
    return absl::InvalidArgumentError("Config is missing attestation domain");
  }

  members_view->attestation_domain = authority_config.attestation_domain();

  members_view->aad_generator =
      AdditionalAuthenticatedDataGenerator::CreateEkepAadGenerator();

  members_view->initialized = true;

  return absl::OkStatus();
}

bool SgxLocalAssertionGenerator::IsInitialized() const {
  return members_.ReaderLock()->initialized;
}

EnclaveIdentityType SgxLocalAssertionGenerator::IdentityType() const {
  return kIdentityType;
}

std::string SgxLocalAssertionGenerator::AuthorityType() const {
  return kAuthorityType;
}

Status SgxLocalAssertionGenerator::CreateAssertionOffer(
    AssertionOffer *offer) const {
  if (!IsInitialized()) {
    return absl::FailedPreconditionError("Not initialized");
  }

  offer->mutable_description()->set_identity_type(IdentityType());
  offer->mutable_description()->set_authority_type(AuthorityType());

  sgx::LocalAssertionOfferAdditionalInfo additional_info;
  additional_info.set_local_attestation_domain(
      members_.ReaderLock()->attestation_domain);
  if (!additional_info.SerializeToString(
          offer->mutable_additional_information())) {
    return absl::InternalError(
        "Failed to serialize LocalAssertionOfferAdditionalInfo");
  }

  return absl::OkStatus();
}

StatusOr<bool> SgxLocalAssertionGenerator::CanGenerate(
    const AssertionRequest &request) const {
  if (!IsInitialized()) {
    return Status(absl::StatusCode::kFailedPrecondition, "Not initialized");
  }

  StatusOr<sgx::LocalAssertionRequestAdditionalInfo> additional_info_result =
      ParseAdditionalInfo(request);

  if (!additional_info_result.ok()) {
    return additional_info_result.status();
  }

  sgx::LocalAssertionRequestAdditionalInfo additional_info =
      additional_info_result.value();

  return additional_info.local_attestation_domain() ==
         members_.ReaderLock()->attestation_domain;
}

Status SgxLocalAssertionGenerator::Generate(const std::string &user_data,
                                            const AssertionRequest &request,
                                            Assertion *assertion) const {
  if (!IsInitialized()) {
    return absl::FailedPreconditionError("Not initialized");
  }

  StatusOr<sgx::LocalAssertionRequestAdditionalInfo> additional_info_result =
      ParseAdditionalInfo(request);
  if (!additional_info_result.ok()) {
    return additional_info_result.status();
  }

  sgx::LocalAssertionRequestAdditionalInfo additional_info =
      additional_info_result.value();

  if (additional_info.local_attestation_domain() !=
      members_.ReaderLock()->attestation_domain) {
    return absl::InvalidArgumentError(
        "AssertionRequest specifies non-local attestation domain");
  }

  // The layout and endianness of the TARGETINFO structure is defined by the
  // Intel SGX architecture. Consequently, two SGX-enabled machines can use a
  // common wire-format for this structure by simply dumping the raw bytes of
  // this structure into a proto. Here, we assume that the TARGETINFO string in
  // the request originates from a machine that supports the Intel SGX
  // architecture, and was copied into the request byte-for-byte. Since the
  // LocalAssertionGenerator runs inside an SGX enclave, it is safe to restore
  // the TARGETINFO structure directly from the request.
  sgx::AlignedTargetinfoPtr tinfo;
  ASYLO_RETURN_IF_ERROR(SetTrivialObjectFromBinaryString<sgx::Targetinfo>(
      additional_info.targetinfo(), tinfo.get()));

  // The REPORTDATA is a user-provided input to the hardware report that is
  // included in the report's MAC. Use a SHA256 hash of |user_data| as the
  // REPORTDATA value so that the resulting assertion is cryptographically-bound
  // to this user-provided data. Note that the SHA256 hash only occupies the
  // lower 32 bytes of the 64-byte REPORTDATA structure. The upper part is set
  // to a concatenation of the purpose and uuid of the EKEP AAD specified at
  // asylo/identity/additional_authenticated_data_generator.cc.
  sgx::AlignedReportdataPtr reportdata;
  UnsafeBytes<kAdditionalAuthenticatedDataSize> aad;
  ASYLO_ASSIGN_OR_RETURN(
      aad, members_.ReaderLock()->aad_generator->Generate(user_data));
  reportdata->data = aad;

  // Generate a REPORT that is bound to the provided |user_data| and is targeted
  // at the enclave described in the request.
  sgx::Report report;
  ASYLO_ASSIGN_OR_RETURN(
      report,
      sgx::HardwareInterface::CreateDefault()->GetReport(*tinfo, *reportdata));

  // As explained above, the REPORT structure can be copied byte-for-byte into
  // the report field of the assertion because the layout and endianness of the
  // structure is defined by the Intel SGX architecture. As a result, dumping
  // the raw bytes of the report is sufficient when the structure is sent
  // between two SGX-enabled machines. An SGX-enabled assertion verifier should
  // be able to restore these bytes into a valid REPORT structure.
  sgx::LocalAssertion local_assertion;
  local_assertion.set_report(ConvertTrivialObjectToBinaryString(report));

  if (!local_assertion.SerializeToString(assertion->mutable_assertion())) {
    return absl::InternalError("Failed to serialize local assertion");
  }
  assertion->mutable_description()->set_identity_type(IdentityType());
  assertion->mutable_description()->set_authority_type(AuthorityType());

  return absl::OkStatus();
}

StatusOr<sgx::LocalAssertionRequestAdditionalInfo>
SgxLocalAssertionGenerator::ParseAdditionalInfo(
    const AssertionRequest &request) const {
  if (!IsCompatibleAssertionDescription(request.description())) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "Incompatible assertion description");
  }

  sgx::LocalAssertionRequestAdditionalInfo additional_info;
  if (!additional_info.ParseFromString(request.additional_information())) {
    return Status(absl::StatusCode::kInternal,
                  "Failed to parse request additional information");
  }

  return additional_info;
}

// Static registration of the LocalAssertionGenerator library.
SET_STATIC_MAP_VALUE_OF_DERIVED_TYPE(AssertionGeneratorMap,
                                     SgxLocalAssertionGenerator);

}  // namespace asylo
