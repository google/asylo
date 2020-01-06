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

#include "asylo/identity/attestation/sgx/sgx_intel_ecdsa_qe_remote_assertion_generator.h"

#include <cstdint>
#include <memory>
#include <vector>

#include "absl/memory/memory.h"
#include "absl/strings/str_format.h"
#include "absl/synchronization/mutex.h"
#include "asylo/crypto/sha256_hash.h"
#include "asylo/identity/additional_authenticated_data_generator.h"
#include "asylo/identity/attestation/sgx/internal/dcap_intel_architectural_enclave_interface.h"
#include "asylo/identity/attestation/sgx/internal/enclave_dcap_library_interface.h"
#include "asylo/identity/attestation/sgx/internal/intel_architectural_enclave_interface.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/identity/sgx/code_identity_constants.h"
#include "asylo/identity/sgx/hardware_interface.h"
#include "asylo/identity/sgx/identity_key_management_structs.h"
#include "asylo/util/error_codes.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"

namespace asylo {

using asylo::sgx::AlignedReportdataPtr;
using asylo::sgx::AlignedReportPtr;
using asylo::sgx::AlignedTargetinfoPtr;
using asylo::sgx::DcapIntelArchitecturalEnclaveInterface;
using asylo::sgx::DcapLibraryInterface;
using asylo::sgx::EnclaveDcapLibraryInterface;
using asylo::sgx::IntelArchitecturalEnclaveInterface;
using asylo::sgx::kSgxIntelEcdsaQeRemoteAssertionAuthority;

const char *const SgxIntelEcdsaQeRemoteAssertionGenerator::kDefaultConfig = "";

SgxIntelEcdsaQeRemoteAssertionGenerator::
    SgxIntelEcdsaQeRemoteAssertionGenerator()
    : SgxIntelEcdsaQeRemoteAssertionGenerator(
          AdditionalAuthenticatedDataGenerator::CreateEkepAadGenerator(),
          absl::make_unique<DcapIntelArchitecturalEnclaveInterface>(
              absl::make_unique<EnclaveDcapLibraryInterface>()),
          sgx::HardwareInterface::CreateDefault()) {}

SgxIntelEcdsaQeRemoteAssertionGenerator::
    SgxIntelEcdsaQeRemoteAssertionGenerator(
        std::unique_ptr<AdditionalAuthenticatedDataGenerator> aad_generator,
        std::unique_ptr<IntelArchitecturalEnclaveInterface> intel_enclaves,
        std::unique_ptr<sgx::HardwareInterface> hardware_interface)
    : aad_generator_(std::move(aad_generator)),
      intel_enclaves_(std::move(intel_enclaves)),
      hardware_interface_(std::move(hardware_interface)) {}

Status SgxIntelEcdsaQeRemoteAssertionGenerator::Initialize(
    const std::string &config) {
  if (config != kDefaultConfig) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  absl::StrFormat("Invalid config: '%s'", config));
  }

  auto is_initialized_view = is_initialized_.Lock();

  if (*is_initialized_view) {
    return Status(error::GoogleError::FAILED_PRECONDITION,
                  "Already initialized");
  }

  *is_initialized_view = true;
  return Status::OkStatus();
}

bool SgxIntelEcdsaQeRemoteAssertionGenerator::IsInitialized() const {
  return *is_initialized_.ReaderLock();
}

EnclaveIdentityType SgxIntelEcdsaQeRemoteAssertionGenerator::IdentityType()
    const {
  return CODE_IDENTITY;
}

std::string SgxIntelEcdsaQeRemoteAssertionGenerator::AuthorityType() const {
  return kSgxIntelEcdsaQeRemoteAssertionAuthority;
}

Status SgxIntelEcdsaQeRemoteAssertionGenerator::CreateAssertionOffer(
    AssertionOffer *offer) const {
  if (!IsInitialized()) {
    return Status(
        error::GoogleError::FAILED_PRECONDITION,
        "The Intel ECDSA assertion generator has not been initialized.");
  }

  offer->Clear();
  offer->mutable_description()->set_authority_type(AuthorityType());
  offer->mutable_description()->set_identity_type(IdentityType());

  return Status::OkStatus();
}

StatusOr<bool> SgxIntelEcdsaQeRemoteAssertionGenerator::CanGenerate(
    const AssertionRequest &request) const {
  if (!IsInitialized()) {
    return Status(
        error::GoogleError::FAILED_PRECONDITION,
        "The Intel ECDSA assertion generator has not been initialized.");
  }

  return request.description().authority_type() == AuthorityType() &&
         request.description().identity_type() == IdentityType();
}

Status SgxIntelEcdsaQeRemoteAssertionGenerator::Generate(
    const std::string &user_data, const AssertionRequest &request,
    Assertion *assertion) const {
  bool can_generate;
  ASYLO_ASSIGN_OR_RETURN(can_generate, CanGenerate(request));
  if (!can_generate) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  absl::StrFormat("Cannot generate assertions for '%s'",
                                  request.ShortDebugString()));
  }

  AlignedReportdataPtr reportdata;
  ASYLO_ASSIGN_OR_RETURN(reportdata->data, aad_generator_->Generate(user_data));

  AlignedTargetinfoPtr targetinfo;
  ASYLO_ASSIGN_OR_RETURN(*targetinfo, intel_enclaves_->GetQeTargetinfo());

  sgx::Report report;
  ASYLO_ASSIGN_OR_RETURN(
      report, hardware_interface_->GetReport(*targetinfo, *reportdata));

  std::vector<uint8_t> quote;
  ASYLO_ASSIGN_OR_RETURN(quote, intel_enclaves_->GetQeQuote(report));

  assertion->mutable_assertion()->assign(quote.begin(), quote.end());
  assertion->mutable_description()->set_authority_type(AuthorityType());
  assertion->mutable_description()->set_identity_type(IdentityType());

  return Status::OkStatus();
}

SET_STATIC_MAP_VALUE_OF_DERIVED_TYPE(AssertionGeneratorMap,
                                     SgxIntelEcdsaQeRemoteAssertionGenerator);

}  // namespace asylo
