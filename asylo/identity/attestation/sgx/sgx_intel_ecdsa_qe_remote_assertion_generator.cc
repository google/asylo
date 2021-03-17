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
#include <iterator>
#include <memory>
#include <vector>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_format.h"
#include "absl/synchronization/mutex.h"
#include "absl/types/variant.h"
#include "asylo/crypto/certificate.pb.h"
#include "asylo/crypto/certificate_interface.h"
#include "asylo/crypto/certificate_util.h"
#include "asylo/crypto/sha256_hash.h"
#include "asylo/crypto/x509_certificate.h"
#include "asylo/identity/additional_authenticated_data_generator.h"
#include "asylo/identity/attestation/sgx/internal/dcap_intel_architectural_enclave_interface.h"
#include "asylo/identity/attestation/sgx/internal/enclave_dcap_library_interface.h"
#include "asylo/identity/attestation/sgx/internal/intel_architectural_enclave_interface.h"
#include "asylo/identity/attestation/sgx/internal/intel_ecdsa_quote.h"
#include "asylo/identity/attestation/sgx/sgx_intel_ecdsa_qe_remote_assertion_authority_config.pb.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/identity/platform/sgx/internal/code_identity_constants.h"
#include "asylo/identity/platform/sgx/internal/hardware_interface.h"
#include "asylo/identity/platform/sgx/internal/identity_key_management_structs.h"
#include "asylo/util/error_codes.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"
#include "QuoteVerification/Src/AttestationLibrary/include/QuoteVerification/QuoteConstants.h"

namespace asylo {

using asylo::sgx::AlignedReportdataPtr;
using asylo::sgx::AlignedReportPtr;
using asylo::sgx::AlignedTargetinfoPtr;
using asylo::sgx::DcapIntelArchitecturalEnclaveInterface;
using asylo::sgx::DcapLibraryInterface;
using asylo::sgx::EnclaveDcapLibraryInterface;
using asylo::sgx::IntelArchitecturalEnclaveInterface;
using asylo::sgx::kSgxIntelEcdsaQeRemoteAssertionAuthority;

using GeneratorInfo =
    SgxIntelEcdsaQeRemoteAssertionAuthorityConfig_GeneratorInfo;

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
  auto members_view = members_.Lock();

  if (members_view->is_initialized) {
    return absl::FailedPreconditionError("Already initialized");
  }

  SgxIntelEcdsaQeRemoteAssertionAuthorityConfig parsed_config;
  if (!parsed_config.ParseFromString(config)) {
    return absl::InvalidArgumentError(
        "Unable to parse assertion authority config");
  }

  // If the client did not pass generator initialization info, then do not
  // initialize this object. Assertion generation is not possible without
  // configuration. This is not an error, as the application may want to use
  // assertion verification (e.g. it is not hosting any enclaves).
  if (!parsed_config.has_generator_info()) {
    return absl::OkStatus();
  }

  ASYLO_RETURN_IF_ERROR(ReadCertificationData(parsed_config));

  members_view->is_initialized = true;
  return absl::OkStatus();
}

Status SgxIntelEcdsaQeRemoteAssertionGenerator::ReadCertificationData(
    const SgxIntelEcdsaQeRemoteAssertionAuthorityConfig &config) const {
  switch (config.generator_info().certification_case()) {
    case GeneratorInfo::CERTIFICATION_NOT_SET:
      return absl::InvalidArgumentError(
          "Generator info is missing certification info");

    case GeneratorInfo::kPckCertificateChain:
      return intel_enclaves_->SetPckCertificateChain(
          config.generator_info().pck_certificate_chain());

    case GeneratorInfo::kUseDcapDefault:
      return absl::OkStatus();
  }

  return absl::InvalidArgumentError(absl::StrCat(
      "Assertion authority config does not contain a known certification "
      "data type: ",
      config.generator_info().certification_case()));
}

bool SgxIntelEcdsaQeRemoteAssertionGenerator::IsInitialized() const {
  return members_.ReaderLock()->is_initialized;
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
    return absl::FailedPreconditionError(
        "The Intel ECDSA assertion generator has not been initialized.");
  }

  offer->Clear();
  offer->mutable_description()->set_authority_type(AuthorityType());
  offer->mutable_description()->set_identity_type(IdentityType());

  return absl::OkStatus();
}

StatusOr<bool> SgxIntelEcdsaQeRemoteAssertionGenerator::CanGenerate(
    const AssertionRequest &request) const {
  if (!IsInitialized()) {
    return Status(
        absl::StatusCode::kFailedPrecondition,
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
    return absl::InvalidArgumentError(absl::StrFormat(
        "Cannot generate assertions for '%s'", request.ShortDebugString()));
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

  return absl::OkStatus();
}

SET_STATIC_MAP_VALUE_OF_DERIVED_TYPE(AssertionGeneratorMap,
                                     SgxIntelEcdsaQeRemoteAssertionGenerator);

}  // namespace asylo
