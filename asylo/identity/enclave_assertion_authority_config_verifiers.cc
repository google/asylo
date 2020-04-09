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

#include "asylo/identity/enclave_assertion_authority_config_verifiers.h"

#include <string>

#include "absl/strings/str_format.h"
#include "asylo/crypto/certificate.pb.h"
#include "asylo/crypto/certificate_util.h"
#include "asylo/daemon/identity/attestation_domain.h"
#include "asylo/identity/attestation/sgx/sgx_age_remote_assertion_authority_config.pb.h"
#include "asylo/identity/attestation/sgx/sgx_intel_ecdsa_qe_remote_assertion_authority_config.pb.h"
#include "asylo/identity/enclave_assertion_authority_config.pb.h"
#include "asylo/identity/sgx/sgx_local_assertion_authority_config.pb.h"
#include "asylo/util/error_codes.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"

namespace asylo {

Status VerifySgxLocalAssertionAuthorityConfig(
    const SgxLocalAssertionAuthorityConfig &config) {
  if (!config.has_attestation_domain()) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "Attestation domain is not set");
  }

  if (config.attestation_domain().size() != kAttestationDomainNameSize) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  absl::StrFormat("Attestation domain must be %d bytes in size "
                                  "but was %d bytes in size",
                                  kAttestationDomainNameSize,
                                  config.attestation_domain().size()));
  }

  return Status::OkStatus();
}

Status VerifySgxAgeRemoteAssertionAuthorityConfig(
    const SgxAgeRemoteAssertionAuthorityConfig &config) {
  if (!config.has_intel_root_certificate()) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "SGX AGE remote authority config must include an Intel root "
                  "certificate");
  }

  if (config.server_address().empty()) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "SGX AGE remote authority config must have a server address");
  }

  return Status::OkStatus();
}

Status VerifySgxIntelEcdsaQeRemoteAssertionAuthorityConfig(
    const SgxIntelEcdsaQeRemoteAssertionAuthorityConfig &config) {
  if (config.ByteSizeLong() == 0) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "Configuration must not be empty");
  }

  for (const auto &cert :
       config.generator_info().pck_certificate_chain().certificates()) {
    ASYLO_RETURN_IF_ERROR(FullyValidateCertificate(cert));
  }

  for (const auto &cert : config.verifier_info().root_certificates()) {
    ASYLO_RETURN_IF_ERROR(FullyValidateCertificate(cert));
  }

  if (config.has_verifier_info() &&
      config.verifier_info().root_certificates().empty()) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "Must provide at least one trusted root certificate");
  }

  return Status::OkStatus();
}

}  // namespace asylo
