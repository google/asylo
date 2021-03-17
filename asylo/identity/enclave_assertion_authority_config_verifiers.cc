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

#include "absl/status/status.h"
#include "absl/strings/str_format.h"
#include "asylo/crypto/certificate.pb.h"
#include "asylo/crypto/certificate_util.h"
#include "asylo/daemon/identity/attestation_domain.h"
#include "asylo/identity/attestation/sgx/sgx_age_remote_assertion_authority_config.pb.h"
#include "asylo/identity/attestation/sgx/sgx_intel_ecdsa_qe_remote_assertion_authority_config.pb.h"
#include "asylo/identity/attestation/sgx/sgx_local_assertion_authority_config.pb.h"
#include "asylo/identity/enclave_assertion_authority_config.pb.h"
#include "asylo/identity/identity_acl.pb.h"
#include "asylo/identity/platform/sgx/sgx_identity.pb.h"
#include "asylo/identity/platform/sgx/sgx_identity_util.h"
#include "asylo/util/error_codes.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"

namespace asylo {

Status VerifySgxLocalAssertionAuthorityConfig(
    const SgxLocalAssertionAuthorityConfig &config) {
  if (!config.has_attestation_domain()) {
    return absl::InvalidArgumentError("Attestation domain is not set");
  }

  if (config.attestation_domain().size() != kAttestationDomainNameSize) {
    return absl::InvalidArgumentError(absl::StrFormat(
        "Attestation domain must be %d bytes in size "
        "but was %d bytes in size",
        kAttestationDomainNameSize, config.attestation_domain().size()));
  }

  return absl::OkStatus();
}

Status VerifySgxAgeRemoteAssertionAuthorityConfig(
    const SgxAgeRemoteAssertionAuthorityConfig &config) {
  if (!config.has_intel_root_certificate()) {
    return absl::InvalidArgumentError(
        "SGX AGE remote authority config must include an Intel root "
        "certificate");
  }

  if (config.server_address().empty()) {
    return absl::InvalidArgumentError(
        "SGX AGE remote authority config must have a server address");
  }

  return absl::OkStatus();
}

Status VerifySgxIntelEcdsaQeRemoteAssertionAuthorityConfig(
    const SgxIntelEcdsaQeRemoteAssertionAuthorityConfig &config) {
  if (config.ByteSizeLong() == 0) {
    return absl::InvalidArgumentError("Configuration must not be empty");
  }

  for (const auto &cert :
       config.generator_info().pck_certificate_chain().certificates()) {
    ASYLO_RETURN_IF_ERROR(FullyValidateCertificate(cert));
  }

  for (const auto &cert : config.verifier_info().root_certificates()) {
    ASYLO_RETURN_IF_ERROR(FullyValidateCertificate(cert));
  }

  if (config.has_verifier_info()) {
    if (config.verifier_info().root_certificates().empty()) {
      return absl::InvalidArgumentError(
          "Verifier configuration must contain at least one trusted "
          "root certificate");
    }
    if (!config.verifier_info().has_qe_identity_expectation()) {
      return absl::InvalidArgumentError(
          "Verifier configuration is missing QE identity expectation");
    }
    if (config.verifier_info().qe_identity_expectation().item_case() ==
        IdentityAclPredicate::ITEM_NOT_SET) {
      return absl::InvalidArgumentError(
          "QE identity expectation must be set to expectation or ACL group");
    }
    // The |qe_identity_expectation| field is an IdentityAclPredicate and would
    // need to be recursively validated. This check just tests the basic case of
    // a single expectation that is expected to be an SgxIdentityExpectation.
    if (config.verifier_info().qe_identity_expectation().item_case() ==
            IdentityAclPredicate::kExpectation &&
        !ParseSgxIdentityExpectation(
             config.verifier_info().qe_identity_expectation().expectation())
             .ok()) {
      return absl::InvalidArgumentError(
          "QE identity expectation must be a valid SGX identity expectation");
    }
  }

  return absl::OkStatus();
}

}  // namespace asylo
