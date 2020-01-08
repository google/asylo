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

#include "asylo/identity/enclave_assertion_authority_configs.h"

#include <string>

#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "asylo/daemon/identity/attestation_domain.h"
#include "asylo/identity/attestation/sgx/sgx_age_remote_assertion_authority_config.pb.h"
#include "asylo/identity/descriptions.h"
#include "asylo/identity/enclave_assertion_authority_config.pb.h"
#include "asylo/identity/sgx/sgx_local_assertion_authority_config.pb.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"

namespace asylo {

EnclaveAssertionAuthorityConfig CreateNullAssertionAuthorityConfig() {
  EnclaveAssertionAuthorityConfig authority_config;
  SetNullAssertionDescription(authority_config.mutable_description());
  // No configuration needed for the null assertion authority.
  return authority_config;
}

StatusOr<EnclaveAssertionAuthorityConfig>
CreateSgxLocalAssertionAuthorityConfig(std::string attestation_domain) {
  if (attestation_domain.size() != kAttestationDomainNameSize) {
    return Status(
        error::GoogleError::INVALID_ARGUMENT,
        absl::StrFormat("Attestation domain must be %d bytes in size "
                        "but was %d bytes in size",
                        kAttestationDomainNameSize, attestation_domain.size()));
  }

  EnclaveAssertionAuthorityConfig authority_config;
  SetSgxLocalAssertionDescription(authority_config.mutable_description());

  SgxLocalAssertionAuthorityConfig config;
  *config.mutable_attestation_domain() = std::move(attestation_domain);

  if (!config.SerializeToString(authority_config.mutable_config())) {
    return Status(error::GoogleError::INTERNAL,
                  "Failed to serialize SgxLocalAssertionAuthorityConfig");
  }

  return authority_config;
}

StatusOr<EnclaveAssertionAuthorityConfig>
CreateSgxLocalAssertionAuthorityConfig() {
  std::string attestation_domain;
  ASYLO_ASSIGN_OR_RETURN(attestation_domain, GetAttestationDomain());
  return CreateSgxLocalAssertionAuthorityConfig(std::move(attestation_domain));
}

StatusOr<EnclaveAssertionAuthorityConfig>
CreateSgxAgeRemoteAssertionAuthorityConfig(
    std::vector<Certificate> certificates, std::string server_address) {
  EnclaveAssertionAuthorityConfig authority_config;
  SetSgxAgeRemoteAssertionDescription(authority_config.mutable_description());

  if (certificates.empty()) {
    return Status(
        error::GoogleError::INVALID_ARGUMENT,
        "SGX AGE remote authority config must have at least one certificate");
  }

  SgxAgeRemoteAssertionAuthorityConfig config;
  for (auto &certificate : certificates) {
    *config.add_root_ca_certificates() = std::move(certificate);
  }

  config.set_server_address(std::move(server_address));

  if (!config.SerializeToString(authority_config.mutable_config())) {
    return Status(error::GoogleError::INTERNAL,
                  "Failed to serialize SgxAgeRemoteAssertionAuthorityConfig");
  }

  return authority_config;
}

}  // namespace asylo
