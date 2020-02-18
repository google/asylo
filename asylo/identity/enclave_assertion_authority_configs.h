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

#ifndef ASYLO_IDENTITY_ENCLAVE_ASSERTION_AUTHORITY_CONFIGS_H_
#define ASYLO_IDENTITY_ENCLAVE_ASSERTION_AUTHORITY_CONFIGS_H_

#include <string>

#include "asylo/crypto/certificate.pb.h"
#include "asylo/identity/enclave_assertion_authority_config.pb.h"
#include "asylo/util/statusor.h"

/// @file enclave_assertion_authority_configs.h
/// @brief Provides functions for creating enclave assertion authority configs.
///
/// The term "enclave assertion authority" refers to the combination of
/// EnclaveAssertionGenerator and EnclaveAssertionVerifier for a particular type
/// of assertion.
///
/// To configure assertion authorities in the untrusted application, use a
/// sequence of calls like the following:
///
/// ```
///   std::vector<EnclaveAssertionAuthorityConfig> authority_configs = {
///       CreateNullAssertionAuthorityConfig(),
///   };
///   CHECK(InitializeEnclaveAssertionAuthorities(
///       authority_configs.cbegin(), authority_configs.cend()).ok());
/// ```
///
/// To configure assertion authorities inside an enclave, pass the set of
/// configurations through the EnclaveConfig:
///
/// ```
///   EnclaveManager *manager = ...
///   EnclaveLoadConfig load_config = ...
///   EnclaveConfig config;
///   *config.add_enclave_assertion_authority_configs() =
///       CreateNullAssertionAuthorityTestConfig();
///   *load_config.mutable_config() = config;
///   CHECK(manager->LoadEnclave(load_config).ok());
/// ```
///
/// Assertion authorities are automatically initialized in TrustedApplication
/// using the provided configurations.

namespace asylo {

/// Creates a configuration for the null assertion authority.
///
/// This configuration is required when using the NullAssertionGenerator or
/// NullAssertionVerifier.
///
/// \return A config for the null assertion authority.
EnclaveAssertionAuthorityConfig CreateNullAssertionAuthorityConfig();

/// Creates a configuration for the SGX local assertion authority.
///
/// This configuration is required when using the SgxLocalAssertionGenerator or
/// SgxLocalAssertionVerifier.
///
/// \param attestation_domain A 16-byte unique identifier for the SGX machine.
/// \return A config for the SGX local assertion authority.
StatusOr<EnclaveAssertionAuthorityConfig>
CreateSgxLocalAssertionAuthorityConfig(std::string attestation_domain);

/// Creates a configuration for the SGX local assertion authority.
///
/// The attestation domain is derived from the per-boot machine UUID in
/// /proc/sys/kernel/random/boot_id.
///
/// This configuration is required when using the SgxLocalAssertionGenerator or
/// SgxLocalAssertionVerifier.
///
/// /return A config for the SGX local assertion authority.
StatusOr<EnclaveAssertionAuthorityConfig>
CreateSgxLocalAssertionAuthorityConfig();

}  // namespace asylo

#endif  // ASYLO_IDENTITY_ENCLAVE_ASSERTION_AUTHORITY_CONFIGS_H_
