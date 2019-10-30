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

#include "asylo/identity/enclave_assertion_authority_config.pb.h"
#include "asylo/util/statusor.h"

// This file provides factory functions for configs that can be used to
// initialize various enclave assertion authorities. The term "enclave assertion
// authority" refers to the combination of EnclaveAssertionGenerator and
// EnclaveAssertionVerifier for a particular type of assertion.
//
// To configure assertion authorities in the untrusted application, use a call
// like the following:
//
//   std::vector<EnclaveAssertionAuthorityConfig> authority_configs = {
//       CreateNullAssertionAuthorityConfig(),
//   };
//   ASSERT_OK(InitializeEnclaveAssertionAuthorities(
//       authority_configs.cbegin(), authority_configs.cend());
//
// To configure assertion authorities inside an enclave, pass the set of
// configurations through the EnclaveConfig:
//
//   EnclaveManager *manager = ...
//   EnclaveLoadConfig load_config = ...
//   EnclaveConfig config;
//   *config.add_enclave_assertion_authority_configs() =
//       CreateNullAssertionAuthorityTestConfig();
//   *load_config.mutable_config() = config;
//   ASSERT_OK(manager->LoadEnclave(load_config));
//
// Assertion authorities are automatically initialized in the TrustedApplication
// using the provided configurations.

namespace asylo {

// Creates configuration for the null assertion authority. This configuration is
// required when using the NullAssertionGenerator or NullAssertionVerifier.
EnclaveAssertionAuthorityConfig CreateNullAssertionAuthorityConfig();

// Creates configuration for the SGX local assertion authority. The
// |attestation_domain| is a 16-byte unique identifier for the SGX machine. This
// configuration is required when using the SgxLocalAssertionGenerator or
// SgxLocalAssertionVerifier.
StatusOr<EnclaveAssertionAuthorityConfig>
CreateSgxLocalAssertionAuthorityConfig(std::string attestation_domain);

}  // namespace asylo

#endif  // ASYLO_IDENTITY_ENCLAVE_ASSERTION_AUTHORITY_CONFIGS_H_
