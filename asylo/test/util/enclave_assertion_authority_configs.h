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

#ifndef ASYLO_TEST_UTIL_ENCLAVE_ASSERTION_AUTHORITY_CONFIGS_H_
#define ASYLO_TEST_UTIL_ENCLAVE_ASSERTION_AUTHORITY_CONFIGS_H_

#include "asylo/identity/enclave_assertion_authority_config.pb.h"

namespace asylo {

// This file provides test configs that can be used to initialize the various
// enclave assertion authorities.
//
// To configure assertion authorities in the untrusted application, use a call
// like the following:
//
//   std::vector<EnclaveAssertionAuthorityConfig> authority_configs = {
//       GetFooAssertionAuthorityTestConfig(),
//   };
//   ASSERT_OK(InitializeEnclaveAssertionAuthorities(
//       authority_configs.cbegin(), authority_configs.cend());
//
// To configure assertion authorities inside an enclave, pass the configuration
// through the EnclaveConfig:
//
//   EnclaveManager *manager = ...
//   EnclaveLoader loader = ...
//   EnclaveConfig config;
//   *config.add_enclave_assertion_authority_configs() =
//       GetFooAssertionAuthorityTestConfig();
//   ASSERT_OK(manager->LoadEnclave("/some/enclave/path", loader, config));

// Gets a suitable test configuration for null assertion authorities.
EnclaveAssertionAuthorityConfig GetNullAssertionAuthorityTestConfig();

// Gets a suitable test configuration for SGX local assertion authorities.
EnclaveAssertionAuthorityConfig GetSgxLocalAssertionAuthorityTestConfig();

}  // namespace asylo

#endif  // ASYLO_TEST_UTIL_ENCLAVE_ASSERTION_AUTHORITY_CONFIGS_H_
