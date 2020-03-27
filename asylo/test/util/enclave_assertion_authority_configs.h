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
#include "asylo/identity/platform/sgx/sgx_identity.pb.h"

namespace asylo {

// Creates a suitable test configuration for the null assertion authority. This
// configuration is required when using the NullAssertionGenerator or
// NullAssertionVerifier.
EnclaveAssertionAuthorityConfig GetNullAssertionAuthorityTestConfig();

// Creates a suitable test configuration for the SGX local assertion authority.
// This configuration is required when using the SgxLocalAssertionGenerator,
// SgxLocalAssertionVerifier, or SgxRemoteAssertionGenerator.
EnclaveAssertionAuthorityConfig GetSgxLocalAssertionAuthorityTestConfig();

// Creates a suitable test configuration for the SGX AGE-based remote assertion
// authority where the AGE service is located at |server_address| and the AGE
// has the identity |age_identity|. This configuration is required when using
// the SgxAgeRemoteAssertionGenerator or SgxAgeRemoteAssertionVerifier.
EnclaveAssertionAuthorityConfig GetSgxAgeRemoteAssertionAuthorityTestConfig(
    std::string server_address, SgxIdentity age_identity);

// Creates a suitable test configuration for the SGX AGE-based remote assertion
// authority where the AGE service is located at |server_address|. The AGE
// identity expectation matches on the default test enclave configuration. This
// configuration is required when using the SgxAgeRemoteAssertionGenerator or
// SgxAgeRemoteAssertionVerifier.
EnclaveAssertionAuthorityConfig GetSgxAgeRemoteAssertionAuthorityTestConfig(
    std::string server_address);

}  // namespace asylo

#endif  // ASYLO_TEST_UTIL_ENCLAVE_ASSERTION_AUTHORITY_CONFIGS_H_
