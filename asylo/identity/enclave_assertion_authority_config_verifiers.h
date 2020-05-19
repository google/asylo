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

#ifndef ASYLO_IDENTITY_ENCLAVE_ASSERTION_AUTHORITY_CONFIG_VERIFIERS_H_
#define ASYLO_IDENTITY_ENCLAVE_ASSERTION_AUTHORITY_CONFIG_VERIFIERS_H_

#include "asylo/identity/attestation/sgx/sgx_age_remote_assertion_authority_config.pb.h"
#include "asylo/identity/attestation/sgx/sgx_intel_ecdsa_qe_remote_assertion_authority_config.pb.h"
#include "asylo/identity/attestation/sgx/sgx_local_assertion_authority_config.pb.h"
#include "asylo/util/status.h"

namespace asylo {

// Verifies a configuration for the SGX local assertion authority.
Status VerifySgxLocalAssertionAuthorityConfig(
    const SgxLocalAssertionAuthorityConfig &config);

// Verifies a configuration for the SGX AGE remote assertion authority.
Status VerifySgxAgeRemoteAssertionAuthorityConfig(
    const SgxAgeRemoteAssertionAuthorityConfig &config);

// Verifies a default, production configuration for the SGX Intel ECDSA QE.
Status VerifySgxIntelEcdsaQeRemoteAssertionAuthorityConfig(
    const SgxIntelEcdsaQeRemoteAssertionAuthorityConfig &config);

}  // namespace asylo

#endif  // ASYLO_IDENTITY_ENCLAVE_ASSERTION_AUTHORITY_CONFIG_VERIFIERS_H_
