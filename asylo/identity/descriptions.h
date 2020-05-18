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

#ifndef ASYLO_IDENTITY_DESCRIPTIONS_H_
#define ASYLO_IDENTITY_DESCRIPTIONS_H_

#include "asylo/identity/attestation/null/internal/null_identity_constants.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/identity/platform/sgx/internal/code_identity_constants.h"

namespace asylo {

/// Sets `assertion_description` to describe a null assertion.
///
/// \param assertion_description The `AssertionDescription` to populate.
inline void SetNullAssertionDescription(
    AssertionDescription *assertion_description) {
  assertion_description->set_identity_type(EnclaveIdentityType::NULL_IDENTITY);
  assertion_description->set_authority_type(kNullAssertionAuthority);
}

/// Sets `identity_description` to describe a null identity.
///
/// \param identity_description The `EnclaveIdentityDescription` to populate.
inline void SetNullIdentityDescription(
    EnclaveIdentityDescription *identity_description) {
  identity_description->set_identity_type(EnclaveIdentityType::NULL_IDENTITY);
  identity_description->set_authority_type(kNullAuthorizationAuthority);
}

/// Sets `assertion_description` to describe an SGX local assertion.
///
/// \param assertion_description The `AssertionDescription` to populate.
inline void SetSgxLocalAssertionDescription(
    AssertionDescription *assertion_description) {
  assertion_description->set_identity_type(EnclaveIdentityType::CODE_IDENTITY);
  assertion_description->set_authority_type(sgx::kSgxLocalAssertionAuthority);
}

/// Sets `assertion_description` to describe an SGX remote assertion generated
/// by the Assertion Generator Enclave (AGE).
///
/// \param assertion_description The `AssertionDescription` to populate.
inline void SetSgxAgeRemoteAssertionDescription(
    AssertionDescription *assertion_description) {
  assertion_description->set_identity_type(EnclaveIdentityType::CODE_IDENTITY);
  assertion_description->set_authority_type(
      sgx::kSgxAgeRemoteAssertionAuthority);
}

/// Sets `assertion_description` to describe an SGX remote assertion generated
/// by the Intel ECDSA Quoting Enclave (QE).
///
/// \param assertion_description The `AssertionDescription` to populate.
inline void SetSgxIntelEcdsaQeRemoteAssertionDescription(
    AssertionDescription *assertion_description) {
  assertion_description->set_identity_type(EnclaveIdentityType::CODE_IDENTITY);
  assertion_description->set_authority_type(
      sgx::kSgxIntelEcdsaQeRemoteAssertionAuthority);
}

/// Sets `identity_description` to describe an SGX identity.
///
/// \param identity_description The `EnclaveIdentityDescription` to populate.
inline void SetSgxIdentityDescription(
    EnclaveIdentityDescription *identity_description) {
  identity_description->set_identity_type(EnclaveIdentityType::CODE_IDENTITY);
  identity_description->set_authority_type(sgx::kSgxAuthorizationAuthority);
}

}  // namespace asylo

#endif  // ASYLO_IDENTITY_DESCRIPTIONS_H_
