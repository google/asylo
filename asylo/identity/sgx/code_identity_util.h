/*
 *
 * Copyright 2017 Asylo authors
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

#ifndef ASYLO_IDENTITY_SGX_CODE_IDENTITY_UTIL_H_
#define ASYLO_IDENTITY_SGX_CODE_IDENTITY_UTIL_H_

#include "asylo/identity/identity.pb.h"
#include "asylo/identity/sgx/code_identity.pb.h"
#include "asylo/identity/sgx/code_identity_constants.h"
#include "asylo/identity/sgx/identity_key_management_structs.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace sgx {

// Sets |assertion_description| to describe an SGX local assertion.
inline void SetSgxLocalAssertionDescription(
    AssertionDescription *assertion_description) {
  assertion_description->set_identity_type(EnclaveIdentityType::CODE_IDENTITY);
  assertion_description->set_authority_type(sgx::kSgxLocalAssertionAuthority);
}

// Sets |assertion_description| to describe an SGX remote assertion.
inline void SetSgxRemoteAssertionDescription(
    AssertionDescription *assertion_description) {
  assertion_description->set_identity_type(EnclaveIdentityType::CODE_IDENTITY);
  assertion_description->set_authority_type(sgx::kSgxRemoteAssertionAuthority);
}

// Sets |identity_description| to describe an SGX code identity.
inline void SetSgxIdentityDescription(
    EnclaveIdentityDescription *identity_description) {
  identity_description->set_identity_type(EnclaveIdentityType::CODE_IDENTITY);
  identity_description->set_authority_type(sgx::kSgxAuthorizationAuthority);
}

// Matches |identity| to given |expectation|. Returns true if there is no error
// encountered, and if the match is successful. Else returns false.
StatusOr<bool> MatchIdentityToExpectation(
    const CodeIdentity &identity, const CodeIdentityExpectation &expectation);

// Sets |expectation| based on |identity| and |match_spec|. Returns true on
// success (no error), else returns false.
Status SetExpectation(const CodeIdentityMatchSpec &match_spec,
                      const CodeIdentity &identity,
                      CodeIdentityExpectation *expectation);

// Checks if a signer-assigned identity is valid.
bool IsValidSignerAssignedIdentity(const SignerAssignedIdentity &identity);

// Checks if an enclave identity is valid.
bool IsValidCodeIdentity(const CodeIdentity &identity);

// Checks if a match specification is valid.
bool IsValidMatchSpec(const CodeIdentityMatchSpec &match_spec);

// Checks if an identity expectation is valid.
bool IsValidExpectation(const CodeIdentityExpectation &expectation);

// Parses CodeIdentity from |report| and places the result in |identity|. Does
// not verify |report|.
Status ParseIdentityFromHardwareReport(const Report &report,
                                       CodeIdentity *identity);

// Sets |spec| to the default SGX match spec, which requires a match on
// MRSIGNER, MISCSELECT, and all ATTRIBUTES that do not fall into the default
// "do not care" set.
Status SetDefaultMatchSpec(CodeIdentityMatchSpec *spec);

// Sets |spec| to the strictest SGX match spec, which requires a match on
// MRENCLAVE, MRSIGNER, MISCSELECT, and all ATTRIBUTES bits.
void SetStrictMatchSpec(CodeIdentityMatchSpec *spec);

// Sets |identity| to the current enclave's identity.
void SetSelfCodeIdentity(CodeIdentity *identity);

// Sets |expectation| to default expectation, which is defined as the pair
// <self identity, default match spec>.
Status SetDefaultSelfCodeIdentityExpectation(
    CodeIdentityExpectation *expectation);

// Sets |expectation| to the strictest self identity expectation, which is
// defined as the pair <self identity, strict match spec>.
Status SetStrictSelfCodeIdentityExpectation(
    CodeIdentityExpectation *expectation);

// Parses SGX code identity from a EnclaveIdentity proto.
Status ParseSgxIdentity(const EnclaveIdentity &generic_identity,
                        CodeIdentity *sgx_identity);

// Parses SGX match spec |sgx_match_spec| from a string (which is how it is
// stored in the EnclaveIdentityExpectation proto).
Status ParseSgxMatchSpec(const std::string &generic_match_spec,
                         CodeIdentityMatchSpec *sgx_match_spec);

// Parses SGX code identity expectation |sgx_expectation| from
// |generic_expectation|.
Status ParseSgxExpectation(
    const EnclaveIdentityExpectation &generic_expectation,
    CodeIdentityExpectation *sgx_expectation);

// Serializes SGX code identity |sgx_identity| into the identity field of
// |generic_identity|. Sets the description field of |generic_identity| to
// indicate the identity type CODE_IDENTITY and the authority type "SGX".
Status SerializeSgxIdentity(const CodeIdentity &sgx_identity,
                            EnclaveIdentity *generic_identity);

// Serializes SGX match spec to a string that is suitable for use in a
// EnclaveIdentityExpectation proto.
Status SerializeSgxMatchSpec(const CodeIdentityMatchSpec &sgx_match_spec,
                             std::string *generic_match_spec);

// Serializes reference_identity and match_spec portions of |sgx_expectation|
// into the appropriate fields of |generic_expectation|. Sets the description
// field of |generic_expectation| to indicate the identity type CODE_IDENTITY
// and the authority type "SGX".
Status SerializeSgxExpectation(const CodeIdentityExpectation &sgx_expectation,
                               EnclaveIdentityExpectation *generic_expectation);

// Sets |tinfo| to match this enclave's identity. Any reports generated using
// this TARGETINFO are targeted at this enclave.
void SetTargetinfoFromSelfIdentity(Targetinfo *tinfo);

// Verifies the hardware report |report|.
Status VerifyHardwareReport(const Report &report);

namespace internal {

// Verifies whether |identity| is compatible with |spec|. This function is
// exposed through this header for testing purposes only.
bool IsIdentityCompatibleWithMatchSpec(const CodeIdentity &identity,
                                       const CodeIdentityMatchSpec &spec);

}  // namespace internal
}  // namespace sgx
}  // namespace asylo

#endif  // ASYLO_IDENTITY_SGX_CODE_IDENTITY_UTIL_H_
