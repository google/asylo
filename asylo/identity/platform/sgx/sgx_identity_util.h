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

#ifndef ASYLO_IDENTITY_PLATFORM_SGX_SGX_IDENTITY_UTIL_H_
#define ASYLO_IDENTITY_PLATFORM_SGX_SGX_IDENTITY_UTIL_H_

#include <string>

#include "asylo/identity/identity.pb.h"
#include "asylo/identity/platform/sgx/sgx_identity.pb.h"
#include "asylo/util/statusor.h"

namespace asylo {

/// This enum defines a set of recommended match specs. Users are advised to
/// pick the one that most closely matches their application's security
/// requirements and make adjustments to these match specs as needed.
///
/// ### `DEFAULT`
/// - Requires a match on MRSIGNER, all MISCSELECT bits, and all ATTRIBUTES
///   bits that are considered security-critical by default.
/// - Does not require a match on any `sgx::MachineConfiguration` fields.
///
/// ### `STRICT_LOCAL`
/// - Requires a match on MRENCLAVE, MRSIGNER, all MISCSELECT bits, and all
///   ATTRIBUTES bits.
/// - Requires a match on CPUSVN.
///   - Note that no other `sgx::MachineConfiguration` fields are required to
///     match, as they are unavailable in local attestation.
/// ### `STRICT_REMOTE`
/// - Equivalent to the `STRICT_LOCAL` match spec, with the added requirement of
///   matching all `sgx::MachineConfiguration` fields (not just CPUSVN).
enum class SgxIdentityMatchSpecOptions { DEFAULT, STRICT_LOCAL, STRICT_REMOTE };

/// Returns the current enclave's identity.
SgxIdentity GetSelfSgxIdentity();

/// Returns an `SgxIdentityMatchSpec` corresponding to `options` on success or a
/// non-OK Status on failure.
StatusOr<SgxIdentityMatchSpec> CreateSgxIdentityMatchSpec(
    SgxIdentityMatchSpecOptions options);

/// Returns an `SgxIdentityExpectation` formed from `identity` and `match_spec`,
/// or returns a non-OK Status if either are invalid or if they are
/// incompatible with each other.
StatusOr<SgxIdentityExpectation> CreateSgxIdentityExpectation(
    SgxIdentity identity, SgxIdentityMatchSpec match_spec);

/// Returns an `SgxIdentityExpectation` formed from `identity` and the match
/// spec corresponding to `options`, or returns a non-OK Status if either are
/// invalid or if they are incompatible with each other.
StatusOr<SgxIdentityExpectation> CreateSgxIdentityExpectation(
    SgxIdentity identity, SgxIdentityMatchSpecOptions options);

/// Returns whether `identity` is valid.
///
/// An `SgxIdentity` is considered valid if its MISCSELECT and ATTRIBUTES
/// properties are set and any additional fields present in the message are
/// valid as well.
bool IsValidSgxIdentity(const SgxIdentity &identity);

/// Returns whether `match_spec` is valid.
///
/// An `SgxIdentityMatchSpec` is valid if all of its constituent fields are set.
bool IsValidSgxIdentityMatchSpec(const SgxIdentityMatchSpec &match_spec);

/// Returns whether `expectation` is valid.
///
/// An `SgxIdentityExpectation` is valid if its identity and match spec
/// components are valid and they are both compatible with each other.
bool IsValidSgxIdentityExpectation(const SgxIdentityExpectation &expectation);

/// Parses and validates `generic_identity`, returning an `SgxIdentity` on
/// success or a non-OK Status on failure.
StatusOr<SgxIdentity> ParseSgxIdentity(const EnclaveIdentity &generic_identity);

/// Parses and validates `generic_match_spec`, returning an
/// `SgxIdentityMatchSpec` on success or a non-OK Status on failure.
StatusOr<SgxIdentityMatchSpec> ParseSgxIdentityMatchSpec(
    const std::string &generic_match_spec);

/// Parses and validates `generic_expectation`, returning an
/// `SgxIdentityExpectation` on success or a non-OK Status on failure.
StatusOr<SgxIdentityExpectation> ParseSgxIdentityExpectation(
    const EnclaveIdentityExpectation &generic_expectation);

/// Serializes `sgx_identity`, returning an `EnclaveIdentity` on success or a
/// non-OK Status on failure.
StatusOr<EnclaveIdentity> SerializeSgxIdentity(const SgxIdentity &sgx_identity);

/// Serializes `sgx_match_spec`, returning a string on success or a non-OK
/// Status on failure.
StatusOr<std::string> SerializeSgxIdentityMatchSpec(
    const SgxIdentityMatchSpec &sgx_match_spec);

/// Serializes `sgx_expectation`, returning an `EnclaveIdentityExpectation` on
/// success or a non-OK Status on failure.
StatusOr<EnclaveIdentityExpectation> SerializeSgxIdentityExpectation(
    const SgxIdentityExpectation &sgx_expectation);

}  // namespace asylo

#endif  // ASYLO_IDENTITY_PLATFORM_SGX_SGX_IDENTITY_UTIL_H_
