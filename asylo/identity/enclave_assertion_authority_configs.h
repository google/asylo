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
#include <vector>

#include "asylo/crypto/certificate.pb.h"
#include "asylo/identity/attestation/sgx/sgx_intel_ecdsa_qe_remote_assertion_authority_config.pb.h"
#include "asylo/identity/enclave_assertion_authority_config.pb.h"
#include "asylo/identity/identity_acl.pb.h"
#include "asylo/identity/platform/sgx/sgx_identity.pb.h"
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

/// Creates a configuration for the SGX AGE remote assertion authority.
///
/// This configuration is required when using the
/// SgxAgeRemoteAssertionGenerator or SgxAgeRemoteAssertionVerifier.
///
/// \param intel_cert The Intel root certificate to use for verification.
/// \param certificates A vector of X.509-formatted CA certificates that can
///                     be used to verify whether an assertion is valid.
/// \param server_address The address of the AGE's service.
/// \param age_identity_expectation The identity expectation for the AGE.
/// \return A config for the SGX AGE remote assertion authority.
StatusOr<EnclaveAssertionAuthorityConfig>
CreateSgxAgeRemoteAssertionAuthorityConfig(
    Certificate intel_root_cert, std::vector<Certificate> certificates,
    std::string server_address, IdentityAclPredicate age_identity_expectation);

/// Creates a configuration for the SGX AGE remote assertion authority.
///
/// This configuration is required when using the
/// SgxAgeRemoteAssertionGenerator or SgxAgeRemoteAssertionVerifier. It uses the
/// Intel root certificate value |kIntelSgxRootCaCertificate| and no additional
/// root certificates. It sets the AGE identity expectation to the default
/// expectation of the given SgxIdentity, as documented by
/// `SgxIdentityMatchSpecOptions`.
///
/// \param server_address The address of the AGE's service.
/// \param age_identity The expected identity of the AGE.
/// \return A config for the SGX AGE remote assertion authority.
StatusOr<EnclaveAssertionAuthorityConfig>
CreateSgxAgeRemoteAssertionAuthorityConfig(std::string server_address,
                                           SgxIdentity age_identity);

namespace experimental {

/// Creates configuration for the SGX Intel ECDSA QE remote assertion authority.
/// The returned configuration contains the Intel SGX Root CA Certificate for
/// verifying assertion root of trust. Any generated assertions will include the
/// certification data that the Intel DCAP library locates using the Platform
/// Quote Provider Library, as documented in
/// https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf
///
/// This type of EnclaveAssertionAuthorityConfig is required when using the
/// SgxIntelEcdsaQeRemoteAssertionVerifier and/or
/// SgxIntelEcdsaQeRemoteAssertionGenerator.
///
/// \return A config for the SGX Intel ECDSA QE remote assertion authority.
StatusOr<EnclaveAssertionAuthorityConfig>
CreateSgxIntelEcdsaQeRemoteAssertionAuthorityConfig();

/// Creates configuration for the SGX Intel ECDSA QE remote assertion authority.
/// The returned configuration contains the Intel SGX Root CA Certificate for
/// verifying assertion root of trust. Any generated assertions will include the
/// given `pck_certificate_chain` as certification data.
///
/// This type of EnclaveAssertionAuthorityConfig is required when using the
/// SgxIntelEcdsaQeRemoteAssertionVerifier and/or
/// SgxIntelEcdsaQeRemoteAssertionGenerator.
///
/// \param pck_certificate_chain The certification chain to include with any
///                              generated assertions.
/// \param qe_identity The Intel ECDSA QE's identity.
/// \return A config for the SGX Intel ECDSA QE remote assertion authority.
StatusOr<EnclaveAssertionAuthorityConfig>
CreateSgxIntelEcdsaQeRemoteAssertionAuthorityConfig(
    CertificateChain pck_certificate_chain, SgxIdentity qe_identity);

}  // namespace experimental

}  // namespace asylo

#endif  // ASYLO_IDENTITY_ENCLAVE_ASSERTION_AUTHORITY_CONFIGS_H_
