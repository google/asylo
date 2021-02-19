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
#include <vector>

#include <google/protobuf/message.h>
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "asylo/daemon/identity/attestation_domain.h"
#include "asylo/identity/attestation/sgx/internal/intel_certs/intel_sgx_root_ca_cert.h"
#include "asylo/identity/attestation/sgx/internal/intel_certs/qe_identity.h"
#include "asylo/identity/attestation/sgx/sgx_age_remote_assertion_authority_config.pb.h"
#include "asylo/identity/attestation/sgx/sgx_intel_ecdsa_qe_remote_assertion_authority_config.pb.h"
#include "asylo/identity/attestation/sgx/sgx_local_assertion_authority_config.pb.h"
#include "asylo/identity/descriptions.h"
#include "asylo/identity/enclave_assertion_authority_config.pb.h"
#include "asylo/identity/enclave_assertion_authority_config_verifiers.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/identity/identity_acl.pb.h"
#include "asylo/identity/platform/sgx/sgx_identity.pb.h"
#include "asylo/identity/platform/sgx/sgx_identity_util.h"
#include "asylo/util/proto_enum_util.h"
#include "asylo/util/proto_parse_util.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace {

StatusOr<EnclaveAssertionAuthorityConfig> SerializeToAuthorityConfig(
    const google::protobuf::Message &inner_config,
    std::function<void(AssertionDescription *)> set_description) {
  EnclaveAssertionAuthorityConfig authority_config;
  if (!inner_config.SerializeToString(authority_config.mutable_config())) {
    return absl::InternalError(
        absl::StrCat("Failed to serialize ", inner_config.GetTypeName()));
  }

  set_description(authority_config.mutable_description());
  return authority_config;
}

// Creates an IdentityAclPredicate containing an EnclaveIdentityExpectation that
// uses |sgx_identity| and the DEFAULT match spec.
StatusOr<IdentityAclPredicate> CreateDefaultExpectation(
    SgxIdentity sgx_identity) {
  IdentityAclPredicate acl;

  SgxIdentityExpectation sgx_identity_expectation;
  ASYLO_ASSIGN_OR_RETURN(
      sgx_identity_expectation,
      CreateSgxIdentityExpectation(std::move(sgx_identity),
                                   SgxIdentityMatchSpecOptions::DEFAULT));
  ASYLO_ASSIGN_OR_RETURN(
      *acl.mutable_expectation(),
      SerializeSgxIdentityExpectation(sgx_identity_expectation));
  return acl;
}

}  // namespace

EnclaveAssertionAuthorityConfig CreateNullAssertionAuthorityConfig() {
  EnclaveAssertionAuthorityConfig authority_config;
  SetNullAssertionDescription(authority_config.mutable_description());
  // No configuration needed for the null assertion authority.
  return authority_config;
}

StatusOr<EnclaveAssertionAuthorityConfig>
CreateSgxLocalAssertionAuthorityConfig(std::string attestation_domain) {
  SgxLocalAssertionAuthorityConfig config;
  *config.mutable_attestation_domain() = std::move(attestation_domain);
  ASYLO_RETURN_IF_ERROR(VerifySgxLocalAssertionAuthorityConfig(config));

  return SerializeToAuthorityConfig(config, SetSgxLocalAssertionDescription);
}

StatusOr<EnclaveAssertionAuthorityConfig>
CreateSgxLocalAssertionAuthorityConfig() {
  std::string attestation_domain;
  ASYLO_ASSIGN_OR_RETURN(attestation_domain, GetAttestationDomain());
  return CreateSgxLocalAssertionAuthorityConfig(std::move(attestation_domain));
}

StatusOr<EnclaveAssertionAuthorityConfig>
CreateSgxAgeRemoteAssertionAuthorityConfig(
    Certificate intel_root_cert,
    std::vector<Certificate> additional_certificates,
    std::string server_address, IdentityAclPredicate age_identity_expectation) {
  SgxAgeRemoteAssertionAuthorityConfig config;
  *config.mutable_intel_root_certificate() = std::move(intel_root_cert);
  config.set_server_address(std::move(server_address));
  for (auto &certificate : additional_certificates) {
    *config.add_root_ca_certificates() = std::move(certificate);
  }
  *config.mutable_age_identity_expectation() =
      std::move(age_identity_expectation);
  ASYLO_RETURN_IF_ERROR(VerifySgxAgeRemoteAssertionAuthorityConfig(config));

  return SerializeToAuthorityConfig(config,
                                    SetSgxAgeRemoteAssertionDescription);
}

StatusOr<EnclaveAssertionAuthorityConfig>
CreateSgxAgeRemoteAssertionAuthorityConfig(std::string server_address,
                                           SgxIdentity age_identity) {
  IdentityAclPredicate age_identity_expectation;
  ASYLO_ASSIGN_OR_RETURN(age_identity_expectation,
                         CreateDefaultExpectation(age_identity));
  return CreateSgxAgeRemoteAssertionAuthorityConfig(
      MakeIntelSgxRootCaCertificateProto(), {}, std::move(server_address),
      std::move(age_identity_expectation));
}

namespace experimental {

StatusOr<EnclaveAssertionAuthorityConfig>
CreateSgxIntelEcdsaQeRemoteAssertionAuthorityConfig() {
  SgxIntelEcdsaQeRemoteAssertionAuthorityConfig sgx_config;
  *sgx_config.mutable_verifier_info()->add_root_certificates() =
      MakeIntelSgxRootCaCertificateProto();
  ASYLO_ASSIGN_OR_RETURN(
      *sgx_config.mutable_verifier_info()->mutable_qe_identity_expectation(),
      CreateDefaultExpectation(
          ParseTextProtoOrDie(sgx::kIntelEcdsaQeIdentityTextproto)));
  sgx_config.mutable_generator_info()->mutable_use_dcap_default();
  return SerializeToAuthorityConfig(
      sgx_config, SetSgxIntelEcdsaQeRemoteAssertionDescription);
}

StatusOr<EnclaveAssertionAuthorityConfig>
CreateSgxIntelEcdsaQeRemoteAssertionAuthorityConfig(
    CertificateChain pck_certificate_chain, SgxIdentity qe_identity) {
  if (pck_certificate_chain.certificates_size() == 0) {
    return absl::InvalidArgumentError(
        "The pck_certificate_chain must not be empty");
  }

  SgxIntelEcdsaQeRemoteAssertionAuthorityConfig sgx_config;
  *sgx_config.mutable_verifier_info()->add_root_certificates() =
      MakeIntelSgxRootCaCertificateProto();

  *sgx_config.mutable_generator_info()->mutable_pck_certificate_chain() =
      std::move(pck_certificate_chain);
  ASYLO_ASSIGN_OR_RETURN(
      *sgx_config.mutable_verifier_info()->mutable_qe_identity_expectation(),
      CreateDefaultExpectation(std::move(qe_identity)));
  ASYLO_RETURN_IF_ERROR(
      VerifySgxIntelEcdsaQeRemoteAssertionAuthorityConfig(sgx_config));

  return SerializeToAuthorityConfig(
      sgx_config, SetSgxIntelEcdsaQeRemoteAssertionDescription);
}

}  // namespace experimental

}  // namespace asylo
