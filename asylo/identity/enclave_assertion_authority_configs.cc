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
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "asylo/daemon/identity/attestation_domain.h"
#include "asylo/identity/attestation/sgx/sgx_age_remote_assertion_authority_config.pb.h"
#include "asylo/identity/attestation/sgx/sgx_intel_ecdsa_qe_remote_assertion_authority_config.pb.h"
#include "asylo/identity/descriptions.h"
#include "asylo/identity/enclave_assertion_authority_config.pb.h"
#include "asylo/identity/enclave_assertion_authority_config_verifiers.h"
#include "asylo/identity/sgx/intel_certs/intel_sgx_root_ca_cert.h"
#include "asylo/identity/sgx/sgx_local_assertion_authority_config.pb.h"
#include "asylo/util/proto_enum_util.h"
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
    return Status(
        error::GoogleError::INTERNAL,
        absl::StrCat("Failed to serialize ", inner_config.GetTypeName()));
  }

  set_description(authority_config.mutable_description());
  return authority_config;
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

namespace experimental {

StatusOr<EnclaveAssertionAuthorityConfig>
CreateSgxIntelEcdsaQeRemoteAssertionAuthorityConfig() {
  SgxIntelEcdsaQeRemoteAssertionAuthorityConfig sgx_config;
  *sgx_config.mutable_verifier_info()->add_root_certificates() =
      MakeIntelSgxRootCaCertificateProto();
  sgx_config.mutable_generator_info()->mutable_use_dcap_default();
  return SerializeToAuthorityConfig(
      sgx_config, SetSgxIntelEcdsaQeRemoteAssertionDescription);
}

StatusOr<EnclaveAssertionAuthorityConfig>
CreateSgxIntelEcdsaQeRemoteAssertionAuthorityConfig(
    std::vector<Certificate> pck_certificate_chain) {
  if (pck_certificate_chain.empty()) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "The pck_certificate_chain must not be empty");
  }

  SgxIntelEcdsaQeRemoteAssertionAuthorityConfig sgx_config;
  *sgx_config.mutable_verifier_info()->add_root_certificates() =
      MakeIntelSgxRootCaCertificateProto();

  auto config_pck_certs =
      sgx_config.mutable_generator_info()->mutable_pck_certificate_chain();
  for (auto &cert : pck_certificate_chain) {
    *config_pck_certs->add_certificates() = std::move(cert);
  }
  ASYLO_RETURN_IF_ERROR(
      VerifySgxIntelEcdsaQeRemoteAssertionAuthorityConfig(sgx_config));

  return SerializeToAuthorityConfig(
      sgx_config, SetSgxIntelEcdsaQeRemoteAssertionDescription);
}

}  // namespace experimental

}  // namespace asylo
