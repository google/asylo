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

#include "asylo/test/util/enclave_assertion_authority_configs.h"

#include "asylo/crypto/certificate.pb.h"
#include "asylo/crypto/sha256_hash.pb.h"
#include "asylo/identity/enclave_assertion_authority_config.pb.h"
#include "asylo/identity/enclave_assertion_authority_configs.h"
#include "asylo/identity/identity_acl.pb.h"
#include "asylo/identity/platform/sgx/attributes.pb.h"
#include "asylo/identity/platform/sgx/code_identity.pb.h"
#include "asylo/identity/platform/sgx/internal/secs_attributes.h"
#include "asylo/identity/platform/sgx/sgx_identity.pb.h"
#include "asylo/identity/platform/sgx/sgx_identity_util.h"
#include "asylo/identity/provisioning/sgx/internal/fake_sgx_pki.h"
#include "asylo/util/proto_parse_util.h"
#include "debug_key_mrsigner.h"

namespace asylo {

// The attestation domain is expected to be a 16-byte unique identifier.
const char kAttestationDomain[] = "A 16-byte string";

EnclaveAssertionAuthorityConfig GetNullAssertionAuthorityTestConfig() {
  return CreateNullAssertionAuthorityConfig();
}

EnclaveAssertionAuthorityConfig GetSgxLocalAssertionAuthorityTestConfig() {
  return CreateSgxLocalAssertionAuthorityConfig(kAttestationDomain).value();
}

EnclaveAssertionAuthorityConfig GetSgxAgeRemoteAssertionAuthorityTestConfig(
    std::string server_address, SgxIdentity age_identity) {
  IdentityAclPredicate age_identity_expectation;

  SgxIdentityExpectation age_sgx_identity_expectation =
      CreateSgxIdentityExpectation(std::move(age_identity),
                                   SgxIdentityMatchSpecOptions::DEFAULT)
          .value();

  *age_identity_expectation.mutable_expectation() =
      SerializeSgxIdentityExpectation(age_sgx_identity_expectation).value();

  return CreateSgxAgeRemoteAssertionAuthorityConfig(
             sgx::GetFakeSgxRootCertificate(), {}, std::move(server_address),
             age_identity_expectation)
      .value();
}

EnclaveAssertionAuthorityConfig GetSgxAgeRemoteAssertionAuthorityTestConfig(
    std::string server_address) {
  SgxIdentity age_identity;
  sgx::CodeIdentity *age_code_identity = age_identity.mutable_code_identity();
  age_code_identity->set_miscselect(0);
  sgx::SecsAttributeSet attributes =
      sgx::SecsAttributeSet::FromBits({sgx::AttributeBit::INIT,
                                       sgx::AttributeBit::DEBUG,
                                       sgx::AttributeBit::MODE64BIT})
          .value();
  *age_code_identity->mutable_attributes() = attributes.ToProtoAttributes();
  sgx::SignerAssignedIdentity *age_signer_assigned_identity =
      age_identity.mutable_code_identity()->mutable_signer_assigned_identity();
  *age_signer_assigned_identity->mutable_mrsigner() =
      ParseTextProtoOrDie(linux_sgx::kDebugKeyMrsignerTextProto);
  age_signer_assigned_identity->set_isvprodid(0);
  age_signer_assigned_identity->set_isvsvn(0);

  return GetSgxAgeRemoteAssertionAuthorityTestConfig(std::move(server_address),
                                                     age_identity);
}

}  // namespace asylo
