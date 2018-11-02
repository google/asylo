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

#include "asylo/identity/sgx/sgx_local_secret_sealer.h"

#include <memory>
#include <vector>

#include "absl/memory/memory.h"
#include "asylo/crypto/aes_gcm_siv.h"
#include "asylo/crypto/util/byte_container_util.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/crypto/util/bytes.h"
#include "asylo/identity/identity_acl.pb.h"
#include "asylo/identity/sgx/code_identity.pb.h"
#include "asylo/identity/sgx/code_identity_util.h"
#include "asylo/identity/sgx/identity_key_management_structs.h"
#include "asylo/identity/sgx/local_secret_sealer_helpers.h"
#include "asylo/identity/sgx/self_identity.h"
#include "asylo/util/status_macros.h"

namespace asylo {

constexpr size_t kAes256GcmSivKeySize = 32;

std::unique_ptr<SgxLocalSecretSealer>
SgxLocalSecretSealer::CreateMrenclaveSecretSealer() {
  sgx::CodeIdentityMatchSpec spec;
  sgx::SetDefaultMatchSpec(&spec);

  // SetDefaultMatchSpec() sets the expectation to match MRSIGNER. The match bit
  // needs to be flipped so that the LocalSecretSealer sets the ACL to match on
  // MRENCLAVE.
  spec.set_is_mrenclave_match_required(true);
  spec.set_is_mrsigner_match_required(false);
  sgx::CodeIdentityExpectation expectation;
  sgx::SetExpectation(spec, sgx::GetSelfIdentity()->identity, &expectation);
  return absl::WrapUnique<SgxLocalSecretSealer>(
      new SgxLocalSecretSealer(expectation));
}

std::unique_ptr<SgxLocalSecretSealer>
SgxLocalSecretSealer::CreateMrsignerSecretSealer() {
  sgx::CodeIdentityMatchSpec spec;
  sgx::SetDefaultMatchSpec(&spec);
  sgx::CodeIdentityExpectation expectation;
  sgx::SetExpectation(spec, sgx::GetSelfIdentity()->identity, &expectation);
  return absl::WrapUnique<SgxLocalSecretSealer>(
      new SgxLocalSecretSealer(expectation));
}

SgxLocalSecretSealer::SgxLocalSecretSealer(
    const sgx::CodeIdentityExpectation &default_client_acl)
    : cryptor_{new AesGcmSivCryptor(kMaxAesGcmSivMessageSize,
                                    new AesGcmSivNonceGenerator())},
      default_client_acl_{default_client_acl} {}

SealingRootType SgxLocalSecretSealer::RootType() const { return LOCAL; }

std::string SgxLocalSecretSealer::RootName() const {
  return sgx::internal::kSgxLocalSecretSealerRootName;
}

std::vector<EnclaveIdentityExpectation> SgxLocalSecretSealer::RootAcl() const {
  // There is no enclave-identity-based ACL for an SGX local root.
  return {};
}

Status SgxLocalSecretSealer::SetDefaultHeader(
    SealedSecretHeader *header) const {
  SealingRootInformation *info = header->mutable_root_info();
  info->set_sealing_root_type(RootType());
  info->set_sealing_root_name(RootName());
  sgx::SealedSecretAdditionalInfo additional_info;

  // Default cipher suite is AES256_GCM_SIV.
  additional_info.set_cipher_suite(sgx::AES256_GCM_SIV);
  const UnsafeBytes<sgx::kCpusvnSize> &cpusvn = sgx::GetSelfIdentity()->cpusvn;
  additional_info.set_cpusvn(reinterpret_cast<const char *>(cpusvn.data()),
                             cpusvn.size());
  if (!additional_info.SerializeToString(info->mutable_additional_info())) {
    return Status(error::GoogleError::INTERNAL,
                  "Could not serialize additional info");
  }
  ASYLO_RETURN_IF_ERROR(sgx::SerializeSgxIdentity(
      sgx::GetSelfIdentity()->identity, header->add_author()));
  return sgx::SerializeSgxExpectation(
      default_client_acl_, header->mutable_client_acl()->mutable_expectation());
}

Status SgxLocalSecretSealer::Seal(
    const SealedSecretHeader &header,
    ByteContainerView additional_authenticated_data, ByteContainerView secret,
    SealedSecret *sealed_secret) {
  UnsafeBytes<sgx::kCpusvnSize> cpusvn;
  sgx::CipherSuite cipher_suite;
  sgx::CodeIdentityExpectation sgx_expectation;
  ASYLO_RETURN_IF_ERROR(
      sgx::internal::ParseKeyGenerationParamsFromSealedSecretHeader(
          header, &cpusvn, &cipher_suite, &sgx_expectation));

  if (!header.SerializeToString(
          sealed_secret->mutable_sealed_secret_header())) {
    return Status(error::GoogleError::INTERNAL,
                  "Header serialization to std::string failed");
  }
  sealed_secret->set_additional_authenticated_data(
      reinterpret_cast<const char *>(additional_authenticated_data.data()),
      additional_authenticated_data.size());

  std::string final_additional_data;
  SerializeByteContainers(&final_additional_data,
                          sealed_secret->sealed_secret_header(),
                          additional_authenticated_data);

  CleansingVector<uint8_t> key;
  ASYLO_RETURN_IF_ERROR(sgx::internal::GenerateCryptorKey(
      cipher_suite, "default_key_id", cpusvn, sgx_expectation,
      kAes256GcmSivKeySize, &key));

  return cryptor_->Seal(key, final_additional_data, secret,
                        sealed_secret->mutable_iv(),
                        sealed_secret->mutable_secret_ciphertext());
}

Status SgxLocalSecretSealer::Unseal(const SealedSecret &sealed_secret,
                                    CleansingVector<uint8_t> *secret) {
  SealedSecretHeader header;
  if (!header.ParseFromString(sealed_secret.sealed_secret_header())) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "Could not parse the sealed secret header");
  }

  UnsafeBytes<sgx::kCpusvnSize> cpusvn;
  sgx::CipherSuite cipher_suite;
  sgx::CodeIdentityExpectation sgx_expectation;
  ASYLO_RETURN_IF_ERROR(
      sgx::internal::ParseKeyGenerationParamsFromSealedSecretHeader(
          header, &cpusvn, &cipher_suite, &sgx_expectation));

  std::string final_additional_data;
  SerializeByteContainers(&final_additional_data,
                          sealed_secret.sealed_secret_header(),
                          sealed_secret.additional_authenticated_data());

  CleansingVector<uint8_t> key;
  ASYLO_RETURN_IF_ERROR(sgx::internal::GenerateCryptorKey(
      cipher_suite, "default_key_id", cpusvn, sgx_expectation,
      kAes256GcmSivKeySize, &key));

  return cryptor_->Open(key, final_additional_data,
                        sealed_secret.secret_ciphertext(), sealed_secret.iv(),
                        secret);
}

}  // namespace asylo
