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

#include "asylo/identity/sgx/local_secret_sealer.h"

#include <memory>
#include <vector>

#include "absl/memory/memory.h"
#include "asylo/identity/identity_acl.pb.h"
#include "asylo/identity/sgx/code_identity.pb.h"
#include "asylo/identity/sgx/code_identity_util.h"
#include "asylo/identity/sgx/identity_key_management_structs.h"
#include "asylo/identity/sgx/local_secret_sealer_helpers.h"
#include "asylo/identity/sgx/self_identity.h"
#include "asylo/identity/util/byte_container_util.h"
#include "asylo/identity/util/byte_container_view.h"
#include "asylo/platform/crypto/aes_gcm_siv.h"

namespace asylo {
namespace sgx {

constexpr size_t kAes256GcmSivKeySize = 32;

std::unique_ptr<LocalSecretSealer>
LocalSecretSealer::CreateMrenclaveSecretSealer() {
  CodeIdentityMatchSpec spec;
  SetDefaultMatchSpec(&spec);

  // SetDefaultMatchSpec() sets the expectation to match MRSIGNER. The match bit
  // needs to be flipped so that the LocalSecretSealer sets the ACL to match on
  // MRENCLAVE.
  spec.set_is_mrenclave_match_required(true);
  spec.set_is_mrsigner_match_required(false);
  CodeIdentityExpectation expectation;
  SetExpectation(spec, GetSelfIdentity()->identity, &expectation);
  return absl::WrapUnique<LocalSecretSealer>(
      new LocalSecretSealer(expectation));
}

std::unique_ptr<LocalSecretSealer>
LocalSecretSealer::CreateMrsignerSecretSealer() {
  CodeIdentityMatchSpec spec;
  SetDefaultMatchSpec(&spec);
  CodeIdentityExpectation expectation;
  SetExpectation(spec, GetSelfIdentity()->identity, &expectation);
  return absl::WrapUnique<LocalSecretSealer>(
      new LocalSecretSealer(expectation));
}

LocalSecretSealer::LocalSecretSealer(
    const CodeIdentityExpectation &default_client_acl)
    : cryptor_{new AesGcmSivCryptor(kMaxAesGcmSivMessageSize,
                                    new AesGcmSivNonceGenerator())},
      default_client_acl_{default_client_acl} {}

SealingRootType LocalSecretSealer::RootType() const { return LOCAL; }

std::string LocalSecretSealer::RootName() const {
  return internal::kSgxLocalSecretSealerRootName;
}

std::vector<EnclaveIdentityExpectation> LocalSecretSealer::RootAcl() const {
  // There is no enclave-identity-based ACL for an SGX local root.
  return {};
}

Status LocalSecretSealer::SetDefaultHeader(SealedSecretHeader *header) const {
  SealingRootInformation *info = header->mutable_root_info();
  info->set_sealing_root_type(RootType());
  info->set_sealing_root_name(RootName());
  SealedSecretAdditionalInfo additional_info;

  // Default cipher suite is AES256_GCM_SIV.
  additional_info.set_cipher_suite(AES256_GCM_SIV);
  const UnsafeBytes<kCpusvnSize> &cpusvn = GetSelfIdentity()->cpusvn;
  additional_info.set_cpusvn(reinterpret_cast<const char *>(cpusvn.data()),
                             cpusvn.size());
  if (!additional_info.SerializeToString(info->mutable_additional_info())) {
    return Status(::asylo::error::GoogleError::INTERNAL,
                  "Could not serialize additional info");
  }
  Status status =
      SerializeSgxIdentity(GetSelfIdentity()->identity, header->add_author());
  if (!status.ok()) {
    return status;
  }

  return SerializeSgxExpectation(
      default_client_acl_, header->mutable_client_acl()->mutable_expectation());
}

Status LocalSecretSealer::Seal(const SealedSecretHeader &header,
                               ByteContainerView additional_authenticated_data,
                               ByteContainerView secret,
                               SealedSecret *sealed_secret) {
  UnsafeBytes<kCpusvnSize> cpusvn;
  CipherSuite cipher_suite;
  CodeIdentityExpectation sgx_expectation;
  Status status = internal::ParseKeyGenerationParamsFromSealedSecretHeader(
      header, &cpusvn, &cipher_suite, &sgx_expectation);
  if (!status.ok()) {
    return status;
  }

  if (!header.SerializeToString(
          sealed_secret->mutable_sealed_secret_header())) {
    return Status(::asylo::error::GoogleError::INTERNAL,
                  "Header serialization to std::string failed");
  }
  sealed_secret->set_additional_authenticated_data(
      reinterpret_cast<const char *>(additional_authenticated_data.data()),
      additional_authenticated_data.size());

  std::string final_additional_data;
  std::vector<ByteContainerView> views{sealed_secret->sealed_secret_header(),
                                       additional_authenticated_data};
  SerializeByteContainers(views, &final_additional_data);

  CleansingVector<uint8_t> key;
  status =
      internal::GenerateCryptorKey(cipher_suite, "default_key_id", cpusvn,
                                   sgx_expectation, kAes256GcmSivKeySize, &key);
  if (!status.ok()) {
    return status;
  }

  return cryptor_->Seal(key, final_additional_data, secret,
                        sealed_secret->mutable_iv(),
                        sealed_secret->mutable_secret_ciphertext());
}

Status LocalSecretSealer::Unseal(const SealedSecret &sealed_secret,
                                 CleansingVector<uint8_t> *secret) {
  SealedSecretHeader header;
  if (!header.ParseFromString(sealed_secret.sealed_secret_header())) {
    return Status(::asylo::error::GoogleError::INVALID_ARGUMENT,
                  "Could not parse the sealed secret header");
  }

  UnsafeBytes<kCpusvnSize> cpusvn;
  CipherSuite cipher_suite;
  CodeIdentityExpectation sgx_expectation;
  Status status = internal::ParseKeyGenerationParamsFromSealedSecretHeader(
      header, &cpusvn, &cipher_suite, &sgx_expectation);
  if (!status.ok()) {
    return status;
  }

  std::string final_additional_data;
  std::vector<ByteContainerView> views{
      sealed_secret.sealed_secret_header(),
      sealed_secret.additional_authenticated_data()};
  SerializeByteContainers(views, &final_additional_data);

  CleansingVector<uint8_t> key;
  status =
      internal::GenerateCryptorKey(cipher_suite, "default_key_id", cpusvn,
                                   sgx_expectation, kAes256GcmSivKeySize, &key);
  if (!status.ok()) {
    return status;
  }

  return cryptor_->Open(key, final_additional_data,
                        sealed_secret.secret_ciphertext(), sealed_secret.iv(),
                        secret);
}

}  // namespace sgx
}  // namespace asylo
