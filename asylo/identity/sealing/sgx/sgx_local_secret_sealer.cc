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

#include "asylo/identity/sealing/sgx/sgx_local_secret_sealer.h"

#include <memory>
#include <vector>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "asylo/crypto/aead_cryptor.h"
#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/util/byte_container_util.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/crypto/util/bytes.h"
#include "asylo/identity/identity_acl.pb.h"
#include "asylo/identity/platform/sgx/code_identity.pb.h"
#include "asylo/identity/platform/sgx/internal/identity_key_management_structs.h"
#include "asylo/identity/platform/sgx/sgx_identity.pb.h"
#include "asylo/identity/platform/sgx/sgx_identity_util.h"
#include "asylo/identity/sealing/sgx/internal/local_secret_sealer_helpers.h"
#include "asylo/util/status_macros.h"

namespace asylo {

constexpr size_t kAes256GcmSivKeySize = 32;

std::unique_ptr<SgxLocalSecretSealer>
SgxLocalSecretSealer::CreateMrenclaveSecretSealer() {
  // This always returns OK because the DEFAULT match spec options are valid.
  auto expectation_status = CreateSgxIdentityExpectation(
      GetSelfSgxIdentity(), SgxIdentityMatchSpecOptions::DEFAULT);
  CHECK(expectation_status.ok())
      << "Failed to create default self identity expectation";
  SgxIdentityExpectation expectation = expectation_status.value();

  // SgxIdentityMatchSpecOptions::DEFAULT sets the expectation to match
  // MRSIGNER. The match bit needs to be flipped so that the LocalSecretSealer
  // sets the ACL to match on MRENCLAVE.
  expectation.mutable_match_spec()
      ->mutable_code_identity_match_spec()
      ->set_is_mrenclave_match_required(true);
  expectation.mutable_match_spec()
      ->mutable_code_identity_match_spec()
      ->set_is_mrsigner_match_required(false);

  return absl::WrapUnique<SgxLocalSecretSealer>(
      new SgxLocalSecretSealer(expectation));
}

std::unique_ptr<SgxLocalSecretSealer>
SgxLocalSecretSealer::CreateMrsignerSecretSealer() {
  // This always returns OK because the DEFAULT match spec options are valid.
  auto expectation_status = CreateSgxIdentityExpectation(
      GetSelfSgxIdentity(), SgxIdentityMatchSpecOptions::DEFAULT);
  CHECK(expectation_status.ok())
      << "Failed to create default self identity expectation";
  SgxIdentityExpectation expectation = expectation_status.value();

  return absl::WrapUnique<SgxLocalSecretSealer>(
      new SgxLocalSecretSealer(expectation));
}

SgxLocalSecretSealer::SgxLocalSecretSealer(
    const SgxIdentityExpectation &default_client_acl)
    : default_client_acl_{default_client_acl} {}

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
  info->set_aead_scheme(AeadScheme::AES256_GCM_SIV);

  ASYLO_ASSIGN_OR_RETURN(*header->add_author(),
                         SerializeSgxIdentity(GetSelfSgxIdentity()));
  ASYLO_ASSIGN_OR_RETURN(*header->mutable_client_acl()->mutable_expectation(),
                         SerializeSgxIdentityExpectation(default_client_acl_));
  return absl::OkStatus();
}

StatusOr<size_t> SgxLocalSecretSealer::MaxMessageSize(
    const SealedSecretHeader &header) const {
  AeadScheme aead_scheme;
  ASYLO_ASSIGN_OR_RETURN(
      aead_scheme, sgx::internal::GetAeadSchemeFromSealedSecretHeader(header));
  return AeadCryptor::MaxMessageSize(aead_scheme);
}

StatusOr<uint64_t> SgxLocalSecretSealer::MaxSealedMessages(
    const SealedSecretHeader &header) const {
  AeadScheme aead_scheme;
  ASYLO_ASSIGN_OR_RETURN(
      aead_scheme, sgx::internal::GetAeadSchemeFromSealedSecretHeader(header));
  return AeadCryptor::MaxSealedMessages(aead_scheme);
}

Status SgxLocalSecretSealer::Seal(
    const SealedSecretHeader &header,
    ByteContainerView additional_authenticated_data, ByteContainerView secret,
    SealedSecret *sealed_secret) {
  AeadScheme aead_scheme;
  SgxIdentityExpectation sgx_expectation;
  ASYLO_RETURN_IF_ERROR(
      sgx::internal::ParseKeyGenerationParamsFromSealedSecretHeader(
          header, &aead_scheme, &sgx_expectation));

  if (!header.SerializeToString(
          sealed_secret->mutable_sealed_secret_header())) {
    return absl::InternalError("Header serialization to string failed");
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
      aead_scheme, "default_key_id", sgx_expectation, kAes256GcmSivKeySize,
      &key));

  std::unique_ptr<AeadCryptor> cryptor;
  ASYLO_ASSIGN_OR_RETURN(cryptor, sgx::internal::MakeCryptor(aead_scheme, key));
  return sgx::internal::Seal(cryptor.get(), secret, final_additional_data,
                             sealed_secret);
}

Status SgxLocalSecretSealer::Unseal(const SealedSecret &sealed_secret,
                                    CleansingVector<uint8_t> *secret) {
  SealedSecretHeader header;
  if (!header.ParseFromString(sealed_secret.sealed_secret_header())) {
    return absl::InvalidArgumentError(
        "Could not parse the sealed secret header");
  }

  AeadScheme aead_scheme;
  SgxIdentityExpectation sgx_expectation;
  ASYLO_RETURN_IF_ERROR(
      sgx::internal::ParseKeyGenerationParamsFromSealedSecretHeader(
          header, &aead_scheme, &sgx_expectation));

  std::string final_additional_data;
  SerializeByteContainers(&final_additional_data,
                          sealed_secret.sealed_secret_header(),
                          sealed_secret.additional_authenticated_data());

  CleansingVector<uint8_t> key;
  ASYLO_RETURN_IF_ERROR(sgx::internal::GenerateCryptorKey(
      aead_scheme, "default_key_id", sgx_expectation, kAes256GcmSivKeySize,
      &key));

  std::unique_ptr<AeadCryptor> cryptor;
  ASYLO_ASSIGN_OR_RETURN(cryptor, sgx::internal::MakeCryptor(aead_scheme, key));
  return sgx::internal::Open(cryptor.get(), sealed_secret,
                             final_additional_data, secret);
}

}  // namespace asylo
