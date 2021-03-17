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

#include "asylo/identity/sealing/sgx/internal/local_secret_sealer_helpers.h"

#include <cstdint>
#include <string>
#include <vector>

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/types/span.h"
#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/sha256_hash.h"
#include "asylo/crypto/util/byte_container_util.h"
#include "asylo/crypto/util/bytes.h"
#include "asylo/crypto/util/trivial_object_util.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/identity/identity_acl.pb.h"
#include "asylo/identity/platform/sgx/internal/hardware_interface.h"
#include "asylo/identity/platform/sgx/internal/secs_attributes.h"
#include "asylo/identity/platform/sgx/internal/self_identity.h"
#include "asylo/identity/platform/sgx/internal/sgx_identity_util_internal.h"
#include "asylo/identity/platform/sgx/machine_configuration.pb.h"
#include "asylo/identity/sealing/sealed_secret.pb.h"
#include "asylo/platform/common/singleton.h"
#include "asylo/util/cleansing_types.h"
#include "asylo/util/proto_enum_util.h"
#include "asylo/util/status_macros.h"

namespace asylo {
namespace sgx {
namespace internal {

const char *const kSgxLocalSecretSealerRootName = "SGX";

Status ParseKeyGenerationParamsFromSealedSecretHeader(
    const SealedSecretHeader &header, AeadScheme *aead_scheme,
    SgxIdentityExpectation *sgx_expectation) {
  const SealingRootInformation &root_info = header.root_info();
  if (root_info.sealing_root_type() != LOCAL) {
    return absl::InvalidArgumentError("Incorrect sealing_root_type");
  }
  if (root_info.sealing_root_name() != kSgxLocalSecretSealerRootName) {
    return absl::InvalidArgumentError("Incorrect sealing_root_name");
  }
  if (header.client_acl().item_case() != IdentityAclPredicate::kExpectation) {
    return absl::InvalidArgumentError("Malformed client_acl");
  }

  ASYLO_RETURN_IF_ERROR(
      ParseSgxExpectation(header.client_acl().expectation(), sgx_expectation));

  ASYLO_ASSIGN_OR_RETURN(*aead_scheme,
                         GetAeadSchemeFromSealedSecretHeader(header));

  bool result;
  std::string explanation;
  ASYLO_ASSIGN_OR_RETURN(
      result, MatchIdentityToExpectation(GetSelfIdentity()->sgx_identity,
                                         *sgx_expectation, &explanation));
  if (!result) {
    return absl::PermissionDeniedError(
        absl::StrCat("Identity of the current enclave does not match the ACL: ",
                     explanation));
  }
  return absl::OkStatus();
}

uint16_t ConvertMatchSpecToKeypolicy(const SgxIdentityMatchSpec &spec) {
  uint16_t policy = 0;
  if (spec.code_identity_match_spec().is_mrenclave_match_required()) {
    policy |= kKeypolicyMrenclaveBitMask;
  }
  if (spec.code_identity_match_spec().is_mrsigner_match_required()) {
    policy |= kKeypolicyMrsignerBitMask;
  }
  return policy;
}

Status GenerateCryptorKey(AeadScheme aead_scheme, const std::string &key_id,
                          const SgxIdentityExpectation &sgx_expectation,
                          size_t key_size, CleansingVector<uint8_t> *key) {
  // The function generates the |key_size| number of bytes by concatenating
  // bytes from one or more hardware-generated "subkeys." Each of the subkeys
  // is obtained by calling the GetKey() function. Except for the last subkey,
  // all bytes from all other subkeys are utilized. If more than one subkey is
  // used, each subkey is generated using a different value of the KEYID field
  // of the KEYREQUEST input to the GetKey() function. All the other fields of
  // the KEYREQUEST structure stay unchanged across the areKey() calls.

  // Create and populate an aligned KEYREQUEST structure.
  AlignedKeyrequestPtr req;

  // Zero-out the KEYREQUEST.
  *req = TrivialZeroObject<Keyrequest>();

  req->keyname = KeyrequestKeyname::SEAL_KEY;
  req->keypolicy = ConvertMatchSpecToKeypolicy(sgx_expectation.match_spec());
  req->isvsvn = sgx_expectation.reference_identity()
                    .code_identity()
                    .signer_assigned_identity()
                    .isvsvn();
  req->cpusvn = UnsafeBytes<kCpusvnSize>(sgx_expectation.reference_identity()
                                             .machine_configuration()
                                             .cpu_svn()
                                             .value());

  req->attributemask = SecsAttributeSet(sgx_expectation.match_spec()
                                            .code_identity_match_spec()
                                            .attributes_match_mask());

  // req->keyid is populated uniquely on each call to GetKey().
  req->miscmask = sgx_expectation.match_spec()
                      .code_identity_match_spec()
                      .miscselect_match_mask();

  key->resize(0);
  key->reserve(key_size);

  size_t remaining_key_bytes = key_size;
  size_t key_subscript = 0;
  Sha256Hash hasher;
  while (remaining_key_bytes > 0) {
    std::vector<uint8_t> key_info;
    // Build a key_info string that uniquely and unambiguously encodes
    // sealing-root description, ciphersuite with which the key will be used,
    // key identifier, key size, and key subscript.
    ASYLO_RETURN_IF_ERROR(SerializeByteContainers(
        &key_info, SealingRootType_Name(LOCAL), kSgxLocalSecretSealerRootName,
        AeadScheme_Name(aead_scheme), key_id, absl::StrCat(key_size),
        absl::StrCat(key_subscript)));

    static_assert(decltype(req->keyid)::size() == kSha256DigestLength,
                  "KEYREQUEST.KEYID field has unexpected size");

    hasher.Init();
    hasher.Update(key_info);
    std::vector<uint8_t> digest;
    hasher.CumulativeHash(&digest);
    req->keyid.assign(digest);

    HardwareKey hardware_key;
    ASYLO_ASSIGN_OR_RETURN(hardware_key,
                           HardwareInterface::CreateDefault()->GetKey(*req));
    size_t copy_size = std::min(hardware_key.size(), remaining_key_bytes);
    remaining_key_bytes -= copy_size;
    std::copy(hardware_key.cbegin(), hardware_key.cbegin() + copy_size,
              std::back_inserter(*key));
    ++key_subscript;
  }
  return absl::OkStatus();
}

StatusOr<std::unique_ptr<AeadCryptor>> MakeCryptor(AeadScheme aead_scheme,
                                                   ByteContainerView key) {
  switch (aead_scheme) {
    case AeadScheme::AES256_GCM_SIV:
      return AeadCryptor::CreateAesGcmSivCryptor(key);
    default:
      return absl::InvalidArgumentError("Unsupported cipher suite");
  }
}

Status Seal(AeadCryptor *cryptor, ByteContainerView secret,
            ByteContainerView additional_data, SealedSecret *sealed_secret) {
  std::vector<uint8_t> ciphertext(secret.size() + cryptor->MaxSealOverhead());
  std::vector<uint8_t> iv(cryptor->NonceSize());

  size_t ciphertext_size = 0;
  ASYLO_RETURN_IF_ERROR(
      cryptor->Seal(secret, additional_data, absl::MakeSpan(iv),
                    absl::MakeSpan(ciphertext), &ciphertext_size));

  sealed_secret->set_secret_ciphertext(ciphertext.data(), ciphertext_size);
  sealed_secret->set_iv(iv.data(), iv.size());

  return absl::OkStatus();
}

Status Open(AeadCryptor *cryptor, const SealedSecret &sealed_secret,
            ByteContainerView additional_data,
            CleansingVector<uint8_t> *secret) {
  secret->resize(sealed_secret.secret_ciphertext().size());
  size_t plaintext_size = 0;
  ASYLO_RETURN_IF_ERROR(cryptor->Open(
      sealed_secret.secret_ciphertext(), additional_data, sealed_secret.iv(),
      absl::MakeSpan(*secret), &plaintext_size));
  secret->resize(plaintext_size);
  return absl::OkStatus();
}

StatusOr<AeadScheme> GetAeadSchemeFromSealedSecretHeader(
    const SealedSecretHeader &header) {
  AeadScheme aead_scheme = header.root_info().aead_scheme();

  if (aead_scheme != AeadScheme::AES256_GCM_SIV) {
    return absl::InvalidArgumentError(absl::StrCat(
        "Unsupported AeadScheme ", ProtoEnumValueName(aead_scheme)));
  }

  return aead_scheme;
}

}  // namespace internal
}  // namespace sgx
}  // namespace asylo
