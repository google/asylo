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

#include "asylo/identity/sgx/local_secret_sealer_helpers.h"

#include <cstdint>
#include <vector>

#include "absl/strings/str_cat.h"
#include "absl/types/span.h"
#include "asylo/crypto/sha256_hash.h"
#include "asylo/crypto/util/byte_container_util.h"
#include "asylo/crypto/util/bytes.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/identity/identity_acl.pb.h"
#include "asylo/identity/sealed_secret.pb.h"
#include "asylo/identity/sgx/code_identity_util.h"
#include "asylo/identity/sgx/hardware_interface.h"
#include "asylo/identity/sgx/local_sealed_secret.pb.h"
#include "asylo/identity/sgx/self_identity.h"
#include "asylo/platform/common/singleton.h"
#include "asylo/util/cleansing_types.h"
#include "asylo/util/status_macros.h"

namespace asylo {
namespace sgx {
namespace internal {

using experimental::AeadCryptor;

const char *const kSgxLocalSecretSealerRootName = "SGX";

Status ParseKeyGenerationParamsFromSealedSecretHeader(
    const SealedSecretHeader &header, UnsafeBytes<kCpusvnSize> *cpusvn,
    CipherSuite *cipher_suite, CodeIdentityExpectation *sgx_expectation) {
  const SealingRootInformation &root_info = header.root_info();
  if (root_info.sealing_root_type() != LOCAL) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "Incorrect sealing_root_type");
  }
  if (root_info.sealing_root_name() != kSgxLocalSecretSealerRootName) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "Incorrect sealing_root_name");
  }
  SealedSecretAdditionalInfo info;
  if (!info.ParseFromString(root_info.additional_info())) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "Could not parse additional_info");
  }
  if (info.cpusvn().size() != cpusvn->size()) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "Incorrect cpusvn size");
  }
  cpusvn->assign(info.cpusvn().data(), info.cpusvn().size());
  ASYLO_ASSIGN_OR_RETURN(*cipher_suite,
                         ParseCipherSuiteFromSealedSecretHeader(header));
  if (header.client_acl().item_case() != IdentityAclPredicate::kExpectation) {
    return Status(error::GoogleError::INVALID_ARGUMENT, "Malformed client_acl");
  }
  const EnclaveIdentityExpectation &generic_expectation =
      header.client_acl().expectation();
  ASYLO_RETURN_IF_ERROR(
      ParseSgxExpectation(generic_expectation, sgx_expectation));
  bool result;
  ASYLO_ASSIGN_OR_RETURN(result,
                         MatchIdentityToExpectation(GetSelfIdentity()->identity,
                                                    *sgx_expectation));
  if (!result) {
    return Status(error::GoogleError::PERMISSION_DENIED,
                  "Identity of the current enclave does not match the ACL");
  }
  return Status::OkStatus();
}

uint16_t ConvertMatchSpecToKeypolicy(const CodeIdentityMatchSpec &spec) {
  uint16_t policy = 0;
  if (spec.is_mrenclave_match_required()) {
    policy |= kKeypolicyMrenclaveBitMask;
  }
  if (spec.is_mrsigner_match_required()) {
    policy |= kKeypolicyMrsignerBitMask;
  }
  return policy;
}

Status GenerateCryptorKey(CipherSuite cipher_suite, const std::string &key_id,
                          const UnsafeBytes<kCpusvnSize> &cpusvn,
                          const CodeIdentityExpectation &sgx_expectation,
                          size_t key_size, CleansingVector<uint8_t> *key) {
  // The function generates the |key_size| number of bytes by concatenating
  // bytes from one or more hardware-generated "subkeys." Each of the subkeys
  // is obtained by calling the GetHardwareKey() function. Except for the last
  // subkey, all bytes from all other subkeys are utilized. If more than one
  // subkey is used, each subkey is generated using a different value of
  // the KEYID field of the KEYREQUEST input to the GetHardwareKey() function.
  // All the other fields of the KEYREQUEST structure stay unchanged across
  // the GetHardwareKey() calls.

  // Create and populate an aligned KEYREQUEST structure.
  AlignedKeyrequestPtr req;
  req->keyname = KeyrequestKeyname::SEAL_KEY;
  req->keypolicy = ConvertMatchSpecToKeypolicy(sgx_expectation.match_spec());
  req->isvsvn =
      sgx_expectation.reference_identity().signer_assigned_identity().isvsvn();
  req->reserved1.fill(0);
  req->cpusvn = cpusvn;
  ConvertSecsAttributeRepresentation(
      sgx_expectation.match_spec().attributes_match_mask(),
      &req->attributemask);
  // req->keyid is populated uniquely on each call to GetHardwareKey().
  req->miscmask = sgx_expectation.match_spec().miscselect_match_mask();
  req->reserved2.fill(0);

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
        CipherSuite_Name(cipher_suite), key_id, absl::StrCat(key_size),
        absl::StrCat(key_subscript)));

    static_assert(decltype(req->keyid)::size() == SHA256_DIGEST_LENGTH,
                  "KEYREQUEST.KEYID field has unexpected size");

    hasher.Init();
    hasher.Update(key_info);
    std::vector<uint8_t> digest;
    hasher.CumulativeHash(&digest);
    req->keyid.assign(digest);

    AlignedHardwareKeyPtr hardware_key;
    ASYLO_RETURN_IF_ERROR(GetHardwareKey(*req, hardware_key.get()));
    size_t copy_size = std::min(hardware_key->size(), remaining_key_bytes);
    remaining_key_bytes -= copy_size;
    std::copy(hardware_key->cbegin(), hardware_key->cbegin() + copy_size,
              std::back_inserter(*key));
    ++key_subscript;
  }
  return Status::OkStatus();
}

StatusOr<std::unique_ptr<AeadCryptor>> MakeCryptor(CipherSuite cipher_suite,
                                                   ByteContainerView key) {
  switch (cipher_suite) {
    case sgx::AES256_GCM_SIV:
      return AeadCryptor::CreateAesGcmSivCryptor(key);
    case sgx::UNKNOWN_CIPHER_SUITE:
    default:
      return Status(error::GoogleError::INVALID_ARGUMENT,
                    "Unsupported cipher suite");
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

  return Status::OkStatus();
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
  return Status::OkStatus();
}

StatusOr<CipherSuite> ParseCipherSuiteFromSealedSecretHeader(
    const SealedSecretHeader &header) {
  SealedSecretAdditionalInfo info;
  if (!info.ParseFromString(header.root_info().additional_info())) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "Could not parse additional_info");
  }
  if (info.cipher_suite() == UNKNOWN_CIPHER_SUITE) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "Unsupported cipher suite");
  }
  return info.cipher_suite();
}

AeadScheme CipherSuiteToAeadScheme(CipherSuite cipher_suite) {
  switch (cipher_suite) {
    case sgx::AES256_GCM_SIV:
      return AeadScheme::AES256_GCM_SIV;
    default:
      return AeadScheme::UNKNOWN_AEAD_SCHEME;
  }
}

}  // namespace internal
}  // namespace sgx
}  // namespace asylo
