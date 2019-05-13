/*
 *
 * Copyright 2018 Asylo authors
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

#include "asylo/crypto/ecdsa_p256_sha256_signing_key.h"

#include <openssl/bytestring.h>
#include <openssl/crypto.h>
#include <openssl/ec_key.h>
#include <openssl/ecdsa.h>
#include <openssl/mem.h>
#include <openssl/nid.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <cstdint>
#include <utility>
#include <vector>

#include "absl/memory/memory.h"
#include "asylo/crypto/sha256_hash.h"
#include "asylo/crypto/util/bssl_util.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"

namespace asylo {
namespace {

// Returns an EC_KEY containing the public key corresponding to |private_key|.
StatusOr<bssl::UniquePtr<EC_KEY>> CreatePublicKeyFromPrivateKey(
    const EC_KEY *private_key) {
  bssl::UniquePtr<EC_KEY> public_key(
      EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
  if (!public_key) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }
  if (!EC_KEY_set_public_key(public_key.get(),
                             EC_KEY_get0_public_key(private_key))) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }

  return std::move(public_key);
}

}  // namespace

// EcdsaP256Sha256VerifyingKey

StatusOr<std::unique_ptr<EcdsaP256Sha256VerifyingKey>>
EcdsaP256Sha256VerifyingKey::CreateFromDer(ByteContainerView serialized_key) {
  // The input data containing the serialized public key.
  uint8_t const *serialized_key_data = serialized_key.data();

  // Create a public key from the input data. If |a| was set, the EC_KEY object
  // referenced by |a| would be freed and |a| would be updated to point to the
  // returned object.
  bssl::UniquePtr<EC_KEY> key(d2i_EC_PUBKEY(/*a=*/nullptr, &serialized_key_data,
                                            serialized_key.size()));
  if (!key) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }
  return Create(std::move(key));
}

StatusOr<std::unique_ptr<EcdsaP256Sha256VerifyingKey>>
EcdsaP256Sha256VerifyingKey::CreateFromPem(ByteContainerView serialized_key) {
  // The input bio object containing the serialized public key.
  bssl::UniquePtr<BIO> key_bio(
      BIO_new_mem_buf(serialized_key.data(), serialized_key.size()));

  // Create a public key from the input PEM data. For more information, see
  // https://www.openssl.org/docs/man1.1.0/man3/PEM_read_bio_EC_PUBKEY.html.
  bssl::UniquePtr<EC_KEY> key(PEM_read_bio_EC_PUBKEY(
      key_bio.get(), /*x=*/nullptr, /*cb=*/nullptr, /*u=*/nullptr));
  if (!key) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }

  return Create(std::move(key));
}

StatusOr<std::unique_ptr<EcdsaP256Sha256VerifyingKey>>
EcdsaP256Sha256VerifyingKey::Create(bssl::UniquePtr<EC_KEY> public_key) {
  if (EC_GROUP_get_curve_name(EC_KEY_get0_group(public_key.get())) !=
      NID_X9_62_prime256v1) {
    return Status(
        error::GoogleError::INVALID_ARGUMENT,
        "public_key parameter must represent a point on the NIST P256 curve");
  }

  return absl::WrapUnique<EcdsaP256Sha256VerifyingKey>(
      new EcdsaP256Sha256VerifyingKey(std::move(public_key)));
}

SignatureScheme EcdsaP256Sha256VerifyingKey::GetSignatureScheme() const {
  return SignatureScheme::ECDSA_P256_SHA256;
}

StatusOr<std::string> EcdsaP256Sha256VerifyingKey::SerializeToDer() const {
  uint8_t *key = nullptr;
  int length = i2d_EC_PUBKEY(public_key_.get(), &key);
  if (length <= 0) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }
  bssl::UniquePtr<uint8_t> deleter(key);
  return std::string(reinterpret_cast<char *>(key), length);
}

Status EcdsaP256Sha256VerifyingKey::Verify(ByteContainerView message,
                                           ByteContainerView signature) const {
  Sha256Hash hasher;
  hasher.Init();
  hasher.Update(message);
  std::vector<uint8_t> digest;
  ASYLO_RETURN_IF_ERROR(hasher.CumulativeHash(&digest));

  if (!ECDSA_verify(/*type=*/0, digest.data(), digest.size(), signature.data(),
                    signature.size(), public_key_.get())) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }
  return Status::OkStatus();
}

EcdsaP256Sha256VerifyingKey::EcdsaP256Sha256VerifyingKey(
    bssl::UniquePtr<EC_KEY> public_key)
    : public_key_(std::move(public_key)) {}

// EcdsaP256Sha256SigningKey

StatusOr<std::unique_ptr<EcdsaP256Sha256SigningKey>>
EcdsaP256Sha256SigningKey::Create() {
  bssl::UniquePtr<EC_KEY> key(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
  if (!key) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }

  int result = 0;
  if (FIPS_mode()) {
    result = EC_KEY_generate_key_fips(key.get());
  } else {
    result = EC_KEY_generate_key(key.get());
  }
  if (!result) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }

  return EcdsaP256Sha256SigningKey::Create(std::move(key));
}

StatusOr<std::unique_ptr<EcdsaP256Sha256SigningKey>>
EcdsaP256Sha256SigningKey::CreateFromDer(ByteContainerView serialized_key) {
  CBS buffer;
  CBS_init(&buffer, serialized_key.data(), serialized_key.size());

  bssl::UniquePtr<EC_GROUP> group(
      EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
  if (!group) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }

  bssl::UniquePtr<EC_KEY> key(EC_KEY_parse_private_key(&buffer, group.get()));
  if (!key) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }

  return Create(std::move(key));
}

StatusOr<std::unique_ptr<EcdsaP256Sha256SigningKey>>
EcdsaP256Sha256SigningKey::CreateFromPem(ByteContainerView serialized_key) {
  // The input bio object containing the serialized public key.
  bssl::UniquePtr<BIO> key_bio(
      BIO_new_mem_buf(serialized_key.data(), serialized_key.size()));

  // Create a private key from the input PEM data.
  bssl::UniquePtr<EC_KEY> key(PEM_read_bio_ECPrivateKey(
      key_bio.get(), /*x=*/nullptr, /*cb=*/nullptr, /*u=*/nullptr));
  if (!key) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }

  return Create(std::move(key));
}

StatusOr<std::unique_ptr<EcdsaP256Sha256SigningKey>>
EcdsaP256Sha256SigningKey::Create(bssl::UniquePtr<EC_KEY> private_key) {
  if (EC_GROUP_get_curve_name(EC_KEY_get0_group(private_key.get())) !=
      NID_X9_62_prime256v1) {
    return Status(
        error::GoogleError::INVALID_ARGUMENT,
        "private_key parameter must be a key for the NIST P256 curve");
  }

  auto public_key_result = CreatePublicKeyFromPrivateKey(private_key.get());
  if (!public_key_result.ok()) {
    return public_key_result.status();
  }

  return absl::WrapUnique<EcdsaP256Sha256SigningKey>(
      new EcdsaP256Sha256SigningKey(std::move(private_key),
                                    std::move(public_key_result).ValueOrDie()));
}

Status EcdsaP256Sha256SigningKey::SerializeToDer(
    CleansingVector<uint8_t> *serialized_key) const {
  CBB buffer;
  if (!CBB_init(&buffer, /*initial_capacity=*/0) ||
      !EC_KEY_marshal_private_key(&buffer, private_key_.get(),
                                  EC_KEY_get_enc_flags(private_key_.get()))) {
    CBB_cleanup(&buffer);
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }

  uint8_t *key_data;
  size_t key_data_size = 0;
  CBB_finish(&buffer, &key_data, &key_data_size);

  serialized_key->assign(key_data, key_data + key_data_size);

  OPENSSL_cleanse(key_data, key_data_size);
  OPENSSL_free(key_data);

  return Status::OkStatus();
}

SignatureScheme EcdsaP256Sha256SigningKey::GetSignatureScheme() const {
  return SignatureScheme::ECDSA_P256_SHA256;
}

StatusOr<std::unique_ptr<VerifyingKey>>
EcdsaP256Sha256SigningKey::GetVerifyingKey() const {
  bssl::UniquePtr<EC_KEY> public_key_copy(EC_KEY_dup(public_key_.get()));
  if (!public_key_copy) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }

  return EcdsaP256Sha256VerifyingKey::Create(std::move(public_key_copy));
}

Status EcdsaP256Sha256SigningKey::Sign(ByteContainerView message,
                                       std::vector<uint8_t> *signature) const {
  Sha256Hash hasher;
  hasher.Init();
  hasher.Update(message);
  std::vector<uint8_t> digest;
  ASYLO_RETURN_IF_ERROR(hasher.CumulativeHash(&digest));

  signature->resize(ECDSA_size(private_key_.get()));
  uint32_t signature_size = 0;
  if (!ECDSA_sign(/*type=*/0, digest.data(), digest.size(), signature->data(),
                  &signature_size, private_key_.get())) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }
  signature->resize(signature_size);
  return Status::OkStatus();
}

EcdsaP256Sha256SigningKey::EcdsaP256Sha256SigningKey(
    bssl::UniquePtr<EC_KEY> private_key, bssl::UniquePtr<EC_KEY> public_key)
    : private_key_(std::move(private_key)),
      public_key_(std::move(public_key)) {}

}  // namespace asylo
