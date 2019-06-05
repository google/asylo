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

#include "asylo/crypto/rsa_oaep_encryption_key.h"

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/pem.h>

#include "absl/strings/str_cat.h"
#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/asymmetric_encryption_key.h"
#include "asylo/crypto/util/bssl_util.h"
#include "asylo/crypto/util/byte_container_util.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/util/status_macros.h"

namespace asylo {
namespace {

StatusOr<bssl::UniquePtr<RSA>> CreateRsaKey(int number_of_bits) {
  bssl::UniquePtr<RSA> rsa(RSA_new());
  bssl::UniquePtr<BIGNUM> e(BN_new());

  if (!BN_set_word(e.get(), RSA_F4) ||
      !RSA_generate_key_ex(rsa.get(), number_of_bits, e.get(),
                           /*cb=*/nullptr)) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }
  return std::move(rsa);
}

AsymmetricEncryptionScheme GetAsymmetricEncryptionScheme(int number_of_bits) {
  switch (number_of_bits) {
    case 3072:
      return AsymmetricEncryptionScheme::RSA3072_OAEP;
    case 2048:
      return AsymmetricEncryptionScheme::RSA2048_OAEP;
    default:
      return AsymmetricEncryptionScheme::UNKNOWN_ASYMMETRIC_ENCRYPTION_SCHEME;
  }
}

Status CheckKeySize(int key_size) {
  if (key_size != 2048 && key_size != 3072) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  absl::StrCat("Invalid key size: ", key_size));
  }
  return Status::OkStatus();
}

}  // namespace

StatusOr<std::unique_ptr<RsaOaepEncryptionKey>>
RsaOaepEncryptionKey::CreateFromDer(ByteContainerView serialized_key) {
  // The input data containing the serialized public key.
  bssl::UniquePtr<RSA> public_key(
      RSA_public_key_from_bytes(serialized_key.data(), serialized_key.size()));
  if (!public_key) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }
  ASYLO_RETURN_IF_ERROR(CheckKeySize(RSA_bits(public_key.get())));

  return Create(std::move(public_key));
}

StatusOr<std::unique_ptr<RsaOaepEncryptionKey>>
RsaOaepEncryptionKey::CreateFromPem(ByteContainerView serialized_key) {
  // The input data containing the serialized public key.
  bssl::UniquePtr<BIO> key_bio(
      BIO_new_mem_buf(serialized_key.data(), serialized_key.size()));

  // Create a public key from the input PEM data. For more information, see
  // https://www.openssl.org/docs/man1.1.0/man3/PEM_read_bio_RSA_PUBKEY.html
  bssl::UniquePtr<RSA> public_key(PEM_read_bio_RSA_PUBKEY(
      key_bio.get(), /*x=*/nullptr, /*cb=*/nullptr, /*u=*/nullptr));
  if (!public_key) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }
  ASYLO_RETURN_IF_ERROR(CheckKeySize(RSA_bits(public_key.get())));

  return Create(std::move(public_key));
}

StatusOr<std::unique_ptr<RsaOaepEncryptionKey>> RsaOaepEncryptionKey::Create(
    bssl::UniquePtr<RSA> public_key) {
  const BIGNUM *n;
  const BIGNUM *e;
  RSA_get0_key(public_key.get(), &n, &e, /*out_d=*/nullptr);
  if (n == nullptr || e == nullptr) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "Public key is invalid");
  }

  return absl::WrapUnique<RsaOaepEncryptionKey>(
      new RsaOaepEncryptionKey(std::move(public_key)));
}

const RSA *RsaOaepEncryptionKey::GetRsaPublicKey() const {
  return public_key_.get();
}

AsymmetricEncryptionScheme RsaOaepEncryptionKey::GetEncryptionScheme() const {
  return GetAsymmetricEncryptionScheme(RSA_bits(public_key_.get()));
}

StatusOr<std::string> RsaOaepEncryptionKey::SerializeToDer() const {
  uint8_t *buffer = nullptr;
  size_t out_len;
  if (RSA_public_key_to_bytes(&buffer, &out_len, public_key_.get()) != 1) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }
  bssl::UniquePtr<uint8_t> deleter(buffer);
  return CopyToByteContainer<std::string>({buffer, out_len});
}

Status RsaOaepEncryptionKey::Encrypt(ByteContainerView plaintext,
                                     std::vector<uint8_t> *ciphertext) const {
  size_t out_len;
  ciphertext->resize(RSA_size(public_key_.get()));
  if (RSA_encrypt(public_key_.get(), &out_len, ciphertext->data(),
                  ciphertext->size(), plaintext.data(), plaintext.size(),
                  RSA_PKCS1_OAEP_PADDING) != 1) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }
  ciphertext->resize(out_len);
  return Status::OkStatus();
}

RsaOaepEncryptionKey::RsaOaepEncryptionKey(bssl::UniquePtr<RSA> public_key)
    : public_key_(std::move(public_key)) {}

StatusOr<std::unique_ptr<RsaOaepDecryptionKey>>
RsaOaepDecryptionKey::CreateRsa3072OaepDecryptionKey() {
  bssl::UniquePtr<RSA> private_key(RSA_new());
  ASYLO_ASSIGN_OR_RETURN(private_key, CreateRsaKey(/*number_of_bits=*/3072));
  return absl::WrapUnique<RsaOaepDecryptionKey>(
      new RsaOaepDecryptionKey(std::move(private_key)));
}

StatusOr<std::unique_ptr<RsaOaepDecryptionKey>>
RsaOaepDecryptionKey::CreateFromDer(ByteContainerView serialized_key) {
  // The input data containing the serialized public key.
  bssl::UniquePtr<RSA> private_key(
      RSA_private_key_from_bytes(serialized_key.data(), serialized_key.size()));
  if (!private_key) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }
  ASYLO_RETURN_IF_ERROR(CheckKeySize(RSA_bits(private_key.get())));

  return absl::WrapUnique<RsaOaepDecryptionKey>(
      new RsaOaepDecryptionKey(std::move(private_key)));
}

AsymmetricEncryptionScheme RsaOaepDecryptionKey::GetEncryptionScheme() const {
  return GetAsymmetricEncryptionScheme(RSA_bits(private_key_.get()));
}

Status RsaOaepDecryptionKey::SerializeToDer(
    CleansingVector<uint8_t> *serialized_key) const {
  uint8_t *buffer = nullptr;
  size_t out_len;
  if (RSA_private_key_to_bytes(&buffer, &out_len, private_key_.get()) != 1) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }
  bssl::UniquePtr<uint8_t> deleter(buffer);
  serialized_key->assign(buffer, buffer + out_len);
  return Status::OkStatus();
}

StatusOr<std::unique_ptr<AsymmetricEncryptionKey>>
RsaOaepDecryptionKey::GetEncryptionKey() const {
  bssl::UniquePtr<RSA> public_key_copy(RSAPublicKey_dup(private_key_.get()));
  if (!public_key_copy) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }
  return RsaOaepEncryptionKey::Create(std::move(public_key_copy));
}

Status RsaOaepDecryptionKey::Decrypt(
    ByteContainerView ciphertext, CleansingVector<uint8_t> *plaintext) const {
  size_t out_len;
  plaintext->resize(RSA_size(private_key_.get()));
  if (RSA_decrypt(private_key_.get(), &out_len, plaintext->data(),
                  plaintext->size(), ciphertext.data(), ciphertext.size(),
                  RSA_PKCS1_OAEP_PADDING) != 1) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }
  plaintext->resize(out_len);
  return Status::OkStatus();
}

RsaOaepDecryptionKey::RsaOaepDecryptionKey(bssl::UniquePtr<RSA> private_key)
    : private_key_(std::move(private_key)) {}

}  // namespace asylo
