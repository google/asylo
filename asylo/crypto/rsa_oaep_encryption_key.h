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

#ifndef ASYLO_CRYPTO_RSA_OAEP_ENCRYPTION_KEY_H_
#define ASYLO_CRYPTO_RSA_OAEP_ENCRYPTION_KEY_H_

#include <openssl/base.h>
#include <openssl/rsa.h>

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/asymmetric_encryption_key.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

namespace asylo {

// An implementation of the AsymmetricEncryptionKey interface that uses
// RSA-OAEP for message encryption. Currently, the implementation only
// supports RSA-2048 and RSA-3072.
//
// The maximum size of a plaintext message that can be encrypted by
// RsaOaepEncryptionKey is determined by the size of the |public_key_| and the
// length of digests produced by the OAEP hash function.
//
// Specifically, the max size is calculated based on formula:
// max_size <= k - 2hLen - 2, where k is the length in octets of the RSA modulus
// n, and hLen is the digest length in octets of OAEP function.
//
// For example, consider OAEP with SHA-1 which produces a digest size of 20
// bytes. An RsaOaepEncryptionKey with a 3072-bit key can encrypt a message that
// has maximum size 384 - 2 * 20 - 2 = 342 bytes.
class RsaOaepEncryptionKey : public AsymmetricEncryptionKey {
 public:
  // Creates an RSA encryption key from the given DER-encoded
  // |serialized_key|. Uses |hash_alg| for OAEP padding.
  static StatusOr<std::unique_ptr<RsaOaepEncryptionKey>> CreateFromDer(
      ByteContainerView serialized_key, HashAlgorithm hash_alg);

  // Creates an RSA encryption key from the given PEM-encoded
  // |serialized_key|. Uses |hash_alg| for OAEP padding.
  static StatusOr<std::unique_ptr<RsaOaepEncryptionKey>> CreateFromPem(
      ByteContainerView serialized_key, HashAlgorithm hash_alg);

  // Creates an RSA encryption key from the given protobuf |key_proto|.
  // Uses |hash_alg| for OAEP padding.
  static StatusOr<std::unique_ptr<RsaOaepEncryptionKey>> CreateFromProto(
      const AsymmetricEncryptionKeyProto &key_proto, HashAlgorithm hash_alg);

  // Creates a new RSA encryption key from the given |public_key|, using
  // |hash_alg| for OAEP hashing. Uses |hash_alg| for OAEP padding.
  static StatusOr<std::unique_ptr<RsaOaepEncryptionKey>> Create(
      bssl::UniquePtr<RSA> public_key, HashAlgorithm hash_alg);

  const RSA *GetRsaPublicKey() const;

  // From AsymmetricEncryptionKey.

  AsymmetricEncryptionScheme GetEncryptionScheme() const override;

  StatusOr<std::string> SerializeToDer() const override;

  Status Encrypt(ByteContainerView plaintext,
                 std::vector<uint8_t> *ciphertext) const override;

 private:
  RsaOaepEncryptionKey(bssl::UniquePtr<RSA> public_key, HashAlgorithm hash_alg);

  // An RSA public key.
  bssl::UniquePtr<RSA> public_key_;

  // The hash algorithm to use with the OAEP algorithm.
  HashAlgorithm hash_alg_;
};

// An implementation of the AsymmetricDecryptionKey interface that uses RSA-OAEP
// for message decryption.
class RsaOaepDecryptionKey : public AsymmetricDecryptionKey {
 public:
  // Creates a random RSA-3072 decryption key. The public exponent is always set
  // to 65537. Uses |hash_alg| for OAEP padding.
  static StatusOr<std::unique_ptr<RsaOaepDecryptionKey>>
  CreateRsa3072OaepDecryptionKey(HashAlgorithm hash_alg);

  // Creates an RSA decryption key from the given DER-encoded
  // |serialized_key|. Uses |hash_alg| for OAEP padding.
  static StatusOr<std::unique_ptr<RsaOaepDecryptionKey>> CreateFromDer(
      ByteContainerView serialized_key, HashAlgorithm hash_alg);

  // From AsymmetricDecryptionKey.

  AsymmetricEncryptionScheme GetEncryptionScheme() const override;

  Status SerializeToDer(
      CleansingVector<uint8_t> *serialized_key) const override;

  StatusOr<std::unique_ptr<AsymmetricEncryptionKey>> GetEncryptionKey()
      const override;

  Status Decrypt(ByteContainerView ciphertext,
                 CleansingVector<uint8_t> *plaintext) const override;

 private:
  RsaOaepDecryptionKey(bssl::UniquePtr<RSA> private_key,
                       HashAlgorithm hash_alg);

  // An RSA private key.
  bssl::UniquePtr<RSA> private_key_;

  // The hash algorithm to use with the OAEP algorithm.
  HashAlgorithm hash_alg_;
};

}  // namespace asylo

#endif  // ASYLO_CRYPTO_RSA_OAEP_ENCRYPTION_KEY_H_
