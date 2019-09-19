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

#ifndef ASYLO_CRYPTO_ASYMMETRIC_ENCRYPTION_KEY_H_
#define ASYLO_CRYPTO_ASYMMETRIC_ENCRYPTION_KEY_H_

#include <cstdint>
#include <string>
#include <vector>

#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/keys.pb.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/util/cleansing_types.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

namespace asylo {

// AsymmetricEncryptionKey abstracts an asymmetric encryption public key.
class AsymmetricEncryptionKey {
 public:
  virtual ~AsymmetricEncryptionKey() = default;

  // Returns the encryption scheme used by this AsymmetricEncryptionKey.
  virtual AsymmetricEncryptionScheme GetEncryptionScheme() const = 0;

  // Serializes this AsymmetricEncryptionKey into a DER-encoded key structure
  // and returns the serialized key.
  virtual StatusOr<std::string> SerializeToDer() const = 0;

  // Encrypts |plaintext| and places the result into |ciphertext|.
  // Returns a non-OK Status if encryption fails.
  virtual Status Encrypt(ByteContainerView plaintext,
                         std::vector<uint8_t> *ciphertext) const = 0;
};

// AsymmetricDecryptionKey abstracts an asymmetric decryption private key.
class AsymmetricDecryptionKey {
 public:
  virtual ~AsymmetricDecryptionKey() = default;

  // Returns the encryption scheme used by this AsymmetricDecryptionKey.
  virtual AsymmetricEncryptionScheme GetEncryptionScheme() const = 0;

  // Serializes this AsymmetricDecryptionKey into a DER-encoded key structure
  // and returns a non-OK Status if serialization fails.
  virtual Status SerializeToDer(
      CleansingVector<uint8_t> *serialized_key) const = 0;

  // Returns the corresponding encryption public key.
  virtual StatusOr<std::unique_ptr<AsymmetricEncryptionKey>> GetEncryptionKey()
      const = 0;

  // Decrypts |plaintext| and places the result into |ciphertext|.
  // Returns a non-OK Status if decryption fails.
  virtual Status Decrypt(ByteContainerView ciphertext,
                         CleansingVector<uint8_t> *plaintext) const = 0;
};

// Converts the AsymmetricEncryptionKey |key| to a protobuf representation of
// the key.
StatusOr<AsymmetricEncryptionKeyProto> ConvertToAsymmetricEncryptionKeyProto(
    const AsymmetricEncryptionKey &key);

// Converts the AsymmetricDecryptionKey |key| to a protobuf representation of
// the encryption key.
StatusOr<AsymmetricEncryptionKeyProto> ConvertToAsymmetricEncryptionKeyProto(
    const AsymmetricDecryptionKey &key);

}  // namespace asylo

#endif  // ASYLO_CRYPTO_ASYMMETRIC_ENCRYPTION_KEY_H_
