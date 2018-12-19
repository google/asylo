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

#ifndef ASYLO_CRYPTO_AEAD_KEY_H_
#define ASYLO_CRYPTO_AEAD_KEY_H_

#include <openssl/aead.h>
#include <cstdint>
#include <memory>
#include <vector>

#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/util/cleansing_types.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

namespace asylo {

// Key used for AEAD (Authenticated Encryption with Associated Data) operations.
class AeadKey {
 public:
  // Creates an instance of AeadKey using |key| with AES-GCM. |key| must be
  // either 16 bytes or 32 bytes in size. Returns a non-OK status if |key| has
  // an invalid size.
  static StatusOr<std::unique_ptr<AeadKey>> CreateAesGcmKey(
      ByteContainerView key);

  // Creates an instance of AeadKey using |key| with AES-GCM-SIV. |key| must be
  // either 16 bytes or 32 bytes in size. Returns a non-OK status if |key| has
  // an invalid size.
  static StatusOr<std::unique_ptr<AeadKey>> CreateAesGcmSivKey(
      ByteContainerView key);

  // Gets the AEAD scheme used by this AeadKey.
  AeadScheme GetAeadScheme() const;

  // Gets the nonce size in bytes expected for the Seal() and Open() operations.
  size_t NonceSize() const;

  // Gets the max size of the spatial overhead for a Seal() operation.
  size_t MaxSealOverhead() const;

  // Implements the AEAD Seal operation. |nonce|.size() must be the same as the
  // value returned by NonceSize(). |ciphertext| is not resized, but its final
  // size is returned through |ciphertext_size|. This method is marked non-const
  // to allow for implementations that internally manage key rotation.
  Status Seal(ByteContainerView plaintext, ByteContainerView associated_data,
              ByteContainerView nonce, absl::Span<uint8_t> ciphertext,
              size_t *ciphertext_size);

  // Implements the AEAD Open operation. |nonce|.size() must be the same as the
  // value returned by NonceSize(). |plaintext| is not resized, but its final
  // size is returned through |plaintext_size|. This method is marked non-const
  // to allow for implementations that internally manage key rotation.
  Status Open(ByteContainerView ciphertext, ByteContainerView associated_data,
              ByteContainerView nonce, absl::Span<uint8_t> plaintext,
              size_t *plaintext_size);

 private:
  AeadKey(AeadScheme scheme, ByteContainerView key);

  // The object that encapsulates the AEAD algorithm.
  const EVP_AEAD *const aead_;

  // The Asylo enum representation of the AEAD algorithm used by this object.
  const AeadScheme aead_scheme_;

  // The AEAD key.
  const CleansingVector<uint8_t> key_;

  // The max size of the spatial overhead for this object's Seal() operation.
  const size_t max_seal_overhead_;

  // The required nonce size for use with key_.
  const size_t nonce_size_;
};

}  // namespace asylo

#endif  // ASYLO_CRYPTO_AEAD_KEY_H_
