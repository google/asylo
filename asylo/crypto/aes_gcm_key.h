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

#ifndef ASYLO_CRYPTO_AES_GCM_KEY_H_
#define ASYLO_CRYPTO_AES_GCM_KEY_H_

#include <cstdint>
#include <memory>
#include <vector>

#include "asylo/crypto/aead_key.h"
#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/util/cleansing_types.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"
#include <openssl/aead.h>

namespace asylo {

// Implementation of AeadKey using AES-GCM.
class AesGcmKey : public AeadKey {
 public:
  // Creates an instance of AesGcmKey using |key|. |key| must be either 16 bytes
  // or 32 bytes in size. Returns a non-OK status if |key| has an invalid size.
  static StatusOr<std::unique_ptr<AesGcmKey>> Create(ByteContainerView key);

  ~AesGcmKey() override = default;

  // From the AeadKey interface.

  AeadScheme GetAeadScheme() const override;

  size_t NonceSize() const override;

  size_t MaxSealOverhead() const override;

  Status Seal(ByteContainerView plaintext, ByteContainerView associated_data,
              ByteContainerView nonce, absl::Span<uint8_t> ciphertext,
              size_t *ciphertext_size) override;

  Status Open(ByteContainerView ciphertext, ByteContainerView associated_data,
              ByteContainerView nonce, absl::Span<uint8_t> plaintext,
              size_t *plaintext_size) override;

 private:
  AesGcmKey(ByteContainerView key);

  // The object that encapsulates the AEAD algorithm.
  const EVP_AEAD *const aead_;

  // The Asylo enum representation of the AEAD algorithm used by this object.
  const AeadScheme aead_scheme_;

  // The AES-GCM key.
  const CleansingVector<uint8_t> key_;

  // The max size of the spatial overhead for this object's Seal() operation.
  const size_t max_seal_overhead_;

  // The required nonce size for use with key_.
  const size_t nonce_size_;
};

}  // namespace asylo

#endif  // ASYLO_CRYPTO_AES_GCM_KEY_H_
