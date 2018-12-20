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

#ifndef ASYLO_CRYPTO_AEAD_CRYPTOR_H_
#define ASYLO_CRYPTO_AEAD_CRYPTOR_H_

#include <cstdint>
#include <memory>

#include "absl/types/span.h"
#include "asylo/crypto/aead_key.h"
#include "asylo/crypto/nonce_generator_interface.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/util/statusor.h"

namespace asylo {

// An AEAD cryptor that provides Seal() and Open() functionality. Currently
// supported configurations:
// * AES-GCM-128 and AES-GCM-256 with 96-bit random nonces.
// * AES-GCM-SIV-128 and AES-GCM-SIV-256 with 96-bit random nonces.
class AeadCryptor {
 public:
  // Creates an AeadCryptor that uses AES-GCM for Seal() and Open(), and
  // generates random 96-bit nonces for use in Seal().
  static StatusOr<std::unique_ptr<AeadCryptor>> CreateAesGcmCryptor(
      ByteContainerView key);

  // Creates an AeadCryptor that uses AES-GCM-SIV for Seal() and Open(), and
  // generates random 96-bit nonces for use in Seal().
  static StatusOr<std::unique_ptr<AeadCryptor>> CreateAesGcmSivCryptor(
      ByteContainerView key);

  // Returns the maximum size of a message that may be sealed successfully.
  size_t MaxMessageSize() const;

  // Returns the maximum number of messages that may be sealed successfully.
  uint64_t MaxSealedMessages() const;

  // Returns the max overhead of Seal().
  size_t MaxSealOverhead() const;

  // Returns the nonce size.
  size_t NonceSize() const;

  // Implements the AEAD Seal operation. The nonce used is returned through
  // |nonce| and the authenticated ciphertext is written to |ciphertext|.
  // |plaintext|.size() must be less than or equal to MaxMessageSize().
  // |nonce|.size() must be greater than or equal to the value returned by
  // NonceSize(). |ciphertext|.size() must be greater than or equal to
  // |plaintext|.size() + MaxSealOverhead(). |ciphertext| is not resized, but
  // its final size is returned through |ciphertext_size|. Seal() will succeed
  // at most MaxSealedMessages() times.
  Status Seal(ByteContainerView plaintext, ByteContainerView associated_data,
              absl::Span<uint8_t> nonce, absl::Span<uint8_t> ciphertext,
              size_t *ciphertext_size);

  // Implements the AEAD Open operation. |nonce|.size() must be greater than or
  // equal to the value returned by NonceSize(). |plaintext| is not resized, but
  // its final size is returned through |plaintext_size|. To ascertain that
  // |plaintext| is not smaller than is necessary for Open(), |plaintext|.size()
  // should be greater than or equal to |ciphertext|.size().
  Status Open(ByteContainerView ciphertext, ByteContainerView associated_data,
              ByteContainerView nonce, absl::Span<uint8_t> plaintext,
              size_t *plaintext_size);

 private:
  AeadCryptor(std::unique_ptr<AeadKey> key, size_t max_message_size,
              uint64_t max_sealed_messages,
              std::unique_ptr<NonceGeneratorInterface> nonce_generator);

  // The AeadKey used for Seal() and Open().
  const std::unique_ptr<AeadKey> key_;

  // The maximum size of a message passed in for Seal().
  const size_t max_message_size_;

  // The maximum number of messages that may be sealed successfully.
  const uint64_t max_sealed_messages_;

  // The nonce generator used to generate nonces for Seal().
  const std::unique_ptr<NonceGeneratorInterface> nonce_generator_;

  // The number messages that have been sealed successfully.
  size_t number_of_sealed_messages_;
};

}  // namespace asylo

#endif  // ASYLO_CRYPTO_AEAD_CRYPTOR_H_
