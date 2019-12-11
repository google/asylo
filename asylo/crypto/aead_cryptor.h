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
#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/nonce_generator_interface.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/util/statusor.h"

namespace asylo {

/// An AEAD cryptor that provides Seal() and Open() functionality. Currently
/// supported configurations:
/// * AES-GCM-128 and AES-GCM-256 with 96-bit random nonces.
/// * AES-GCM-SIV-128 and AES-GCM-SIV-256 with 96-bit random nonces. (For
///   information on AES-GCM-SIV see https://cyber.biu.ac.il/aes-gcm-siv/)
class AeadCryptor {
 public:
  /// Creates a cryptor that uses AES-GCM for Seal() and Open(), and generates
  /// random 96-bit nonces for use in Seal().
  ///
  /// \param key The underlying key used for encryption and decryption.
  /// \return A pointer to the created cryptor, or a non-OK Status if creation
  ///         failed.
  static StatusOr<std::unique_ptr<AeadCryptor>> CreateAesGcmCryptor(
      ByteContainerView key);

  /// Creates a cryptor that uses AES-GCM-SIV for Seal() and Open(), and
  /// generates random 96-bit nonces for use in Seal().
  ///
  /// \param key The underlying key used for encryption and decryption.
  /// \return A pointer to the created cryptor, or a non-OK Status if creation
  ///         failed.
  static StatusOr<std::unique_ptr<AeadCryptor>> CreateAesGcmSivCryptor(
      ByteContainerView key);

  /// Gets the maximum size of a message that may be sealed successfully with a
  /// cryptor that uses `scheme`.
  ///
  /// \param scheme The associated AeadScheme.
  /// \return The maximum message size that may be sealed successfully, or a
  ///         non-OK Status if `scheme` is unsupported.
  static StatusOr<size_t> MaxMessageSize(AeadScheme scheme);

  /// Gets the maximum number of messages that may be sealed safely with a
  /// cryptor that uses `scheme`.
  ///
  /// \param scheme The associated AeadScheme.
  /// \return The maximum number of messages that may be sealed safely, or a
  ///         non-OK Status if `scheme` is unsupported.
  static StatusOr<uint64_t> MaxSealedMessages(AeadScheme scheme);

  /// Gets the maximum size of a message that may be sealed successfully.
  ///
  /// \return The maximum message size that this cryptor will seal successfully.
  size_t MaxMessageSize() const;

  /// Gets the maximum number of messages that may be sealed successfully.
  ///
  /// \return The maximum number of messages that this cryptor will seal
  ///         successfully.
  uint64_t MaxSealedMessages() const;

  /// Gets the max overhead of Seal().
  ///
  /// \return The maximum space overhead of Seal().
  size_t MaxSealOverhead() const;

  /// Gets the nonce size.
  ///
  /// \return The nonce size.
  size_t NonceSize() const;

  /// Implements the AEAD Seal operation.
  ///
  /// The nonce used is returned through `nonce` and the authenticated
  /// ciphertext is written to `ciphertext`. `plaintext.size()` must be less
  /// than or equal to MaxMessageSize(). `nonce.size()` must be greater than or
  /// equal to the value returned by NonceSize(). `ciphertext.size()` must be
  /// greater than or equal to `plaintext.size()` + MaxSealOverhead().
  /// `ciphertext` is not resized, but its final size is returned through
  /// `ciphertext_size`. Seal() will succeed at most MaxSealedMessages() times.
  ///
  /// \param plaintext The secret that will be sealed.
  /// \param associated_data The authenticated data for the Seal() operation.
  /// \param[out] nonce The generated nonce.
  /// \param[out] ciphertext The sealed ciphertext of `plaintext`.
  /// \param[out] ciphertext_size The size of `ciphertext`.
  /// \return The resulting status of the Seal() operation.
  Status Seal(ByteContainerView plaintext, ByteContainerView associated_data,
              absl::Span<uint8_t> nonce, absl::Span<uint8_t> ciphertext,
              size_t *ciphertext_size);

  /// Implements the AEAD Open operation.
  ///
  /// `nonce.size()` must be greater than or equal to the value returned by
  /// NonceSize(). `plaintext` is not resized, but its final size is returned
  /// through `plaintext_size`. To ascertain that `plaintext` is not smaller
  /// than is necessary for Open(), `plaintext.size()` should be greater than or
  /// equal to `ciphertext.size()`.
  ///
  /// \param ciphertext The sealed ciphertext.
  /// \param associated_data The authenticated data for the Open() operation.
  /// \param nonce The nonce used to seal the ciphertext.
  /// \param[out] plaintext The unsealed ciphertext.
  /// \param[out] plaintext_size The size of the plaintext.
  /// \return The resulting status of the Open() operation.
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

namespace experimental {
/// \deprecated `AeadCryptor` has been moved to the `asylo` top-level namespace.
/// This type alias will be removed in an up-coming release.
using AeadCryptor = ::asylo::AeadCryptor;
}  // namespace experimental

}  // namespace asylo

#endif  // ASYLO_CRYPTO_AEAD_CRYPTOR_H_
