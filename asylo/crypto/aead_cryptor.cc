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
#include "asylo/crypto/aead_cryptor.h"

#include <cstddef>
#include <memory>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "asylo/crypto/random_nonce_generator.h"
#include "asylo/util/status_macros.h"

namespace asylo {
namespace {

// The following constants determine the maximum number of messages that can be
// sealed with a cryptor and the maximum message size. These constants keep the
// adversary's advantage at or below 2^-32 and keep the probability of
// nonce-collision at or below 2^-48.
constexpr uint64_t kAesGcmMaxSealedMessages = UINT64_C(1) << 27;
constexpr size_t kAesGcmMaxMessageSize = static_cast<size_t>(1) << 25;

constexpr uint64_t kAesGcmSivMaxSealedMessages = UINT64_C(1) << 48;
constexpr size_t kAesGcmSivMaxMessageSize = static_cast<size_t>(1) << 25;

}  // namespace

StatusOr<std::unique_ptr<AeadCryptor>> AeadCryptor::CreateAesGcmCryptor(
    ByteContainerView key) {
  std::unique_ptr<AeadKey> aead_key;
  ASYLO_ASSIGN_OR_RETURN(aead_key, AeadKey::CreateAesGcmKey(key));
  return absl::WrapUnique<AeadCryptor>(new AeadCryptor(
      std::move(aead_key), kAesGcmMaxMessageSize, kAesGcmMaxSealedMessages,
      RandomNonceGenerator::CreateAesGcmNonceGenerator()));
}

StatusOr<std::unique_ptr<AeadCryptor>> AeadCryptor::CreateAesGcmSivCryptor(
    ByteContainerView key) {
  std::unique_ptr<AeadKey> aead_key;
  ASYLO_ASSIGN_OR_RETURN(aead_key, AeadKey::CreateAesGcmSivKey(key));
  return absl::WrapUnique<AeadCryptor>(
      new AeadCryptor(std::move(aead_key), kAesGcmSivMaxMessageSize,
                      kAesGcmSivMaxSealedMessages,
                      RandomNonceGenerator::CreateAesGcmNonceGenerator()));
}

StatusOr<size_t> AeadCryptor::MaxMessageSize(AeadScheme scheme) {
  switch (scheme) {
    case AES128_GCM:
    case AES256_GCM:
      return kAesGcmMaxMessageSize;
    case AES128_GCM_SIV:
    case AES256_GCM_SIV:
      return kAesGcmSivMaxMessageSize;
    default:
      return Status(absl::StatusCode::kUnimplemented,
                    "Given scheme is not supported");
  }
}

StatusOr<uint64_t> AeadCryptor::MaxSealedMessages(AeadScheme scheme) {
  switch (scheme) {
    case AES128_GCM:
    case AES256_GCM:
      return kAesGcmMaxSealedMessages;
    case AES128_GCM_SIV:
    case AES256_GCM_SIV:
      return kAesGcmSivMaxSealedMessages;
    default:
      return Status(absl::StatusCode::kUnimplemented,
                    "Given scheme is not supported");
  }
}

size_t AeadCryptor::MaxMessageSize() const { return max_message_size_; }

uint64_t AeadCryptor::MaxSealedMessages() const { return max_sealed_messages_; }

size_t AeadCryptor::MaxSealOverhead() const { return key_->MaxSealOverhead(); }

size_t AeadCryptor::NonceSize() const { return nonce_generator_->NonceSize(); }

Status AeadCryptor::Seal(ByteContainerView plaintext,
                         ByteContainerView associated_data,
                         absl::Span<uint8_t> nonce,
                         absl::Span<uint8_t> ciphertext,
                         size_t *ciphertext_size) {
  if (plaintext.size() > max_message_size_) {
    return Status(absl::StatusCode::kInvalidArgument,
                  absl::StrCat("Plaintext size ", plaintext.size(),
                               " exceeds maximum message size (",
                               max_message_size_, " bytes)"));
  }
  if (number_of_sealed_messages_ >= max_sealed_messages_) {
    return Status(absl::StatusCode::kFailedPrecondition,
                  absl::StrCat("Reached maximum number of sealed messages (",
                               max_sealed_messages_, ")"));
  }
  nonce_generator_->NextNonce(nonce);
  ASYLO_RETURN_IF_ERROR(key_->Seal(plaintext, associated_data, nonce,
                                   ciphertext, ciphertext_size));
  number_of_sealed_messages_++;
  return absl::OkStatus();
}

Status AeadCryptor::Open(ByteContainerView ciphertext,
                         ByteContainerView associated_data,
                         ByteContainerView nonce, absl::Span<uint8_t> plaintext,
                         size_t *plaintext_size) {
  return key_->Open(ciphertext, associated_data, nonce, plaintext,
                    plaintext_size);
}

AeadCryptor::AeadCryptor(
    std::unique_ptr<AeadKey> key, size_t max_message_size,
    uint64_t max_sealed_messages,
    std::unique_ptr<NonceGeneratorInterface> nonce_generator)
    : key_(std::move(key)),
      max_message_size_(max_message_size),
      max_sealed_messages_(max_sealed_messages),
      nonce_generator_(std::move(nonce_generator)),
      number_of_sealed_messages_(0) {}

}  // namespace asylo
