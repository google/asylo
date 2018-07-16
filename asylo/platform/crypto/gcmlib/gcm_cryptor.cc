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

#include "asylo/platform/crypto/gcmlib/gcm_cryptor.h"

#include <openssl/aes.h>
#include <openssl/cmac.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <openssl/rand.h>
#include <cstdlib>
#include <cstring>
#include <ctime>

#include "absl/memory/memory.h"
#include "absl/synchronization/mutex.h"
#include "asylo/crypto/util/bssl_util.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/crypto/util/bytes.h"
#include "asylo/util/logging.h"

namespace asylo {
namespace platform {
namespace crypto {
namespace gcmlib {

namespace {

// Derivation constants for deriving purpose-based keys. The 2nd byte is used
// to differentiate the constants to avoid conflicts with the 1st byte that
// is significant for the derivation algorithm.
constexpr uint8_t kGcmDerivationConstant[kKeyIdLength] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
constexpr uint8_t kCmacDerivationConstant[kKeyIdLength] = {
    0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

bool GenerateDerivedKey(const GcmCryptorKey &wrapping_key,
                        const uint8_t *key_id, GcmCryptorKey *dk) {
  static_assert(kKeyLength == 2 * AES_BLOCK_SIZE, "kKeyLength is invalid");
  ByteContainerView key_id_view(key_id, kKeyIdLength);
  UnsafeBytes<kKeyIdLength> key_id_clone(key_id_view);
  SafeBytes<kKeyIdLength> derived_key;

  // DK[255:128] = AES_CMAC(MK, 1||KID) - where the KID is 255-bit long. Here
  // we are setting the MSB of the 1st byte of the key_id byte array to 1.
  *key_id_clone.data() |= 1 << 7;
  if (1 != AES_CMAC(derived_key.data(),
                    reinterpret_cast<const uint8_t *>(wrapping_key.data()),
                    kKeyLength, key_id_clone.data(), kKeyIdLength)) {
    LOG(ERROR) << "AES_CMAC failed: " << BsslLastErrorString();
    return false;
  }

  // DK[127:0] = AES_CMAC(MK, 0||KID) - where the KID is 255-bit long. Here
  // we are setting the MSB of the 1st byte of the key_id byte array to 0.
  *key_id_clone.data() &= ~(1 << 7);
  if (1 != AES_CMAC(derived_key.data() + AES_BLOCK_SIZE,
                    reinterpret_cast<const uint8_t *>(wrapping_key.data()),
                    kKeyLength, key_id_clone.data(), kKeyIdLength)) {
    LOG(ERROR) << "AES_CMAC failed: " << BsslLastErrorString();
    return false;
  }

  *dk = GcmCryptorKey(derived_key.data(), kKeyLength);
  return true;
}

}  // namespace

GcmCryptor::GcmCryptor(size_t block_length, const GcmCryptorKey &gcm_key,
                       const GcmCryptorKey &cmac_key)
    : kBlockLength(block_length),
      kGcmKey(gcm_key),
      kCmacKey(cmac_key),
      key_id_counter_(0) {}

std::unique_ptr<GcmCryptor> GcmCryptor::Create(
    size_t block_length, const GcmCryptorKey &master_key) {
  if (block_length == 0) {
    return nullptr;
  }

  static_assert(kTokenLength == kNonceLength + kKeyIdLength,
                "kTokenLength is invalid");
  // Verify there is no padding is added to struct Token to satisfy
  // platform-specific alignment constraints.
  static_assert(kTokenLength == sizeof(struct Token),
                "Token contains unexpected padding.");

  if (EVP_AEAD_nonce_length(EVP_aead_aes_256_gcm()) != kNonceLength) {
    LOG(ERROR)
        << "The initialized AEAD mode operates on an unexpected nonce_length="
        << EVP_AEAD_nonce_length(EVP_aead_aes_256_gcm());
    return nullptr;
  }

  if (EVP_AEAD_max_overhead(EVP_aead_aes_256_gcm()) != kTagLength) {
    LOG(ERROR)
        << "The initialized AEAD mode operates on an unexpected tag_length="
        << EVP_AEAD_max_overhead(EVP_aead_aes_256_gcm());
    return nullptr;
  }

  if (master_key.size() != kKeyLength) {
    LOG(ERROR) << "The GCM cryptor supports 256-bit keys only.";
    return nullptr;
  }

  GcmCryptorKey gcm_key;
  if (!GenerateDerivedKey(master_key, kGcmDerivationConstant, &gcm_key)) {
    LOG(ERROR) << "Failed to derive key for GCM: " << BsslLastErrorString();
    return nullptr;
  }

  GcmCryptorKey cmac_key;
  if (!GenerateDerivedKey(master_key, kCmacDerivationConstant, &cmac_key)) {
    LOG(ERROR) << "Failed to derive key for CMAC: " << BsslLastErrorString();
    return nullptr;
  }

  GcmCryptor *gcm_cryptor = new GcmCryptor(block_length, gcm_key, cmac_key);
  return absl::WrapUnique(gcm_cryptor);
}

bool GcmCryptor::EncryptBlock(const uint8_t *plaintext_data, uint8_t *token,
                              uint8_t *ciphertext_data) {
  if (plaintext_data == nullptr || token == nullptr ||
      ciphertext_data == nullptr) {
    LOG(ERROR) << "Invalid input to GcmCryptor::EncryptBlock.";
    return false;
  }

  absl::MutexLock lock(&mu_);

  if (1 != RAND_bytes(next_token_.nonce, kNonceLength)) {
    LOG(ERROR)
        << "Failed to generate random nonce for GcmCryptor::EncryptBlock: "
        << BsslLastErrorString();
    return false;
  }

  if (key_id_counter_ % kKeyIdCycle == 0) {
    key_id_counter_ = 0;

    if (1 != RAND_bytes(next_token_.key_id, kKeyIdLength)) {
      LOG(ERROR)
          << "Failed to generate random token for GcmCryptor::EncryptBlock: "
          << BsslLastErrorString();
      return false;
    }

    if (!GenerateDerivedGcmKey(next_token_.key_id, &next_derived_key_)) {
      LOG(ERROR) << "Failed to derive key for GcmCryptor::EncryptBlock: "
                 << BsslLastErrorString();
      return false;
    }
  }

  // Increment the key reuse counter only if the key was successfully generated.
  key_id_counter_++;

  EVP_AEAD_CTX context;
  if (!EVP_AEAD_CTX_init(
          &context, EVP_aead_aes_256_gcm(),
          reinterpret_cast<const uint8_t *>(next_derived_key_.data()),
          kKeyLength, kTagLength, nullptr)) {
    LOG(ERROR) << "EVP_AEAD_CTX_init failed: " << BsslLastErrorString();
    EVP_AEAD_CTX_cleanup(&context);
    return false;
  }

  size_t ciphertext_length;
  size_t max_ciphertext_length = kBlockLength + kTagLength;
  if (!EVP_AEAD_CTX_seal(&context, ciphertext_data, &ciphertext_length,
                         max_ciphertext_length, next_token_.nonce, kNonceLength,
                         plaintext_data, kBlockLength, nullptr, 0)) {
    LOG(ERROR) << "EVP_AEAD_CTX_seal failed: " << BsslLastErrorString();
    EVP_AEAD_CTX_cleanup(&context);
    return false;
  }

  if (ciphertext_length != max_ciphertext_length) {
    LOG(ERROR) << "EVP_AEAD_CTX_seal failed to encrypt complete plaintext, "
               << "expected ciphertext_length = " << max_ciphertext_length
               << ", encountered ciphertext_length = " << ciphertext_length;
    EVP_AEAD_CTX_cleanup(&context);
    return false;
  }

  memcpy(token, next_token_.data(), kTokenLength);

  EVP_AEAD_CTX_cleanup(&context);
  return true;
}

bool GcmCryptor::DecryptBlock(const uint8_t *ciphertext_data,
                              const uint8_t *token, uint8_t *plaintext_data) {
  if (ciphertext_data == nullptr || token == nullptr ||
      plaintext_data == nullptr) {
    LOG(ERROR) << "Invalid input to GcmCryptor::DecryptBlock.";
    return false;
  }

  const Token *tok = reinterpret_cast<const Token *>(token);

  GcmCryptorKey derived_key;
  if (!GenerateDerivedGcmKey(tok->key_id, &derived_key)) {
    LOG(ERROR) << "Failed to derive key for GcmCryptor::DecryptBlock: "
               << BsslLastErrorString();
    return false;
  }

  EVP_AEAD_CTX context;
  if (!EVP_AEAD_CTX_init(&context, EVP_aead_aes_256_gcm(),
                         reinterpret_cast<const uint8_t *>(derived_key.data()),
                         kKeyLength, kTagLength, nullptr)) {
    LOG(ERROR) << "EVP_AEAD_CTX_init failed: " << BsslLastErrorString();
    EVP_AEAD_CTX_cleanup(&context);
    return false;
  }

  size_t plaintext_length;
  if (!EVP_AEAD_CTX_open(&context, plaintext_data, &plaintext_length,
                         kBlockLength, tok->nonce, kNonceLength,
                         ciphertext_data, kBlockLength + kTagLength, nullptr,
                         0)) {
    LOG(ERROR) << "EVP_AEAD_CTX_open failed: " << BsslLastErrorString();
    EVP_AEAD_CTX_cleanup(&context);
    return false;
  }

  if (plaintext_length != kBlockLength) {
    LOG(ERROR) << "EVP_AEAD_CTX_open failed to decrypt complete ciphertext, "
               << "expected plaintext_length = " << kBlockLength
               << ", encountered plaintext_length = " << plaintext_length;
    EVP_AEAD_CTX_cleanup(&context);
    return false;
  }

  EVP_AEAD_CTX_cleanup(&context);
  return true;
}

bool GcmCryptor::GenerateDerivedGcmKey(const uint8_t *key_id,
                                       GcmCryptorKey *dk) {
  return GenerateDerivedKey(kGcmKey, key_id, dk);
}

bool GcmCryptor::GetAuthTag(uint8_t out[16], const uint8_t *in,
                            size_t in_len) const {
  if (1 != AES_CMAC(out, reinterpret_cast<const uint8_t *>(kCmacKey.data()),
                    kKeyLength, in, in_len)) {
    LOG(ERROR) << "AES_CMAC failed: " << BsslLastErrorString();
    return false;
  }

  return true;
}

// Note: map entries have lifetime of the program and never get disposed,
// because the internal state of the cryptor is defined on the program lifetime
// timescale - the expectation is that over the lifetime of the program the
// number of utilized keys is substantially limited, and notable accumulation of
// unused keys is unlikely, or limited by the client application. I.e., memory
// utilization in enclave is not guarded at the level of this library.
GcmCryptor *GcmCryptorRegistry::GetGcmCryptor(size_t block_length,
                                              const GcmCryptorKey &key) {
  absl::MutexLock lock(&mu_);

  auto it = cryptor_registry_.find(key);
  if (it != cryptor_registry_.end()) {
    return it->second.get();
  }

  auto result =
      cryptor_registry_.emplace(key, GcmCryptor::Create(block_length, key));
  return result.first->second.get();
}

}  // namespace gcmlib
}  // namespace crypto
}  // namespace platform
}  // namespace asylo
