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

#ifndef ASYLO_PLATFORM_CRYPTO_GCMLIB_GCM_CRYPTOR_H_
#define ASYLO_PLATFORM_CRYPTO_GCMLIB_GCM_CRYPTOR_H_

#include <openssl/evp.h>

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "absl/synchronization/mutex.h"
#include "asylo/crypto/util/bytes.h"

namespace asylo {
namespace platform {
namespace crypto {
namespace gcmlib {

// Supported key length.
constexpr size_t kKeyLength = 32;

// Length of integrity tag supplied with the ciphertext.
constexpr size_t kTagLength = 16;

// Length of the token generated at encryption time and used for decryption.
constexpr size_t kTokenLength = 44;

// Length of key ID used in various key derivations.
constexpr size_t kKeyIdLength = 32;

using GcmCryptorKey = SafeBytes<kKeyLength>;

// GcmCryptor implements AES-GCM encryption and decryption.
class GcmCryptor {
 public:
  // Initializes the cryptor with the specified 32 byte key.
  static std::unique_ptr<GcmCryptor> Create(size_t block_length,
                                            const GcmCryptorKey &master_key);
  virtual ~GcmCryptor() = default;

  // Encrypts the input plaintext block with an auto-generated token. No
  // associated data is used. Returns true on success, with the encrypted
  // ciphertext and the generated token supplied. Returns false otherwise.
  bool EncryptBlock(const uint8_t *plaintext_data, uint8_t *token,
                    uint8_t *ciphertext_data);

  // Decrypts the input ciphertext block using the specified token generated at
  // the encryption time. Returns true on success, with the decrypted plaintext
  // supplied. Returns false otherwise.
  bool DecryptBlock(const uint8_t *ciphertext_data, const uint8_t *token,
                    uint8_t *plaintext_data);

  // Generates auth tag, in particular CMAC, for the specified data. Returns
  // true on success, false on failure.
  bool GetAuthTag(uint8_t out[16], const uint8_t *in, size_t in_len) const;

 private:
  static constexpr size_t kNonceLength = 12;
  static constexpr size_t kKeyIdCycle = 256;

  struct Token {
    uint8_t nonce[kNonceLength];
    uint8_t key_id[kKeyIdLength];

    // Returns the address of the Token instance.
    uint8_t *data() { return nonce; }
  };

  GcmCryptor(size_t block_length, const GcmCryptorKey &gcm_key,
             const GcmCryptorKey &cmac_key);
  bool GenerateDerivedGcmKey(const uint8_t *key_id, GcmCryptorKey *dk);

  const size_t kBlockLength;
  const GcmCryptorKey kGcmKey;
  const GcmCryptorKey kCmacKey;
  Token next_token_ ABSL_GUARDED_BY(mu_);
  uint64_t key_id_counter_;
  GcmCryptorKey next_derived_key_ ABSL_GUARDED_BY(mu_);
  absl::Mutex mu_;

  GcmCryptor(const GcmCryptor &) = delete;
  GcmCryptor &operator=(const GcmCryptor &) = delete;
};

// Singleton class represents a registry of keys used by the enclave mapped to
// associated instances of GCM cryptors.
class GcmCryptorRegistry {
 public:
  static GcmCryptorRegistry &GetInstance() {
    static GcmCryptorRegistry *instance = new GcmCryptorRegistry;
    return *instance;
  }

  // Accessor to the instance of GCM cryptor associated with a given key.
  GcmCryptor *GetGcmCryptor(size_t block_length, const GcmCryptorKey &key)
      ABSL_LOCKS_EXCLUDED(mu_);

  class SafeBytesHasher {
   public:
    size_t operator()(const GcmCryptorKey &safe_bytes) const {
      if (safe_bytes.size() == 0) {
        return 0;
      }

      std::hash<unsigned char> uint8_hash;

      size_t result = 0;
      for (const uint8_t &safe_byte : safe_bytes) {
        result ^= uint8_hash(safe_byte);
      }

      return result;
    }
  };

 private:
  GcmCryptorRegistry() = default;
  GcmCryptorRegistry(GcmCryptorRegistry const &) = delete;
  void operator=(GcmCryptorRegistry const &) = delete;

  // This class is expected to be used in context of trusted runtime in the
  // primitives interface where system calls might not be available, so we use
  // std::unordered_map instead of absl::flat_hash_map to prevent unsafe system
  // calls made by absl based containers.
  std::unordered_map<GcmCryptorKey, std::unique_ptr<GcmCryptor>,
                     SafeBytesHasher>
      cryptor_registry_ ABSL_GUARDED_BY(mu_);
  absl::Mutex mu_;
};

}  // namespace gcmlib
}  // namespace crypto
}  // namespace platform
}  // namespace asylo

#endif  // ASYLO_PLATFORM_CRYPTO_GCMLIB_GCM_CRYPTOR_H_
