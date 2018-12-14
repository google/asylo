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

// Test suite for the GcmCryptor class.

#include <openssl/rand.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/crypto/util/bytes.h"
#include "asylo/util/logging.h"
#include "asylo/platform/crypto/gcmlib/gcm_cryptor.h"

namespace asylo {
namespace {

using platform::crypto::gcmlib::GcmCryptor;
using platform::crypto::gcmlib::GcmCryptorKey;
using platform::crypto::gcmlib::GcmCryptorRegistry;
using platform::crypto::gcmlib::kKeyLength;
using platform::crypto::gcmlib::kTagLength;
using platform::crypto::gcmlib::kTokenLength;

constexpr size_t kBlockLength = 128;
constexpr size_t kNonceLength = 12;
constexpr size_t kKeyIdLength = 32;
constexpr size_t kKeyIdCycle = 256;

// Tests success case for encryption and decryption.
TEST(GcmCryptorTest, DecryptAfterEncryptReturnsOriginalTexts) {
  uint8_t plaintext[kBlockLength];
  uint8_t encryptor_buffer[kBlockLength + kTagLength];
  uint8_t decryptor_buffer[kBlockLength + kTagLength];
  GcmCryptorKey key;
  ASSERT_EQ(RAND_bytes(key.data(), key.size()), 1);
  auto encryptor = GcmCryptor::Create(kBlockLength, key);
  auto decryptor = GcmCryptor::Create(kBlockLength, key);
  const int kNumMessages = 1000;
  uint8_t token[kTokenLength];
  memset(token, 0, kTokenLength);
  uint8_t old_token[kTokenLength];
  memset(old_token, 0, kTokenLength);
  for (int i = 0; i < kNumMessages; ++i) {
    ASSERT_EQ(RAND_bytes(plaintext, kBlockLength), 1);
    ASSERT_TRUE(encryptor->EncryptBlock(plaintext, token, encryptor_buffer));
    EXPECT_NE(memcmp(old_token, token, kNonceLength), 0);

    if (i % kKeyIdCycle == 0) {
      EXPECT_NE(
          memcmp(old_token + kNonceLength, token + kNonceLength, kKeyIdLength),
          0);
    } else {
      EXPECT_EQ(
          memcmp(old_token + kNonceLength, token + kNonceLength, kKeyIdLength),
          0);
    }

    memcpy(old_token, token, kTokenLength);

    // Verify encryption is not replaced by identity transformation.
    EXPECT_NE(memcmp(plaintext, encryptor_buffer, kBlockLength), 0);

    ASSERT_TRUE(
        decryptor->DecryptBlock(encryptor_buffer, token, decryptor_buffer));

    EXPECT_EQ(memcmp(plaintext, decryptor_buffer, kBlockLength), 0);
  }
}

// Tests encryption and decryption with in-place processing.
TEST(GcmCryptorTest, DecryptAfterEncryptInPlaceReturnsOriginalTexts) {
  uint8_t plaintext[kBlockLength];
  uint8_t encryptor_buffer[kBlockLength + kTagLength];
  uint8_t decryptor_buffer[kBlockLength + kTagLength];
  GcmCryptorKey key;
  ASSERT_EQ(RAND_bytes(key.data(), key.size()), 1);
  auto encryptor = GcmCryptor::Create(kBlockLength, key);
  auto decryptor = GcmCryptor::Create(kBlockLength, key);
  const int kNumMessages = 1000;
  uint8_t token[kTokenLength];
  memset(token, 0, kTokenLength);
  uint8_t old_token[kTokenLength];
  memset(old_token, 0, kTokenLength);
  for (int i = 0; i < kNumMessages; ++i) {
    ASSERT_EQ(RAND_bytes(plaintext, kBlockLength), 1);
    memcpy(encryptor_buffer, plaintext, kBlockLength);

    // Same buffer for in and out - in-place processing.
    ASSERT_TRUE(
        encryptor->EncryptBlock(encryptor_buffer, token, encryptor_buffer));
    EXPECT_NE(memcmp(old_token, token, kNonceLength), 0);

    if (i % kKeyIdCycle == 0) {
      EXPECT_NE(
          memcmp(old_token + kNonceLength, token + kNonceLength, kKeyIdLength),
          0);
    } else {
      EXPECT_EQ(
          memcmp(old_token + kNonceLength, token + kNonceLength, kKeyIdLength),
          0);
    }

    memcpy(old_token, token, kTokenLength);
    memcpy(decryptor_buffer, encryptor_buffer, kBlockLength + kTagLength);

    // Same buffer for in and out - in-place processing.
    ASSERT_TRUE(
        decryptor->DecryptBlock(decryptor_buffer, token, decryptor_buffer));

    EXPECT_EQ(memcmp(plaintext, decryptor_buffer, kBlockLength), 0);
  }
}

// Tests decryption with an altered key.
TEST(GcmCryptorTest, DecryptWithAlteredKeyFails) {
  uint8_t plaintext[kBlockLength];
  uint8_t encryptor_buffer[kBlockLength + kTagLength];
  uint8_t decryptor_buffer[kBlockLength + kTagLength];
  GcmCryptorKey key;
  ASSERT_EQ(RAND_bytes(key.data(), key.size()), 1);
  auto encryptor = GcmCryptor::Create(kBlockLength, key);
  GcmCryptorKey altered_key(key);
  (*altered_key.data())++;
  auto decryptor = GcmCryptor::Create(kBlockLength, altered_key);
  uint8_t token[kTokenLength];
  memset(token, 0, kTokenLength);
  ASSERT_EQ(RAND_bytes(plaintext, kBlockLength), 1);

  ASSERT_TRUE(encryptor->EncryptBlock(plaintext, token, encryptor_buffer));

  ASSERT_FALSE(
      decryptor->DecryptBlock(encryptor_buffer, token, decryptor_buffer));
}

// Tests decryption with an altered nonce.
TEST(GcmCryptorTest, DecryptWithAlteredNonceFails) {
  uint8_t plaintext[kBlockLength];
  uint8_t encryptor_buffer[kBlockLength + kTagLength];
  uint8_t decryptor_buffer[kBlockLength + kTagLength];
  GcmCryptorKey key;
  ASSERT_EQ(RAND_bytes(key.data(), key.size()), 1);
  auto encryptor = GcmCryptor::Create(kBlockLength, key);
  auto decryptor = GcmCryptor::Create(kBlockLength, key);
  uint8_t token[kTokenLength];
  memset(token, 0, kTokenLength);
  ASSERT_EQ(RAND_bytes(plaintext, kBlockLength), 1);

  ASSERT_TRUE(encryptor->EncryptBlock(plaintext, token, encryptor_buffer));

  uint8_t token_altered_nonce[kTokenLength];
  memcpy(token_altered_nonce, token, kTokenLength);
  uint8_t *partial_nonce = reinterpret_cast<uint8_t *>(token);
  uint8_t *partial_altered_nonce =
      reinterpret_cast<uint8_t *>(token_altered_nonce);
  *partial_altered_nonce = *partial_nonce + 1;

  ASSERT_FALSE(decryptor->DecryptBlock(encryptor_buffer, token_altered_nonce,
                                       decryptor_buffer));
}

// Tests decryption with altered ciphertext.
TEST(GcmCryptorTest, DecryptWithAlteredCiphertextFails) {
  uint8_t plaintext[kBlockLength];
  uint8_t encryptor_buffer[kBlockLength + kTagLength];
  uint8_t decryptor_buffer[kBlockLength + kTagLength];
  GcmCryptorKey key;
  ASSERT_EQ(RAND_bytes(key.data(), key.size()), 1);
  auto encryptor = GcmCryptor::Create(kBlockLength, key);
  auto decryptor = GcmCryptor::Create(kBlockLength, key);
  uint8_t token[kTokenLength];
  memset(token, 0, kTokenLength);
  ASSERT_EQ(RAND_bytes(plaintext, kBlockLength), 1);

  ASSERT_TRUE(encryptor->EncryptBlock(plaintext, token, encryptor_buffer));

  // Alter the ciphertext.
  ++encryptor_buffer[0];

  ASSERT_FALSE(
      decryptor->DecryptBlock(encryptor_buffer, token, decryptor_buffer));
}

// Tests GCM cryptor registry returns consistent instance of GCM cryptor.
TEST(GcmCryptorTest, GetGcmCryptorIsConsistent) {
  GcmCryptorKey key;
  ASSERT_EQ(RAND_bytes(key.data(), key.size()), 1);
  GcmCryptor *c1 =
      GcmCryptorRegistry::GetInstance().GetGcmCryptor(kBlockLength, key);
  GcmCryptor *c2 =
      GcmCryptorRegistry::GetInstance().GetGcmCryptor(kBlockLength, key);

  EXPECT_NE(c1, nullptr);

  EXPECT_EQ(c1, c2);
}

}  // namespace
}  // namespace asylo
