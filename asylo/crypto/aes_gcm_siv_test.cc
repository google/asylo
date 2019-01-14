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

#include "asylo/crypto/aes_gcm_siv.h"

#include <string>
#include <utility>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/strings/escaping.h"
#include "asylo/crypto/nonce_generator.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/crypto/util/bytes.h"
#include "asylo/crypto/util/trivial_object_util.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status.h"

namespace asylo {
namespace {

// Test vector with a 128-bit key from the AES GCM SIV spec
// (https://tools.ietf.org/html/draft-irtf-cfrg-gcmsiv-05).
const char plaintext1_hex[] =
    "01000000000000000000000000000000"
    "02000000000000000000000000000000";
const char aad1_hex[] = "";
const char key1_hex[] = "01000000000000000000000000000000";
const char nonce1_hex[] = "030000000000000000000000";
const char ciphertext1_hex[] =
    "84e07e62ba83a6585417245d7ec413a9"
    "fe427d6315c09b57ce45f2e3936a9445"
    "1a8e45dcd4578c667cd86847bf6155ff";

// Test vector with a 256-bit key from the AES GCM SIV spec.
const char plaintext2_hex[] = "010000000000000000000000";
const char aad2_hex[] = "";
const char key2_hex[] =
    "01000000000000000000000000000000"
    "00000000000000000000000000000000";
const char nonce2_hex[] = "030000000000000000000000";
const char ciphertext2_hex[] =
    "9aab2aeb3faa0a34aea8e2b18ca50da9"
    "ae6559e48fd10f6e5c9ca17e";
constexpr size_t kMessageSizeLimit = 1 << 16;

class FixedNonceGenerator : public NonceGenerator<kAesGcmSivNonceSize> {
 public:
  using AesGcmSivNonce = UnsafeBytes<kAesGcmSivNonceSize>;
  explicit FixedNonceGenerator(ByteContainerView nonce) : nonce_{nonce} {}

  // Implements NextNonce() from NonceGenerator
  Status NextNonce(const std::vector<uint8_t> &key_id,
                   AesGcmSivNonce *nonce) override {
    *nonce = nonce_;
    return Status::OkStatus();
  }

 private:
  AesGcmSivNonce nonce_;
};

// Verifies that the Seal and Open methods conform to two test vectors from the
// AES GCM SIV spec.
TEST(AesGcmSivTest, AesGcmSivTestVectors) {
  auto plaintext1_result =
      InstantiateSafeBytesFromHexString<sizeof(plaintext1_hex)>(plaintext1_hex);
  ASYLO_ASSERT_OK(plaintext1_result);
  auto plaintext1 = plaintext1_result.ValueOrDie();
  auto aad1 = absl::HexStringToBytes(aad1_hex);
  auto key1_result =
      InstantiateSafeBytesFromHexString<sizeof(key1_hex)>(key1_hex);
  ASYLO_ASSERT_OK(key1_result);
  auto key1 = key1_result.ValueOrDie();
  auto nonce1 = absl::HexStringToBytes(nonce1_hex);
  auto ciphertext1 = absl::HexStringToBytes(ciphertext1_hex);

  AesGcmSivCryptor cryptor1(kMessageSizeLimit, new FixedNonceGenerator(nonce1));

  decltype(nonce1) tmp_nonce1;
  decltype(ciphertext1) tmp_ciphertext1;
  EXPECT_TRUE(
      cryptor1.Seal(key1, aad1, plaintext1, &tmp_nonce1, &tmp_ciphertext1)
          .ok());
  EXPECT_EQ(nonce1, tmp_nonce1);
  EXPECT_EQ(ciphertext1, tmp_ciphertext1);

  decltype(plaintext1) tmp_plaintext1;
  EXPECT_TRUE(
      cryptor1.Open(key1, aad1, ciphertext1, nonce1, &tmp_plaintext1).ok());
  EXPECT_EQ(plaintext1, tmp_plaintext1);

  auto plaintext2_result =
      InstantiateSafeBytesFromHexString<sizeof(plaintext2_hex)>(plaintext2_hex);
  ASYLO_ASSERT_OK(plaintext2_result);
  auto plaintext2 = plaintext2_result.ValueOrDie();
  auto aad2 = absl::HexStringToBytes(aad2_hex);
  auto key2_result =
      InstantiateSafeBytesFromHexString<sizeof(key2_hex)>(key2_hex);
  ASYLO_ASSERT_OK(key2_result);
  auto key2 = key2_result.ValueOrDie();
  auto nonce2 = absl::HexStringToBytes(nonce2_hex);
  auto ciphertext2 = absl::HexStringToBytes(ciphertext2_hex);

  AesGcmSivCryptor cryptor2(kMessageSizeLimit, new FixedNonceGenerator(nonce2));

  decltype(nonce2) tmp_nonce2;
  decltype(ciphertext2) tmp_ciphertext2;
  EXPECT_TRUE(
      cryptor2.Seal(key2, aad2, plaintext2, &tmp_nonce2, &tmp_ciphertext2)
          .ok());
  EXPECT_EQ(nonce2, tmp_nonce2);
  EXPECT_EQ(ciphertext2, tmp_ciphertext2);

  decltype(plaintext2) tmp_plaintext2;
  EXPECT_TRUE(
      cryptor2.Open(key2, aad2, ciphertext2, nonce2, &tmp_plaintext2).ok());
  EXPECT_EQ(plaintext2, tmp_plaintext2);
}

constexpr size_t kPlaintextSize = 23;
constexpr size_t kAdditionalDataSize = 15;

// A typed test fixture is used for tests that require a single type object.
template <typename T>
class TypedAesGcmSivTest : public ::testing::Test {
 public:
};

using UnsafeVector = std::vector<uint8_t>;
using SafeVector = CleansingVector<uint8_t>;
using UnsafeString = std::string;
using SafeString = CleansingString;
typedef ::testing::Types<
    std::pair<UnsafeVector, SafeVector>, std::pair<SafeVector, SafeVector>,
    std::pair<UnsafeString, SafeString>, std::pair<SafeString, SafeString>,
    std::pair<UnsafeString, SafeVector>, std::pair<SafeString, SafeVector>,
    std::pair<UnsafeVector, SafeString>, std::pair<SafeVector, SafeString>>
    MyTypes;
TYPED_TEST_SUITE(TypedAesGcmSivTest, MyTypes);

TYPED_TEST(TypedAesGcmSivTest, KeySize128) {
  using InputType = typename TypeParam::first_type;
  using OutputType = typename TypeParam::second_type;

  AesGcmSivCryptor cryptor(kMessageSizeLimit, new AesGcmSivNonceGenerator());

  InputType key, aad, plaintext;
  OutputType nonce, ciphertext;

  key.resize(16);  // 128-bit key
  aad.resize(kAdditionalDataSize);
  plaintext.resize(kPlaintextSize);

  ASSERT_THAT(cryptor.Seal(key, aad, plaintext, &nonce, &ciphertext), IsOk());

  // In addition to encrypted plaintext, the ciphertext includes a 16-byte
  // tag. Verify that the ciphertext has correct size.
  ASSERT_EQ(ciphertext.size(), plaintext.size() + 16);

  OutputType decrypted;
  ASSERT_THAT(cryptor.Open(key, aad, ciphertext, nonce, &decrypted), IsOk());
  EXPECT_TRUE(
      std::equal(plaintext.cbegin(), plaintext.cend(), decrypted.cbegin()));
}

TYPED_TEST(TypedAesGcmSivTest, KeySize256) {
  using InputType = typename TypeParam::first_type;
  using OutputType = typename TypeParam::second_type;

  AesGcmSivCryptor cryptor(kMessageSizeLimit, new AesGcmSivNonceGenerator());

  InputType key, aad, plaintext;
  OutputType nonce, ciphertext;

  key.resize(32);  // 256-bit key
  aad.resize(kAdditionalDataSize);
  plaintext.resize(kPlaintextSize);

  aad.resize(kAdditionalDataSize);
  plaintext.resize(kPlaintextSize);

  ASSERT_THAT(cryptor.Seal(key, aad, plaintext, &nonce, &ciphertext), IsOk());

  // In addition to encrypted plaintext, the ciphertext includes a 16-byte
  // tag. Verify that the ciphertext has correct size.
  ASSERT_EQ(ciphertext.size(), plaintext.size() + 16);

  OutputType decrypted;
  ASSERT_THAT(cryptor.Open(key, aad, ciphertext, nonce, &decrypted), IsOk());
  EXPECT_TRUE(
      std::equal(plaintext.cbegin(), plaintext.cend(), decrypted.cbegin()));
}

}  // namespace
}  // namespace asylo
