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

#include <vector>

#include <gtest/gtest.h>
#include "absl/types/span.h"
#include "asylo/crypto/aead_test_vector.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/cleansing_types.h"

namespace asylo {
namespace {

// Test vector with 256-bit key from example test case 14 on
// http://www.mindspring.com/~dmcgrew/gcm-nist-6.pdf
constexpr char kPlaintextHex256[] = "00000000000000000000000000000000";
constexpr char kKeyHex256[] =
    "00000000000000000000000000000000"
    "00000000000000000000000000000000";
constexpr char kNonceHex256[] = "000000000000000000000000";
constexpr char kCiphertextHex256[] = "cea7403d4d606b6e074ec5d3baf39d18";
constexpr char kTagHex256[] = "d0d1c8a799996bf0265b98b5d48ab919";

// Test vector with 128-bit key from example test case 4 on
// http://www.mindspring.com/~dmcgrew/gcm-nist-6.pdf
constexpr char kPlaintextHex128[] =
    "d9313225f88406e5a55909c5aff5269a"
    "86a7a9531534f7da2e4c303d8a318a72"
    "1c3c0c95956809532fcf0e2449a6b525"
    "b16aedf5aa0de657ba637b39";
constexpr char kKeyHex128[] = "feffe9928665731c6d6a8f9467308308";
constexpr char kAadHex128[] = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
constexpr char kNonceHex128[] = "cafebabefacedbaddecaf888";
constexpr char kCiphertextHex128[] =
    "42831ec2217774244b7221b784d0d49c"
    "e3aa212f2c02a4e035c17e2329aca12e"
    "21d514b25466931c7d8f6a5aac84aa05"
    "1ba30b396a0aac973d58e091";
constexpr char kTagHex128[] = "5bc94fbc3221a5db94fae95ae7121a47";

using ::testing::TestWithParam;

struct AeadCryptorParam {
  std::function<StatusOr<std::unique_ptr<AeadCryptor>>(ByteContainerView)>
      factory;
  AeadTestVector test_vector;
};

class AeadCryptorTest : public TestWithParam<AeadCryptorParam> {};

TEST_P(AeadCryptorTest, EndToEndTest) {
  AeadTestVector test_vector = GetParam().test_vector;
  std::unique_ptr<AeadCryptor> cryptor;
  ASYLO_ASSERT_OK_AND_ASSIGN(cryptor, GetParam().factory(test_vector.key));

  std::vector<uint8_t> actual_ciphertext(test_vector.plaintext.size() +
                                         cryptor->MaxSealOverhead());
  std::vector<uint8_t> actual_nonce(cryptor->NonceSize());
  size_t actual_ciphertext_size;
  ASYLO_ASSERT_OK(cryptor->Seal(
      test_vector.plaintext, test_vector.aad, absl::MakeSpan(actual_nonce),
      absl::MakeSpan(actual_ciphertext), &actual_ciphertext_size));
  actual_ciphertext.resize(actual_ciphertext_size);

  CleansingVector<uint8_t> actual_plaintext(
      test_vector.authenticated_ciphertext.size());
  size_t actual_plaintext_size;
  ASYLO_ASSERT_OK(cryptor->Open(actual_ciphertext, test_vector.aad,
                                actual_nonce, absl::MakeSpan(actual_plaintext),
                                &actual_plaintext_size));
  actual_plaintext.resize(actual_plaintext_size);
  EXPECT_EQ(ByteContainerView(test_vector.plaintext),
            ByteContainerView(actual_plaintext));
}

TEST_P(AeadCryptorTest, OpenTest) {
  AeadTestVector test_vector = GetParam().test_vector;
  std::unique_ptr<AeadCryptor> cryptor;
  ASYLO_ASSERT_OK_AND_ASSIGN(cryptor, GetParam().factory(test_vector.key));

  CleansingVector<uint8_t> actual_plaintext(
      test_vector.authenticated_ciphertext.size());
  size_t actual_plaintext_size;
  ASYLO_ASSERT_OK(cryptor->Open(
      test_vector.authenticated_ciphertext, test_vector.aad, test_vector.nonce,
      absl::MakeSpan(actual_plaintext), &actual_plaintext_size));
  actual_plaintext.resize(actual_plaintext_size);
  EXPECT_EQ(ByteContainerView(test_vector.plaintext),
            ByteContainerView(actual_plaintext));
}

INSTANTIATE_TEST_CASE_P(
    AllTests, AeadCryptorTest,
    ::testing::Values(
        // AES-128-GCM with additional authenticated data.
        AeadCryptorParam({AeadCryptor::CreateAesGcmCryptor,
                          AeadTestVector(kPlaintextHex128, kKeyHex128,
                                         kAadHex128, kNonceHex128,
                                         kCiphertextHex128, kTagHex128)}),
        // AES-256-GCM without additional authenticated data.
        AeadCryptorParam({AeadCryptor::CreateAesGcmCryptor,
                          AeadTestVector(kPlaintextHex256, kKeyHex256,
                                         /*aad_hex=*/"", kNonceHex256,
                                         kCiphertextHex256, kTagHex256)})));

}  // namespace
}  // namespace asylo
