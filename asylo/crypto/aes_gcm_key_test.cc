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

#include "asylo/crypto/aes_gcm_key.h"

#include <memory>
#include <string>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/types/span.h"
#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/util/bytes.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/cleansing_types.h"
#include "asylo/util/error_codes.h"

namespace asylo {
namespace {

using ::testing::Test;

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

constexpr char kBadNonceString[] = "123456";
constexpr char kBadKeyString[] = "deadbeef1337";
constexpr size_t kAesGcmNonceSize = 12;

class AesGcmKeyTest : public Test {
 public:
  void SetUp() override {
    // Sets up the fields for the first test vector.
    auto plaintext256_result =
        InstantiateSafeBytesFromHexString<sizeof(kPlaintextHex256)>(
            kPlaintextHex256);
    ASYLO_ASSERT_OK(plaintext256_result);
    plaintext256_ = plaintext256_result.ValueOrDie();
    auto key256_result =
        InstantiateSafeBytesFromHexString<sizeof(kKeyHex256)>(kKeyHex256);
    ASYLO_ASSERT_OK(key256_result);
    auto key256 = key256_result.ValueOrDie();
    nonce256_ = absl::HexStringToBytes(kNonceHex256);
    authenticated_ciphertext256_ =
        absl::HexStringToBytes(absl::StrCat(kCiphertextHex256, kTagHex256));
    StatusOr<std::unique_ptr<AesGcmKey>> aes_gcm_key256_result =
        AesGcmKey::Create(key256);
    ASSERT_THAT(aes_gcm_key256_result.status(), IsOk());
    aes_gcm_key256_ = std::move(aes_gcm_key256_result).ValueOrDie();

    // Sets up the fields for the second test vector.
    auto plaintext128_result =
        InstantiateSafeBytesFromHexString<sizeof(kPlaintextHex128)>(
            kPlaintextHex128);
    ASYLO_ASSERT_OK(plaintext128_result);
    plaintext128_ = plaintext128_result.ValueOrDie();
    aad128_ = absl::HexStringToBytes(kAadHex128);
    auto key128_result =
        InstantiateSafeBytesFromHexString<sizeof(kKeyHex128)>(kKeyHex128);
    ASYLO_ASSERT_OK(key128_result);
    auto key128 = key128_result.ValueOrDie();
    nonce128_ = absl::HexStringToBytes(kNonceHex128);
    authenticated_ciphertext128_ =
        absl::HexStringToBytes(absl::StrCat(kCiphertextHex128, kTagHex128));
    StatusOr<std::unique_ptr<AesGcmKey>> aes_gcm_key128_result =
        AesGcmKey::Create(key128);
    ASSERT_THAT(aes_gcm_key128_result.status(), IsOk());
    aes_gcm_key128_ = std::move(aes_gcm_key128_result).ValueOrDie();
  }

  SafeBytes<(sizeof(kPlaintextHex256) - 1) / 2> plaintext256_;
  std::string nonce256_;
  std::string authenticated_ciphertext256_;
  std::unique_ptr<AesGcmKey> aes_gcm_key256_;

  SafeBytes<(sizeof(kPlaintextHex128) - 1) / 2> plaintext128_;
  std::string aad128_;
  std::string nonce128_;
  std::string authenticated_ciphertext128_;
  std::unique_ptr<AesGcmKey> aes_gcm_key128_;
};

// Verifies that the AeadSchemes returned are correct.
TEST_F(AesGcmKeyTest, AesGcmKeyTestAeadScheme) {
  // Verifies the first AesGcmKey, which has a key size of 256.
  EXPECT_EQ(aes_gcm_key256_->GetAeadScheme(), AeadScheme::AES256_GCM);

  // Verifies the second AesGcmKey, which has a key size of 128.
  EXPECT_EQ(aes_gcm_key128_->GetAeadScheme(), AeadScheme::AES128_GCM);
}

// Verifies that an AesGcmKey returns the correct nonce size.
TEST_F(AesGcmKeyTest, AesGcmKeyTestNonceSize) {
  EXPECT_EQ(aes_gcm_key256_->NonceSize(), kAesGcmNonceSize);
}

// Verifies that the Seal and Open methods conform to vectors from the AES-GCM
// spec which do not include associated data.
TEST_F(AesGcmKeyTest, AesGcmKeyTestVectorsWithoutAssociatedData) {
  std::vector<uint8_t> actual_ciphertext(plaintext256_.size() +
                                         aes_gcm_key256_->MaxSealOverhead());
  size_t actual_ciphertext_size;
  ASYLO_ASSERT_OK(aes_gcm_key256_->Seal(
      plaintext256_, /*associated_data=*/"", nonce256_,
      absl::MakeSpan(actual_ciphertext), &actual_ciphertext_size));
  EXPECT_EQ(authenticated_ciphertext256_.size(), actual_ciphertext_size);
  actual_ciphertext.resize(actual_ciphertext_size);
  EXPECT_EQ(ByteContainerView(authenticated_ciphertext256_),
            ByteContainerView(actual_ciphertext));

  CleansingVector<uint8_t> actual_plaintext(
      authenticated_ciphertext256_.size());
  size_t actual_plaintext_size;
  ASYLO_ASSERT_OK(aes_gcm_key256_->Open(authenticated_ciphertext256_,
                                        /*associated_data=*/"", nonce256_,
                                        absl::MakeSpan(actual_plaintext),
                                        &actual_plaintext_size));
  actual_plaintext.resize(actual_plaintext_size);
  EXPECT_EQ(ByteContainerView(plaintext256_),
            ByteContainerView(actual_plaintext));
}

// Verifies that the Seal and Open methods conform to vectors from the AES-GCM
// spec which include associated data.
TEST_F(AesGcmKeyTest, AesGcmKeyTestVectorsWithAssociatedData) {
  std::vector<uint8_t> actual_ciphertext(plaintext128_.size() +
                                         aes_gcm_key128_->MaxSealOverhead());
  size_t actual_ciphertext_size;
  ASYLO_ASSERT_OK(aes_gcm_key128_->Seal(plaintext128_, aad128_, nonce128_,
                                        absl::MakeSpan(actual_ciphertext),
                                        &actual_ciphertext_size));
  EXPECT_EQ(authenticated_ciphertext128_.size(), actual_ciphertext_size);
  actual_ciphertext.resize(actual_ciphertext_size);
  EXPECT_EQ(ByteContainerView(authenticated_ciphertext128_),
            ByteContainerView(actual_ciphertext));

  std::vector<uint8_t> actual_plaintext(authenticated_ciphertext128_.size());
  size_t actual_plaintext_size;
  ASYLO_ASSERT_OK(aes_gcm_key128_->Open(
      authenticated_ciphertext128_, aad128_, nonce128_,
      absl::MakeSpan(actual_plaintext), &actual_plaintext_size));
  actual_plaintext.resize(actual_plaintext_size);
  EXPECT_EQ(ByteContainerView(plaintext128_),
            ByteContainerView(actual_plaintext));
}

// Verifies that an AesGcmKey cannot be created with a key with an invalid size.
TEST_F(AesGcmKeyTest, AesGcmKeyTestInvalidKey) {
  auto bad_key_result =
      InstantiateSafeBytesFromHexString<sizeof(kBadKeyString)>(kBadKeyString);
  ASYLO_ASSERT_OK(bad_key_result);
  auto bad_key = bad_key_result.ValueOrDie();
  StatusOr<std::unique_ptr<AesGcmKey>> bad_aes_gcm_key_result =
      AesGcmKey::Create(bad_key);
  EXPECT_THAT(bad_aes_gcm_key_result.status(),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

// Verifies that Seal returns a non-OK Status with invalid inputs.
TEST_F(AesGcmKeyTest, AesGcmKeyTestInvalidInputSeal) {
  std::vector<uint8_t> actual_ciphertext(plaintext256_.size() +
                                         aes_gcm_key256_->MaxSealOverhead());
  size_t actual_ciphertext_size;

  // Verifies that Seal fails with a nonce with an invalid size.
  auto bad_nonce = absl::HexStringToBytes(kBadNonceString);
  EXPECT_THAT(aes_gcm_key256_->Seal(
                  plaintext256_, /*associated_data=*/"", bad_nonce,
                  absl::MakeSpan(actual_ciphertext), &actual_ciphertext_size),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

// Verifies that Open returns a non-OK Status with invalid inputs.
TEST_F(AesGcmKeyTest, AesGcmKeyTestInvalidInputOpen) {
  std::vector<uint8_t> actual_plaintext(authenticated_ciphertext256_.size());
  size_t actual_plaintext_size;

  // Verifies that Open fails with a nonce with an invalid size.
  auto bad_nonce = absl::HexStringToBytes(kBadNonceString);
  EXPECT_THAT(aes_gcm_key128_->Open(authenticated_ciphertext128_, aad128_,
                                    bad_nonce, absl::MakeSpan(actual_plaintext),
                                    &actual_plaintext_size),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

// Verifies that the authenticated encryption uses all relevant data.
// Dependent on the test cases not being valid decryptions of each other and
// also not being a collision.
TEST_F(AesGcmKeyTest, AesGcmKeyTestWrongInformation) {
  std::vector<uint8_t> actual_plaintext(authenticated_ciphertext256_.size());
  size_t actual_plaintext_size;

  // Verifies that Open fails with a nonce with the wrong key.
  EXPECT_THAT(aes_gcm_key256_->Open(authenticated_ciphertext128_, aad128_,
                                    nonce128_, absl::MakeSpan(actual_plaintext),
                                    &actual_plaintext_size),
              StatusIs(error::GoogleError::INTERNAL));

  // Verifies that Open fails with the wrong nonce.
  EXPECT_THAT(aes_gcm_key128_->Open(authenticated_ciphertext128_, aad128_,
                                    nonce256_, absl::MakeSpan(actual_plaintext),
                                    &actual_plaintext_size),
              StatusIs(error::GoogleError::INTERNAL));

  // Verifies that Open fails when the associated data is not passed in.
  EXPECT_THAT(aes_gcm_key128_->Open(authenticated_ciphertext128_,
                                    /*associated_data=*/"", nonce128_,
                                    absl::MakeSpan(actual_plaintext),
                                    &actual_plaintext_size),
              StatusIs(error::GoogleError::INTERNAL));

  // Verifies that Open fails when includes associated data not part of the
  // original.
  EXPECT_THAT(aes_gcm_key256_->Open(authenticated_ciphertext256_, aad128_,
                                    nonce256_, absl::MakeSpan(actual_plaintext),
                                    &actual_plaintext_size),
              StatusIs(error::GoogleError::INTERNAL));

  // Verifies that Open fails when the ciphertext does not include the tag.
  auto unauthenticated_ciphertext128_str =
      absl::HexStringToBytes(kCiphertextHex128);
  std::vector<uint8_t> unauthenticated_ciphertext2(
      unauthenticated_ciphertext128_str.cbegin(),
      unauthenticated_ciphertext128_str.cend());
  EXPECT_THAT(aes_gcm_key128_->Open(unauthenticated_ciphertext2, aad128_,
                                    nonce128_, absl::MakeSpan(actual_plaintext),
                                    &actual_plaintext_size),
              StatusIs(error::GoogleError::INTERNAL));
}

}  // namespace
}  // namespace asylo
