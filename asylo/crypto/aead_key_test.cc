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

#include "asylo/crypto/aead_key.h"

#include <memory>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/strings/escaping.h"
#include "absl/types/span.h"
#include "asylo/crypto/aead_test_vector.h"
#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/util/bytes.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/cleansing_types.h"
#include "asylo/util/status.h"

namespace asylo {
namespace {

using ::testing::TestWithParam;

// Test vector with 256-bit key from example test case 14 on
// http://www.mindspring.com/~dmcgrew/gcm-nist-6.pdf
constexpr char kAesGcmPlaintextHex256[] = "00000000000000000000000000000000";
constexpr char kAesGcmKeyHex256[] =
    "00000000000000000000000000000000"
    "00000000000000000000000000000000";
constexpr char kAesGcmNonceHex256[] = "000000000000000000000000";
constexpr char kAesGcmCiphertextHex256[] = "cea7403d4d606b6e074ec5d3baf39d18";
constexpr char kAesGcmTagHex256[] = "d0d1c8a799996bf0265b98b5d48ab919";

// Test vector with 128-bit key from example test case 4 on
// http://www.mindspring.com/~dmcgrew/gcm-nist-6.pdf
constexpr char kAesGcmPlaintextHex128[] =
    "d9313225f88406e5a55909c5aff5269a"
    "86a7a9531534f7da2e4c303d8a318a72"
    "1c3c0c95956809532fcf0e2449a6b525"
    "b16aedf5aa0de657ba637b39";
constexpr char kAesGcmKeyHex128[] = "feffe9928665731c6d6a8f9467308308";
constexpr char kAesGcmAadHex128[] = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
constexpr char kAesGcmNonceHex128[] = "cafebabefacedbaddecaf888";
constexpr char kAesGcmCiphertextHex128[] =
    "42831ec2217774244b7221b784d0d49c"
    "e3aa212f2c02a4e035c17e2329aca12e"
    "21d514b25466931c7d8f6a5aac84aa05"
    "1ba30b396a0aac973d58e091";
constexpr char kAesGcmTagHex128[] = "5bc94fbc3221a5db94fae95ae7121a47";

// Test vector with a 128-bit key from the AES GCM SIV spec
// (https://tools.ietf.org/html/draft-irtf-cfrg-gcmsiv-05).
const char kAesGcmSivPlaintextHex128[] =
    "01000000000000000000000000000000"
    "02000000000000000000000000000000";
const char kAesGcmSivKeyHex128[] = "01000000000000000000000000000000";
const char kAesGcmSivNonceHex128[] = "030000000000000000000000";
const char kAesGcmSivCiphertextHex128[] =
    "84e07e62ba83a6585417245d7ec413a9"
    "fe427d6315c09b57ce45f2e3936a9445";
const char kAesGcmSivTagHex128[] = "1a8e45dcd4578c667cd86847bf6155ff";

// Test vector with a 256-bit key from the AES GCM SIV spec.
const char kAesGcmSivPlaintextHex256[] = "02000000000000000000000000000000";
const char kAesGcmSivKeyHex256[] =
    "01000000000000000000000000000000"
    "00000000000000000000000000000000";
const char kAesGcmSivAadHex256[] = "01";
const char kAesGcmSivNonceHex256[] = "030000000000000000000000";
const char kAesGcmSivCiphertextHex256[] = "c91545823cc24f17dbb0e9e807d5ec17";
const char kAesGcmSivTagHex256[] = "b292d28ff61189e8e49f3875ef91aff7";

constexpr char kAesGcmBadNonceString[] = "123456";
constexpr char kAesGcmBadKeyString[] = "deadbeef1337";
constexpr size_t kAesGcmNonceSize = 12;

struct AeadKeyParam {
  std::function<StatusOr<std::unique_ptr<AeadKey>>(ByteContainerView)> factory;
  AeadTestVector test_vector;
  AeadTestVector bad_data_vector;

  AeadScheme expected_scheme;
  size_t expected_nonce_size;
};

class AeadKeyTest : public TestWithParam<AeadKeyParam> {
 public:
  void SetUp() override {
    test_vector_ = GetParam().test_vector;
    ASYLO_ASSERT_OK_AND_ASSIGN(test_key_, GetParam().factory(test_vector_.key));
    bad_data_vector_ = GetParam().bad_data_vector;
    ASYLO_ASSERT_OK_AND_ASSIGN(bad_key_,
                               GetParam().factory(bad_data_vector_.key));
  }

  std::unique_ptr<AeadKey> test_key_;
  AeadTestVector test_vector_;

  // A key and a vector that are valid, but a different set of data, and as such
  // incompatible when used with the tested key and vector.
  std::unique_ptr<AeadKey> bad_key_;
  AeadTestVector bad_data_vector_;
};

// Verifies that the AeadScheme returned is correct.
TEST_P(AeadKeyTest, AeadKeyTestAeadScheme) {
  EXPECT_EQ(test_key_->GetAeadScheme(), GetParam().expected_scheme);
}

// Verifies that an AeadKey returns the correct nonce size.
TEST_P(AeadKeyTest, AeadKeyTestNonceSize) {
  EXPECT_EQ(test_key_->NonceSize(), GetParam().expected_nonce_size);
}

// Verifies that the Seal and Open methods conform to vectors from the spec.
TEST_P(AeadKeyTest, AeadKeyTestVector) {
  std::vector<uint8_t> actual_ciphertext(test_vector_.plaintext.size() +
                                         test_key_->MaxSealOverhead());
  size_t actual_ciphertext_size;
  ASYLO_ASSERT_OK(test_key_->Seal(
      test_vector_.plaintext, test_vector_.aad, test_vector_.nonce,
      absl::MakeSpan(actual_ciphertext), &actual_ciphertext_size));
  EXPECT_EQ(test_vector_.authenticated_ciphertext.size(),
            actual_ciphertext_size);
  actual_ciphertext.resize(actual_ciphertext_size);
  EXPECT_EQ(ByteContainerView(test_vector_.authenticated_ciphertext),
            ByteContainerView(actual_ciphertext));

  CleansingVector<uint8_t> actual_plaintext(
      test_vector_.authenticated_ciphertext.size());
  size_t actual_plaintext_size;
  ASYLO_ASSERT_OK(test_key_->Open(test_vector_.authenticated_ciphertext,
                                  test_vector_.aad, test_vector_.nonce,
                                  absl::MakeSpan(actual_plaintext),
                                  &actual_plaintext_size));
  actual_plaintext.resize(actual_plaintext_size);
  EXPECT_EQ(ByteContainerView(test_vector_.plaintext),
            ByteContainerView(actual_plaintext));
}

// Verifies that Seal returns a non-OK Status with invalid inputs.
TEST_P(AeadKeyTest, AeadKeyTestInvalidInputSeal) {
  std::vector<uint8_t> actual_ciphertext(test_vector_.plaintext.size() +
                                         test_key_->MaxSealOverhead());
  size_t actual_ciphertext_size;

  // Verifies that Seal fails with a nonce with an invalid size.
  auto bad_nonce = absl::HexStringToBytes(kAesGcmBadNonceString);
  EXPECT_THAT(test_key_->Seal(test_vector_.plaintext, /*associated_data=*/"",
                              bad_nonce, absl::MakeSpan(actual_ciphertext),
                              &actual_ciphertext_size),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

// Verifies that Open returns a non-OK Status with invalid inputs.
TEST_P(AeadKeyTest, AeadKeyTestInvalidInputOpen) {
  std::vector<uint8_t> actual_plaintext(
      test_vector_.authenticated_ciphertext.size());
  size_t actual_plaintext_size;

  // Verifies that Open fails with a nonce with an invalid size.
  auto bad_nonce = absl::HexStringToBytes(kAesGcmBadNonceString);
  EXPECT_THAT(
      test_key_->Open(test_vector_.authenticated_ciphertext, test_vector_.aad,
                      bad_nonce, absl::MakeSpan(actual_plaintext),
                      &actual_plaintext_size),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

// Verifies that the authenticated encryption uses all relevant data.
// Dependent on the test cases not being valid decryptions of each other and
// also not being a collision.
TEST_P(AeadKeyTest, AeadKeyTestWrongInformation) {
  std::vector<uint8_t> actual_plaintext(
      test_vector_.authenticated_ciphertext.size());
  size_t actual_plaintext_size;

  // Verifies that Open fails with a nonce with the wrong key.
  EXPECT_THAT(
      bad_key_->Open(test_vector_.authenticated_ciphertext, test_vector_.aad,
                     test_vector_.nonce, absl::MakeSpan(actual_plaintext),
                     &actual_plaintext_size),
      StatusIs(absl::StatusCode::kInternal));

  // Verifies that Open fails with the wrong nonce.
  EXPECT_THAT(
      test_key_->Open(test_vector_.authenticated_ciphertext, test_vector_.aad,
                      bad_data_vector_.nonce, absl::MakeSpan(actual_plaintext),
                      &actual_plaintext_size),
      StatusIs(absl::StatusCode::kInternal));

  // Verifies that Open fails when the associated data is incorrect.
  EXPECT_THAT(
      test_key_->Open(test_vector_.authenticated_ciphertext,
                      bad_data_vector_.aad, test_vector_.nonce,
                      absl::MakeSpan(actual_plaintext), &actual_plaintext_size),
      StatusIs(absl::StatusCode::kInternal));

  // Verifies that Open fails when the ciphertext does not include the tag.
  auto unauthenticated_ciphertext_str =
      absl::HexStringToBytes(kAesGcmCiphertextHex128);
  std::vector<uint8_t> unauthenticated_ciphertext(
      unauthenticated_ciphertext_str.cbegin(),
      unauthenticated_ciphertext_str.cend());
  EXPECT_THAT(
      test_key_->Open(test_vector_.unauthenticated_ciphertext, test_vector_.aad,
                      test_vector_.nonce, absl::MakeSpan(actual_plaintext),
                      &actual_plaintext_size),
      StatusIs(absl::StatusCode::kInternal));
}

// Verifies that the factory function fails when given an invalid-sized key.
TEST_P(AeadKeyTest, AeadKeyTestInvalidKey) {
  auto bad_key_result =
      InstantiateSafeBytesFromHexString<sizeof(kAesGcmBadKeyString)>(
          kAesGcmBadKeyString);
  ASYLO_ASSERT_OK(bad_key_result);
  auto bad_key = bad_key_result.value();

  StatusOr<std::unique_ptr<AeadKey>> bad_test_key_result =
      GetParam().factory(bad_key);
  EXPECT_THAT(bad_test_key_result,
              StatusIs(absl::StatusCode::kInvalidArgument));
}

INSTANTIATE_TEST_SUITE_P(
    AllTests, AeadKeyTest,
    ::testing::Values(
        // AES-128-GCM with additional authenticated data.
        AeadKeyParam({AeadKey::CreateAesGcmKey,
                      /*test_vector=*/
                      AeadTestVector(kAesGcmPlaintextHex128, kAesGcmKeyHex128,
                                     kAesGcmAadHex128, kAesGcmNonceHex128,
                                     kAesGcmCiphertextHex128, kAesGcmTagHex128),
                      /*bad_data_vector=*/
                      AeadTestVector(kAesGcmPlaintextHex256, kAesGcmKeyHex256,
                                     /*aad_hex=*/"", kAesGcmNonceHex256,
                                     kAesGcmCiphertextHex256, kAesGcmTagHex256),
                      AeadScheme::AES128_GCM, kAesGcmNonceSize}),
        // AES-256-GCM without additional authenticated data.
        AeadKeyParam({AeadKey::CreateAesGcmKey,
                      /*test_vector=*/
                      AeadTestVector(kAesGcmPlaintextHex256, kAesGcmKeyHex256,
                                     /*aad_hex=*/"", kAesGcmNonceHex256,
                                     kAesGcmCiphertextHex256, kAesGcmTagHex256),
                      /*bad_data_vector=*/
                      AeadTestVector(kAesGcmPlaintextHex128, kAesGcmKeyHex128,
                                     kAesGcmAadHex128, kAesGcmNonceHex128,
                                     kAesGcmCiphertextHex128, kAesGcmTagHex128),
                      AeadScheme::AES256_GCM, kAesGcmNonceSize}),
        // AES-128-GCM-SIV with additional authenticated data.
        AeadKeyParam(
            {AeadKey::CreateAesGcmSivKey,
             /*test_vector=*/
             AeadTestVector(kAesGcmSivPlaintextHex128, kAesGcmSivKeyHex128,
                            /*aad_hex=*/"", kAesGcmSivNonceHex128,
                            kAesGcmSivCiphertextHex128, kAesGcmSivTagHex128),
             /*bad_data_vector=*/
             AeadTestVector(kAesGcmPlaintextHex128, kAesGcmKeyHex128,
                            kAesGcmAadHex128, kAesGcmNonceHex128,
                            kAesGcmCiphertextHex128, kAesGcmTagHex128),
             AeadScheme::AES128_GCM_SIV, kAesGcmNonceSize}),
        // AES-256-GCM-SIV without additional authenticated data.
        AeadKeyParam(
            {AeadKey::CreateAesGcmSivKey,
             /*test_vector=*/
             AeadTestVector(kAesGcmSivPlaintextHex256, kAesGcmSivKeyHex256,
                            kAesGcmSivAadHex256, kAesGcmSivNonceHex256,
                            kAesGcmSivCiphertextHex256, kAesGcmSivTagHex256),
             /*bad_data_vector=*/
             AeadTestVector(kAesGcmPlaintextHex256, kAesGcmKeyHex256,
                            /*aad_hex=*/"", kAesGcmNonceHex256,
                            kAesGcmCiphertextHex256, kAesGcmTagHex256),
             AeadScheme::AES256_GCM_SIV, kAesGcmNonceSize})));

}  // namespace
}  // namespace asylo
