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

#include "asylo/crypto/ecdsa_p256_sha256_signing_key.h"

#include <openssl/base.h>
#include <openssl/ec.h>
#include <openssl/nid.h>
#include <openssl/rand.h>

#include <memory>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "gflags/gflags.h"
#include "asylo/util/logging.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/cleansing_types.h"

namespace asylo {
namespace {

DEFINE_string(serialized_signing_key, "", "Hex-encoded DER-format SigningKey");

using ::testing::Not;

const int kBadGroup = NID_secp224r1;
const int kMessageSize = 1000;

constexpr char kTestKey[] =
    "3077020101042000ac5fbc99687708ff1cbf0a3a7c35beeb3ef8e1071a704e8c3bf4c99f01"
    "9dfba00a06082a8648ce3d030107a14403420004f7504d4ada23fab9878a03d86dc93578e5"
    "593a1e662aafe9e98f085c00dd94ec6c703df0145972eb578a1b5927b62b35379d51a5645a"
    "c339aa24cfb7b89685da";

constexpr uint8_t kBadKey[] = "bad key";

class EcdsaP256Sha256SigningKeyTest : public ::testing::Test {
 public:
  void SetUp() override {
    if (!FLAGS_serialized_signing_key.empty()) {
      std::string serialized_signing_key_bin =
          absl::HexStringToBytes(FLAGS_serialized_signing_key);

      auto signing_key_result =
          EcdsaP256Sha256SigningKey::CreateFromDer(serialized_signing_key_bin);
      ASSERT_THAT(signing_key_result, IsOk());
      signing_key_ = std::move(signing_key_result).ValueOrDie();

      LOG(INFO) << "Using provided SigningKey: "
                << FLAGS_serialized_signing_key;
    } else {
      auto signing_key_result = EcdsaP256Sha256SigningKey::Create();
      ASSERT_THAT(signing_key_result, IsOk());
      signing_key_ = std::move(signing_key_result).ValueOrDie();

      CleansingVector<uint8_t> serialized;
      ASSERT_THAT(signing_key_->SerializeToDer(&serialized), IsOk());

      LOG(INFO) << "Using random SigningKey: "
                << absl::BytesToHexString(absl::string_view(
                       reinterpret_cast<const char *>(serialized.data()),
                       serialized.size()));
    }
  }

  std::unique_ptr<EcdsaP256Sha256SigningKey> signing_key_;
};

// Verify that EcdsaP256Sha256SigningKey::Create() fails when the key has an
// incorrect group.
TEST_F(EcdsaP256Sha256SigningKeyTest, CreateSigningKeyWithBadGroup) {
  bssl::UniquePtr<EC_KEY> bad_key(EC_KEY_new_by_curve_name(kBadGroup));
  ASSERT_TRUE(EC_KEY_generate_key(bad_key.get()));
  ASSERT_THAT(EcdsaP256Sha256SigningKey::Create(std::move(bad_key)),
              Not(IsOk()));
}

// Verify that EcdsaP256Sha256VerifyingKey::Create() fails when the key has an
// incorrect group.
TEST_F(EcdsaP256Sha256SigningKeyTest, CreateVerifyingKeyWithBadGroup) {
  bssl::UniquePtr<EC_KEY> bad_key(EC_KEY_new_by_curve_name(kBadGroup));
  ASSERT_TRUE(EC_KEY_generate_key(bad_key.get()));
  ASSERT_THAT(EcdsaP256Sha256VerifyingKey::Create(std::move(bad_key)),
              Not(IsOk()));
}

// Verify that GetSignatureScheme() indicates ECDSA P-256 SHA256 for both
// EcdsaP256Sha256VerifyingKey and EcdsaP256Sha256SigningKey.
TEST_F(EcdsaP256Sha256SigningKeyTest, HashAlgorithm) {
  EXPECT_EQ(signing_key_->GetSignatureScheme(),
            SignatureScheme::ECDSA_P256_SHA256);

  auto verifying_key_result = signing_key_->GetVerifyingKey();
  ASSERT_THAT(verifying_key_result, IsOk());

  std::unique_ptr<VerifyingKey> verifying_key =
      std::move(verifying_key_result).ValueOrDie();
  EXPECT_EQ(verifying_key->GetSignatureScheme(),
            SignatureScheme::ECDSA_P256_SHA256);
}

// Verify that a randomly-generated EcdsaP256Sha256SigningKey can produce a
// signature that the corresponding EcdsaP256Sha256VerifyingKey can verify.
TEST_F(EcdsaP256Sha256SigningKeyTest, SignAndVerify) {
  std::vector<uint8_t> message(kMessageSize);
  ASSERT_TRUE(RAND_bytes(message.data(), kMessageSize));

  std::vector<uint8_t> signature;
  ASSERT_THAT(signing_key_->Sign(message, &signature), IsOk());

  auto verifying_key_result = signing_key_->GetVerifyingKey();
  ASSERT_THAT(verifying_key_result, IsOk());

  std::unique_ptr<VerifyingKey> verifying_key =
      std::move(verifying_key_result).ValueOrDie();
  EXPECT_THAT(verifying_key->Verify(message, signature), IsOk());

  // Ensure that the signature is not verifiable if one bit is flipped.
  signature.back() ^= 1;
  EXPECT_THAT(verifying_key->Verify(message, signature), Not(IsOk()));
}

// Verify that SerializeToDer() and CreateFromDer() from a serialized key are
// working correctly, and that an EcdsaP256Sha256SigningKey restored from a
// serialized version of another EcdsaP256Sha256SigningKey can verify a
// signature produced by the original key successfully.
TEST_F(EcdsaP256Sha256SigningKeyTest, SerializeToDerAndRestoreSigningKey) {
  CleansingVector<uint8_t> serialized_key;
  ASSERT_THAT(signing_key_->SerializeToDer(&serialized_key), IsOk());

  auto signing_key_result2 =
      EcdsaP256Sha256SigningKey::CreateFromDer(serialized_key);
  ASSERT_THAT(signing_key_result2, IsOk());

  std::unique_ptr<EcdsaP256Sha256SigningKey> signing_key2 =
      std::move(signing_key_result2).ValueOrDie();

  // Try to verify something signed by the original key.
  std::vector<uint8_t> message(kMessageSize);
  ASSERT_TRUE(RAND_bytes(message.data(), kMessageSize));

  std::vector<uint8_t> signature;
  ASSERT_THAT(signing_key_->Sign(message, &signature), IsOk());

  auto verifying_key_result = signing_key2->GetVerifyingKey();
  ASSERT_THAT(verifying_key_result, IsOk());

  std::unique_ptr<VerifyingKey> verifying_key =
      std::move(verifying_key_result).ValueOrDie();

  EXPECT_THAT(verifying_key->Verify(message, signature), IsOk());
}

// Verify that an EcdsaP256Sha256SigningKey created from a serialized key
// produces the same serialization as the one it was constructed from.
TEST_F(EcdsaP256Sha256SigningKeyTest, RestoreFromAndSerializeToDerSigningKey) {
  std::string serialized_key_hex(absl::HexStringToBytes(kTestKey));
  const uint8_t *serialized_key_hex_ptr =
      reinterpret_cast<const uint8_t *>(serialized_key_hex.data());
  CleansingVector<uint8_t> serialized_key_bin_expected(
      serialized_key_hex_ptr,
      serialized_key_hex_ptr + serialized_key_hex.size());

  auto signing_key_result2 =
      EcdsaP256Sha256SigningKey::CreateFromDer(serialized_key_bin_expected);
  ASSERT_THAT(signing_key_result2, IsOk());

  std::unique_ptr<EcdsaP256Sha256SigningKey> signing_key2 =
      std::move(signing_key_result2).ValueOrDie();

  CleansingVector<uint8_t> serialized_key_bin_actual;
  signing_key2->SerializeToDer(&serialized_key_bin_actual);

  EXPECT_EQ(serialized_key_bin_expected, serialized_key_bin_actual);
}

// Verify that creating an EcdsaP256Sha256SigningKey from an invalid DER
// serialization fails.
TEST_F(EcdsaP256Sha256SigningKeyTest, CreateFromInvalidSerializationFails) {
  std::vector<uint8_t> serialized_key(kBadKey, kBadKey + sizeof(kBadKey));

  EXPECT_THAT(EcdsaP256Sha256SigningKey::CreateFromDer(serialized_key),
              Not(IsOk()));
}

}  // namespace
}  // namespace asylo
