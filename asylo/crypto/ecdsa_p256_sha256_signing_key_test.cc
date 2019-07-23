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

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/flags/flag.h"
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "asylo/crypto/fake_signing_key.h"
#include "asylo/crypto/signing_key.h"
#include "asylo/crypto/util/byte_container_util.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/util/logging.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/cleansing_types.h"

ABSL_FLAG(std::string, serialized_signing_key, "",
          "Hex-encoded DER-format SigningKey");

namespace asylo {
namespace {

using ::testing::Not;

const int kBadGroup = NID_secp224r1;
const int kMessageSize = 1000;

constexpr char kTestSigningKeyDer[] =
    "30770201010420fe1dd5d79b11d1ba5f2f7be044d8b7eefc2396f77e903ca91fce637a525f"
    "e830a00a06082a8648ce3d030107a14403420004eaeda5103e89194f43bfe0d844f3e79f00"
    "0957fc3c9237c7ea8ddcd67e22c75cd75119ea9aa02f76cecacbbf1b2fe61c69fc9eeada1f"
    "e29a567d6ceb468e16bd";

// The PEM-encoded equivalent of kTestSigningKeyDer.
constexpr char kTestSigningKeyPem[] =
    R"(-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIP4d1debEdG6Xy974ETYt+78I5b3fpA8qR/OY3pSX+gwoAoGCCqGSM49
AwEHoUQDQgAE6u2lED6JGU9Dv+DYRPPnnwAJV/w8kjfH6o3c1n4ix1zXURnqmqAv
ds7Ky78bL+Ycafye6tof4ppWfWzrRo4WvQ==
-----END EC PRIVATE KEY-----)";

constexpr uint8_t kBadKey[] = "bad key";

constexpr char kTestMessageHex[] = "436f66666565206973206c6966652e0a";

constexpr char kTestSignatureHex[] =
    "304502207f504d6040ded5ddd1bd2b87b5ae2febe09b579f19c094b7fae24d8f47137eda02"
    "2100b45795608442ed963abac8850d93d37e028ce187d53dc2b7577e2d2190b9ea47";

constexpr char kInvalidSignatureHex[] =
    "3046022100b5071aa5a029409df562d8b71a5f48"
    "dc03d4f1864762bc14d1c5d849ac8fd5660221008e0879f733c326f7855e4d681d809c9374"
    "6390a519edb7acdca752afe2eedc51";

constexpr char kTestVerifyingKeyDer[] =
    "3059301306072a8648ce3d020106082a8648ce3d03010703420004eaeda5103e89194f43bf"
    "e0d844f3e79f000957fc3c9237c7ea8ddcd67e22c75cd75119ea9aa02f76cecacbbf1b2fe6"
    "1c69fc9eeada1fe29a567d6ceb468e16bd";

// The PEM-encoded equivalent of kTestVerifyingKeyDer.
constexpr char kTestVerifyingKeyPem[] =
    R"(-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6u2lED6JGU9Dv+DYRPPnnwAJV/w8
kjfH6o3c1n4ix1zXURnqmqAvds7Ky78bL+Ycafye6tof4ppWfWzrRo4WvQ==
-----END PUBLIC KEY-----)";

// A different key from kTestVerifyingKeyPem.
constexpr char kOtherVerifyingKeyPem[] =
    R"(-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAHmUUiRjaRBFLAiNPXkezj/adUZg
PhT+dvyvzddfy359Y7+zKolHkL9vEo/mn32i+FOU0vrEIIMFEAISwQ8i2Q==
-----END PUBLIC KEY-----)";

struct VerifyingKeyParam {
  std::function<StatusOr<std::unique_ptr<VerifyingKey>>(ByteContainerView)>
      factory;
  std::string key_data;
};

// Verify that EcdsaP256Sha256VerifyingKey::Create() fails when the key has an
// incorrect group.
TEST(EcdsaP256Sha256VerifyingKeyCreateTest,
     CreateVerifyingKeyWithBadGroupFails) {
  bssl::UniquePtr<EC_KEY> bad_key(EC_KEY_new_by_curve_name(kBadGroup));
  ASSERT_EQ(EC_KEY_generate_key(bad_key.get()), 1);
  ASSERT_THAT(EcdsaP256Sha256VerifyingKey::Create(std::move(bad_key)),
              Not(IsOk()));
}

class EcdsaP256Sha256VerifyingKeyTest
    : public ::testing::TestWithParam<VerifyingKeyParam> {
 public:
  void SetUp() override {
    ASYLO_ASSERT_OK_AND_ASSIGN(verifying_key_,
                               GetParam().factory(GetParam().key_data));
  }
  std::unique_ptr<VerifyingKey> verifying_key_;
};

// Verify that creating a key from an invalid encoding fails.
TEST_P(EcdsaP256Sha256VerifyingKeyTest,
       CreateVerifyingKeyFromInvalidSerializationFails) {
  std::vector<uint8_t> serialized_key(kBadKey, kBadKey + sizeof(kBadKey));

  EXPECT_THAT(GetParam().factory(serialized_key), Not(IsOk()));
}

// Verify that an EcdsaP256Sha256VerifyingKey produces an equivalent
// DER-encoding through SerializeToDer().
TEST_P(EcdsaP256Sha256VerifyingKeyTest, VerifyingKeySerializeToDer) {
  EXPECT_THAT(verifying_key_->SerializeToDer(),
              IsOkAndHolds(absl::HexStringToBytes(kTestVerifyingKeyDer)));
}

// Verify that an EcdsaP256Sha256VerifyingKey verifies a valid signature.
TEST_P(EcdsaP256Sha256VerifyingKeyTest, VerifySuccess) {
  std::string valid_signature(absl::HexStringToBytes(kTestSignatureHex));
  std::string valid_message(absl::HexStringToBytes(kTestMessageHex));

  ASYLO_EXPECT_OK(verifying_key_->Verify(valid_message, valid_signature));
}

// Verify that an EcdsaP256Sha256VerifyingKey does not verify an invalid
// signature.
TEST_P(EcdsaP256Sha256VerifyingKeyTest, VerifyWithIncorrectSignatureFails) {
  std::string invalid_signature(absl::HexStringToBytes(kInvalidSignatureHex));
  std::string valid_message(absl::HexStringToBytes(kTestMessageHex));

  EXPECT_THAT(verifying_key_->Verify(valid_message, invalid_signature),
              Not(IsOk()));
}

// Verify that operator== fails with a different VerifyingKey implementation.
TEST_P(EcdsaP256Sha256VerifyingKeyTest, EqualsFailsWithDifferentClassKeys) {
  FakeVerifyingKey other_verifying_key(ECDSA_P256_SHA256, kTestVerifyingKeyDer);

  EXPECT_FALSE(*verifying_key_ == other_verifying_key);
}

// Verify that operator!= passes with a different VerifyingKey implementation.
TEST_P(EcdsaP256Sha256VerifyingKeyTest, NotEqualsPassesWithDifferentClassKeys) {
  FakeVerifyingKey other_verifying_key(ECDSA_P256_SHA256, kTestVerifyingKeyDer);

  EXPECT_TRUE(*verifying_key_ != other_verifying_key);
}

// Verify that operator== passes when given a key created with the same data.
TEST_P(EcdsaP256Sha256VerifyingKeyTest, EqualsSucceedsWithEquivalentKeys) {
  std::unique_ptr<VerifyingKey> other_verifying_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(other_verifying_key,
                             GetParam().factory(GetParam().key_data));
  EXPECT_TRUE(*verifying_key_ == *other_verifying_key);
}

// Verify that operator== fails when given a key created with different data.
TEST_P(EcdsaP256Sha256VerifyingKeyTest, EqualsFailsWithDifferentKeys) {
  std::unique_ptr<VerifyingKey> other_verifying_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      other_verifying_key,
      EcdsaP256Sha256VerifyingKey::CreateFromPem(kOtherVerifyingKeyPem));
  EXPECT_FALSE(*verifying_key_ == *other_verifying_key);
}

// Verify that operator!= fails when given a key created with the same data.
TEST_P(EcdsaP256Sha256VerifyingKeyTest, NotEqualsFailsWithEquivalentKeys) {
  std::unique_ptr<VerifyingKey> other_verifying_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(other_verifying_key,
                             GetParam().factory(GetParam().key_data));
  EXPECT_FALSE(*verifying_key_ != *other_verifying_key);
}

// Verify that operator!= passes when given a key created with different data.
TEST_P(EcdsaP256Sha256VerifyingKeyTest, NotEqualsSucceedsWithDifferentKeys) {
  std::unique_ptr<VerifyingKey> other_verifying_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      other_verifying_key,
      EcdsaP256Sha256VerifyingKey::CreateFromPem(kOtherVerifyingKeyPem));
  EXPECT_TRUE(*verifying_key_ != *other_verifying_key);
}

// Verify that GetSignatureScheme() indicates ECDSA P-256 SHA256 for
// EcdsaP256Sha256VerifyingKey.
TEST_P(EcdsaP256Sha256VerifyingKeyTest, SignatureScheme) {
  EXPECT_EQ(verifying_key_->GetSignatureScheme(),
            SignatureScheme::ECDSA_P256_SHA256);
}

INSTANTIATE_TEST_SUITE_P(
    AllTests, EcdsaP256Sha256VerifyingKeyTest,
    ::testing::Values(
        VerifyingKeyParam({EcdsaP256Sha256VerifyingKey::CreateFromDer,
                           absl::HexStringToBytes(kTestVerifyingKeyDer)}),
        VerifyingKeyParam({EcdsaP256Sha256VerifyingKey::CreateFromPem,
                           kTestVerifyingKeyPem})));

class EcdsaP256Sha256SigningKeyTest : public ::testing::Test {
 public:
  void SetUp() override {
    if (!absl::GetFlag(FLAGS_serialized_signing_key).empty()) {
      std::string serialized_signing_key_bin =
          absl::HexStringToBytes(absl::GetFlag(FLAGS_serialized_signing_key));

      auto signing_key_result =
          EcdsaP256Sha256SigningKey::CreateFromDer(serialized_signing_key_bin);
      ASYLO_ASSERT_OK(signing_key_result);
      signing_key_ = std::move(signing_key_result).ValueOrDie();

      LOG(INFO) << "Using provided SigningKey: "
                << absl::GetFlag(FLAGS_serialized_signing_key);
    } else {
      auto signing_key_result = EcdsaP256Sha256SigningKey::Create();
      ASYLO_ASSERT_OK(signing_key_result);
      signing_key_ = std::move(signing_key_result).ValueOrDie();

      CleansingVector<uint8_t> serialized;
      ASYLO_ASSERT_OK(signing_key_->SerializeToDer(&serialized));

      LOG(INFO) << "Using random SigningKey: "
                << absl::BytesToHexString(
                       CopyToByteContainer<std::string>(serialized));
    }
  }

  std::unique_ptr<EcdsaP256Sha256SigningKey> signing_key_;
};


// Verify that EcdsaP256Sha256SigningKey::Create() fails when the key has an
// incorrect group.
TEST_F(EcdsaP256Sha256SigningKeyTest, CreateSigningKeyWithBadGroupFails) {
  bssl::UniquePtr<EC_KEY> bad_key(EC_KEY_new_by_curve_name(kBadGroup));
  ASSERT_TRUE(EC_KEY_generate_key(bad_key.get()));
  ASSERT_THAT(EcdsaP256Sha256SigningKey::Create(std::move(bad_key)),
              Not(IsOk()));
}

// Verify that GetSignatureScheme() indicates ECDSA P-256 SHA256 for
// EcdsaP256Sha256SigningKey.
TEST_F(EcdsaP256Sha256SigningKeyTest, SignatureScheme) {
  EXPECT_EQ(signing_key_->GetSignatureScheme(),
            SignatureScheme::ECDSA_P256_SHA256);
}

// Verify that an EcdsaP256Sha256SigningKey created from a PEM-encoded key
// serializes to the correct DER-encoding.
TEST_F(EcdsaP256Sha256SigningKeyTest, CreateSigningKeyFromPemMatchesDer) {
  std::unique_ptr<SigningKey> signing_key_pem;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      signing_key_pem,
      EcdsaP256Sha256SigningKey::CreateFromPem(kTestSigningKeyPem));

  CleansingVector<uint8_t> serialized_der;
  ASYLO_ASSERT_OK(signing_key_pem->SerializeToDer(&serialized_der));

  EXPECT_EQ(ByteContainerView(serialized_der),
            ByteContainerView(absl::HexStringToBytes(kTestSigningKeyDer)));
}

// Verify that a randomly-generated EcdsaP256Sha256SigningKey can produce a
// signature that the corresponding EcdsaP256Sha256VerifyingKey can verify.
TEST_F(EcdsaP256Sha256SigningKeyTest, SignAndVerify) {
  std::vector<uint8_t> message(kMessageSize);
  ASSERT_TRUE(RAND_bytes(message.data(), kMessageSize));

  std::vector<uint8_t> signature;
  ASYLO_ASSERT_OK(signing_key_->Sign(message, &signature));

  auto verifying_key_result = signing_key_->GetVerifyingKey();
  ASYLO_ASSERT_OK(verifying_key_result);

  std::unique_ptr<VerifyingKey> verifying_key =
      std::move(verifying_key_result).ValueOrDie();
  ASYLO_EXPECT_OK(verifying_key->Verify(message, signature));

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
  ASYLO_ASSERT_OK(signing_key_->SerializeToDer(&serialized_key));

  auto signing_key_result2 =
      EcdsaP256Sha256SigningKey::CreateFromDer(serialized_key);
  ASYLO_ASSERT_OK(signing_key_result2);

  std::unique_ptr<EcdsaP256Sha256SigningKey> signing_key2 =
      std::move(signing_key_result2).ValueOrDie();

  // Try to verify something signed by the original key.
  std::vector<uint8_t> message(kMessageSize);
  ASSERT_TRUE(RAND_bytes(message.data(), kMessageSize));

  std::vector<uint8_t> signature;
  ASYLO_ASSERT_OK(signing_key_->Sign(message, &signature));

  auto verifying_key_result = signing_key2->GetVerifyingKey();
  ASYLO_ASSERT_OK(verifying_key_result);

  std::unique_ptr<VerifyingKey> verifying_key =
      std::move(verifying_key_result).ValueOrDie();

  ASYLO_EXPECT_OK(verifying_key->Verify(message, signature));
}

// Verify that an EcdsaP256Sha256SigningKey created from a serialized key
// produces the same serialization as the one it was constructed from.
TEST_F(EcdsaP256Sha256SigningKeyTest, RestoreFromAndSerializeToDerSigningKey) {
  std::string serialized_key_hex(absl::HexStringToBytes(kTestSigningKeyDer));
  CleansingVector<uint8_t> serialized_key_bin_expected =
      CopyToByteContainer<CleansingVector<uint8_t>>(serialized_key_hex);

  auto signing_key_result2 =
      EcdsaP256Sha256SigningKey::CreateFromDer(serialized_key_bin_expected);
  ASYLO_ASSERT_OK(signing_key_result2);

  std::unique_ptr<EcdsaP256Sha256SigningKey> signing_key2 =
      std::move(signing_key_result2).ValueOrDie();

  CleansingVector<uint8_t> serialized_key_bin_actual;
  signing_key2->SerializeToDer(&serialized_key_bin_actual);

  EXPECT_EQ(serialized_key_bin_expected, serialized_key_bin_actual);
}

// Verify that creating an EcdsaP256Sha256SigningKey from an invalid DER
// serialization fails.
TEST_F(EcdsaP256Sha256SigningKeyTest,
       CreateSigningKeyFromInvalidDerSerializationFails) {
  std::vector<uint8_t> serialized_key(kBadKey, kBadKey + sizeof(kBadKey));

  EXPECT_THAT(EcdsaP256Sha256SigningKey::CreateFromDer(serialized_key),
              Not(IsOk()));
}

// Verify that creating an EcdsaP256Sha256SigningKey from an invalid PEM
// serialization fails.
TEST_F(EcdsaP256Sha256SigningKeyTest,
       CreateSigningKeyFromInvalidPemSerializationFails) {
  std::vector<uint8_t> serialized_key(kBadKey, kBadKey + sizeof(kBadKey));

  EXPECT_THAT(EcdsaP256Sha256SigningKey::CreateFromPem(serialized_key),
              Not(IsOk()));
}

}  // namespace
}  // namespace asylo
