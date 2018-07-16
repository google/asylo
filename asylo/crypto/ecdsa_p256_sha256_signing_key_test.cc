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

#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/test/util/status_matchers.h"

namespace asylo {
namespace {

using ::testing::Not;

const int kBadGroup = NID_secp224r1;
const int kMessageSize = 1000;

// Verify that EcdsaP256Sha256SigningKey::Create() fails when the key has an
// incorrect group.
TEST(EcdsaP256Sha256SigningKeyTest, CreateSigningKeyWithBadGroup) {
  bssl::UniquePtr<EC_KEY> bad_key(EC_KEY_new_by_curve_name(kBadGroup));
  ASSERT_TRUE(EC_KEY_generate_key(bad_key.get()));
  ASSERT_THAT(EcdsaP256Sha256SigningKey::Create(std::move(bad_key)),
              Not(IsOk()));
}

// Verify that EcdsaP256Sha256VerifyingKey::Create() fails when the key has an
// incorrect group.
TEST(EcdsaP256Sha256SigningKeyTest, CreateVerifyingKeyWithBadGroup) {
  bssl::UniquePtr<EC_KEY> bad_key(EC_KEY_new_by_curve_name(kBadGroup));
  ASSERT_TRUE(EC_KEY_generate_key(bad_key.get()));
  ASSERT_THAT(EcdsaP256Sha256VerifyingKey::Create(std::move(bad_key)),
              Not(IsOk()));
}


// Verify that GetSignatureScheme() indicates ECDSA P-256 SHA256 for both
// EcdsaP256Sha256VerifyingKey and EcdsaP256Sha256SigningKey.
TEST(EcdsaP256Sha256SigningKeyTest, HashAlgorithm) {
  auto signing_key_result = EcdsaP256Sha256SigningKey::Create();
  ASSERT_THAT(signing_key_result, IsOk());

  std::unique_ptr<EcdsaP256Sha256SigningKey> signing_key =
      std::move(signing_key_result).ValueOrDie();
  EXPECT_EQ(signing_key->GetSignatureScheme(),
            SignatureScheme::ECDSA_P256_SHA256);

  auto verifying_key_result = signing_key->GetVerifyingKey();
  ASSERT_THAT(verifying_key_result, IsOk());

  std::unique_ptr<VerifyingKey> verifying_key =
      std::move(verifying_key_result).ValueOrDie();
  EXPECT_EQ(verifying_key->GetSignatureScheme(),
            SignatureScheme::ECDSA_P256_SHA256);
}

// Verify that a randomly-generated EcdsaP256Sha256SigningKey can produce a
// signature that the corresponding EcdsaP256Sha256VerifyingKey can verify.
TEST(EcdsaP256Sha256SigningKeyTest, SignAndVerify) {
  std::vector<uint8_t> message(kMessageSize);
  ASSERT_TRUE(RAND_bytes(message.data(), kMessageSize));

  auto signing_key_result = EcdsaP256Sha256SigningKey::Create();
  ASSERT_THAT(signing_key_result, IsOk());
  std::unique_ptr<EcdsaP256Sha256SigningKey> signing_key =
      std::move(signing_key_result).ValueOrDie();

  std::vector<uint8_t> signature;
  ASSERT_THAT(signing_key->Sign(message, &signature), IsOk());

  auto verifying_key_result = signing_key->GetVerifyingKey();
  ASSERT_THAT(verifying_key_result, IsOk());

  std::unique_ptr<VerifyingKey> verifying_key =
      std::move(verifying_key_result).ValueOrDie();
  EXPECT_THAT(verifying_key->Verify(message, signature), IsOk());

  // Ensure that the signature is not verifiable if one bit is flipped.
  signature.back() ^= 1;
  EXPECT_THAT(verifying_key->Verify(message, signature), Not(IsOk()));
}

}  // namespace
}  // namespace asylo
