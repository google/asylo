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

#include "asylo/grpc/auth/core/ekep_crypto.h"

#include <openssl/curve25519.h>

#include <memory>
#include <string>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/crypto/sha256_hash.h"
#include "asylo/crypto/util/bytes.h"
#include "asylo/crypto/util/trivial_object_util.h"
#include "asylo/grpc/auth/core/ekep_error_matchers.h"
#include "asylo/grpc/auth/core/handshake.pb.h"
#include "asylo/test/util/status_matchers.h"

namespace asylo {
namespace {

using ::testing::Not;

// Test vector for EKEP secret derivation.
//   Inputs:
//     kTestPrivKey, kTestPubKey, kTestTranscriptHash
//   Outputs:
//     kTestPrimarySecret, kTestAuthenticatorSecret
constexpr char kTestPrivKey[] =
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";

constexpr char kTestPubKey[] =
    "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";

constexpr char kTestTranscriptHash[] =
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

constexpr char kTestPrimarySecret[] =
    "537271d5b1876f97d0a943a27cfa05fd4c97b90909f9fa209e94000cf2329f47"
    "7ecca6f668b97b447774556d9eca9d7ef0aefb9667a0bbc3b81b8684aa7b53bf";

constexpr char kTestAuthenticatorSecret[] =
    "24fcb3c5716e4d9fec12571677d5346138b608d846b09a374b84581761d6eae5"
    "b7460dbf84dad1b7a30dcb8ad9190b5a7a519c74a316724a3460c3ca94efd2fc";

// Test vector for record protocol key derivation.
//   Inputs:
//     kTestPrimarySecret, kTestTranscriptHash
//   Outputs:
//     kTestRecordProtocolKey
constexpr char kTestRecordProtocolKey[] = "c7e0f5436c0fe4efdb6327469651b9fe";

// Test vector for server handshake-authenticator computation.
//   Inputs:
//     kTestAuthenticatorSecret
//   Outputs:
//     kTestServerHandshakeAuthenticator
constexpr char kTestServerHandshakeAuthenticator[] =
    "8489bdbd6e173857a289ad0ecfc8c911ea4cbf22983b55eee1ff7e8315992a81";

// Test vector for client handshake-authenticator computation.
//   Inputs:
//     kTestAuthenticatorSecret
//   Outputs:
//     kTestClientHandshakeAuthenticator
constexpr char kTestClientHandshakeAuthenticator[] =
    "d43f4ef069507d34afee16b475c54cdca87d21daa04309f38deb7b01bd092ac9";

// Verify that DeriveSecrets fails and returns BAD_HANDSHAKE_CIPHER when passed
// an unsupported ciphersuite.
TEST(EkepCryptoTest, DeriveSecretsBadCiphersuite) {
  std::string transcript_hash;
  std::vector<uint8_t> peer_dh_public_key;
  CleansingVector<uint8_t> self_dh_private_key;
  CleansingVector<uint8_t> authenticator_secret;
  CleansingVector<uint8_t> primary_secret;

  Status status = DeriveSecrets(UNKNOWN_HANDSHAKE_CIPHER, transcript_hash,
                                peer_dh_public_key, self_dh_private_key,
                                &primary_secret, &authenticator_secret);
  EXPECT_THAT(status, Not(IsOk()));
  EXPECT_THAT(status, EkepErrorIs(Abort::BAD_HANDSHAKE_CIPHER));
}

// Verify that DeriveSecrets fails and returns PROTOCOL_ERROR when passed a
// public parameter that has an invalid size with respect to the ciphersuite.
TEST(EkepCryptoTest, DeriveSecretsBadPublicParameterSize) {
  std::string transcript_hash;

  // Public parameter is empty.
  std::vector<uint8_t> peer_dh_public_key;

  SafeBytes<X25519_PRIVATE_KEY_LEN> self_dh_private_key =
      TrivialRandomObject<SafeBytes<X25519_PRIVATE_KEY_LEN>>();

  CleansingVector<uint8_t> authenticator_secret;
  CleansingVector<uint8_t> primary_secret;

  Status status = DeriveSecrets(CURVE25519_SHA256, transcript_hash,
                                peer_dh_public_key, self_dh_private_key,
                                &primary_secret, &authenticator_secret);
  EXPECT_THAT(status, Not(IsOk()));
  EXPECT_THAT(status, EkepErrorIs(Abort::PROTOCOL_ERROR));
}

// Verify that DeriveSecrets fails and returns INTERNAL_ERROR when passed a
// private parameter that has an invalid size with respect to the ciphersuite.
TEST(EkepCryptoTest, DeriveSecretsBadPrivateParameterSize) {
  std::string transcript_hash;

  // Private parameter is empty.
  CleansingVector<uint8_t> self_dh_private_key;

  SafeBytes<X25519_PUBLIC_VALUE_LEN> peer_dh_public_key =
      TrivialRandomObject<SafeBytes<X25519_PUBLIC_VALUE_LEN>>();

  CleansingVector<uint8_t> authenticator_secret;
  CleansingVector<uint8_t> primary_secret;

  Status status = DeriveSecrets(CURVE25519_SHA256, transcript_hash,
                                peer_dh_public_key, self_dh_private_key,
                                &primary_secret, &authenticator_secret);
  EXPECT_THAT(status, Not(IsOk()));
  EXPECT_THAT(status, EkepErrorIs(Abort::INTERNAL_ERROR));
}

// Verify success of DeriveSecrets using the ciphersuite consisting of
// Curve25519 and SHA256.
TEST(EkepCryptoTest, DeriveSecretsWithCurve25519Sha256) {
  UnsafeBytes<kSha256DigestLength> transcript_hash;
  ASYLO_ASSERT_OK(
      SetTrivialObjectFromHexString(kTestTranscriptHash, &transcript_hash));

  UnsafeBytes<X25519_PUBLIC_VALUE_LEN> peer_dh_public_key;
  ASYLO_ASSERT_OK(
      SetTrivialObjectFromHexString(kTestPubKey, &peer_dh_public_key));

  SafeBytes<X25519_PRIVATE_KEY_LEN> self_dh_private_key;
  ASYLO_ASSERT_OK(
      SetTrivialObjectFromHexString(kTestPrivKey, &self_dh_private_key));

  SafeBytes<kEkepPrimarySecretSize> expected_primary_secret;
  ASYLO_ASSERT_OK(SetTrivialObjectFromHexString(kTestPrimarySecret,
                                                &expected_primary_secret));

  SafeBytes<kEkepAuthenticatorSecretSize> expected_authenticator_secret;
  ASYLO_ASSERT_OK(SetTrivialObjectFromHexString(
      kTestAuthenticatorSecret, &expected_authenticator_secret));

  CleansingVector<uint8_t> authenticator_secret;
  CleansingVector<uint8_t> primary_secret;

  ASSERT_TRUE(DeriveSecrets(CURVE25519_SHA256, transcript_hash,
                            peer_dh_public_key, self_dh_private_key,
                            &primary_secret, &authenticator_secret)
                  .ok());

  // Verify that the primary secret is as expected.
  SafeBytes<kEkepPrimarySecretSize> *actual_primary_secret =
      SafeBytes<kEkepPrimarySecretSize>::Place(&primary_secret,
                                               /*offset=*/0);
  EXPECT_EQ(*actual_primary_secret, expected_primary_secret);

  // Verify that the authenticator secret is as expected.
  SafeBytes<kEkepAuthenticatorSecretSize> *actual_authenticator_secret =
      SafeBytes<kEkepAuthenticatorSecretSize>::Place(&authenticator_secret,
                                                     /*offset=*/0);
  EXPECT_EQ(*actual_authenticator_secret, expected_authenticator_secret);
}

// Verify that DeriveRecordProtocolKey fails and returns BAD_HANDSHAKE_CIPHER
// when passed an unsupported ciphersuite.
TEST(EkepCryptoTest, DeriveRecordProtocolKeyBadCiphersuite) {
  std::string transcript_hash;
  std::vector<uint8_t> primary_secret;
  CleansingVector<uint8_t> key;

  Status status =
      DeriveRecordProtocolKey(UNKNOWN_HANDSHAKE_CIPHER, ALTSRP_AES128_GCM,
                              transcript_hash, primary_secret, &key);
  EXPECT_THAT(status, Not(IsOk()));
  EXPECT_THAT(status, EkepErrorIs(Abort::BAD_HANDSHAKE_CIPHER));
}

// Verify that DeriveRecordProtocolKey fails and returns BAD_RECORD_PROTOCOL
// when passed an unsupported record protocol.
TEST(EkepCryptoTest, DeriveRecordProtocolKeyBadRecordProtocol) {
  std::string transcript_hash;
  std::vector<uint8_t> primary_secret;
  CleansingVector<uint8_t> key;

  Status status =
      DeriveRecordProtocolKey(CURVE25519_SHA256, UNKNOWN_RECORD_PROTOCOL,
                              transcript_hash, primary_secret, &key);
  EXPECT_THAT(status, Not(IsOk()));
  EXPECT_THAT(status, EkepErrorIs(Abort::BAD_RECORD_PROTOCOL));
}

// Verify success of DeriveRecordProtocolKey when using the ciphersuite
// consisting of Curve25519 and SHA256, and the SEAL record protocol.
TEST(EkepCryptoTest, DeriveRecordProtocolKeySealAes128Gcm) {
  UnsafeBytes<kSha256DigestLength> transcript_hash;
  ASYLO_ASSERT_OK(
      SetTrivialObjectFromHexString(kTestTranscriptHash, &transcript_hash));

  SafeBytes<kEkepPrimarySecretSize> primary_secret;
  ASYLO_ASSERT_OK(
      SetTrivialObjectFromHexString(kTestPrimarySecret, &primary_secret));

  SafeBytes<kAltsRecordProtocolAes128GcmKeySize> expected_key;
  ASYLO_ASSERT_OK(
      SetTrivialObjectFromHexString(kTestRecordProtocolKey, &expected_key));

  CleansingVector<uint8_t> key;

  ASSERT_TRUE(DeriveRecordProtocolKey(CURVE25519_SHA256, ALTSRP_AES128_GCM,
                                      transcript_hash, primary_secret, &key)
                  .ok());

  // Verify that the record protocol key is as expected.
  SafeBytes<kAltsRecordProtocolAes128GcmKeySize> *actual_key =
      SafeBytes<kAltsRecordProtocolAes128GcmKeySize>::Place(&key, /*offset=*/0);
  EXPECT_EQ(*actual_key, expected_key);
}

// Verify that ComputeClientHandshakeAuthenticator fails and returns
// BAD_HANDSHAKER_CIPHER when passed an unsupported ciphersuite.
TEST(EkepCryptoTest, ComputeClientHandshakeAuthenticatorBadCipherSuite) {
  SafeBytes<kEkepAuthenticatorSecretSize> authenticator_secret;
  ASYLO_ASSERT_OK(SetTrivialObjectFromHexString(kTestAuthenticatorSecret,
                                                &authenticator_secret));

  CleansingVector<uint8_t> authenticator;

  Status status = ComputeClientHandshakeAuthenticator(
      UNKNOWN_HANDSHAKE_CIPHER, authenticator_secret, &authenticator);
  EXPECT_THAT(status, Not(IsOk()));
  EXPECT_THAT(status, EkepErrorIs(Abort::BAD_HANDSHAKE_CIPHER));
}

// Verify success of ComputeClientHandshakeAuthenticator when using the
// ciphersuite consisting of Curve25519 and SHA256.
TEST(EkepCryptoTest, ComputeClientHandshakeAuthenticatorSha256) {
  SafeBytes<kEkepAuthenticatorSecretSize> authenticator_secret;
  ASYLO_ASSERT_OK(SetTrivialObjectFromHexString(kTestAuthenticatorSecret,
                                                &authenticator_secret));

  SafeBytes<kSha256DigestLength> expected_authenticator;
  ASYLO_ASSERT_OK(SetTrivialObjectFromHexString(
      kTestClientHandshakeAuthenticator, &expected_authenticator));

  CleansingVector<uint8_t> authenticator;

  ASSERT_TRUE(ComputeClientHandshakeAuthenticator(
                  CURVE25519_SHA256, authenticator_secret, &authenticator)
                  .ok());

  // Verify that the client handshake authenticator is as expected.
  SafeBytes<kSha256DigestLength> *actual_authenticator =
      SafeBytes<kSha256DigestLength>::Place(&authenticator,
                                            /*offset=*/0);
  EXPECT_EQ(*actual_authenticator, expected_authenticator);
}

// Verify that ComputeServerHandshakeAuthenticator fails and returns
// BAD_HANDSHAKER_CIPHER when passed an unsupported ciphersuite.
TEST(EkepCryptoTest, ComputeServerHandshakeAuthenticatorBadCipherSuite) {
  SafeBytes<kEkepAuthenticatorSecretSize> authenticator_secret;
  ASYLO_ASSERT_OK(SetTrivialObjectFromHexString(kTestAuthenticatorSecret,
                                                &authenticator_secret));

  CleansingVector<uint8_t> authenticator;

  Status status = ComputeServerHandshakeAuthenticator(
      UNKNOWN_HANDSHAKE_CIPHER, authenticator_secret, &authenticator);
  EXPECT_THAT(status, Not(IsOk()));
  EXPECT_THAT(status, EkepErrorIs(Abort::BAD_HANDSHAKE_CIPHER));
}

// Verify success of ComputeServerHandshakeAuthenticator when using the
// ciphersuite consisting of Curve25519 and SHA256.
TEST(EkepCryptoTest, ComputeServerHandshakeAuthenticatorSha256) {
  SafeBytes<kEkepAuthenticatorSecretSize> authenticator_secret;
  ASYLO_ASSERT_OK(SetTrivialObjectFromHexString(kTestAuthenticatorSecret,
                                                &authenticator_secret));

  SafeBytes<kSha256DigestLength> expected_authenticator;
  ASYLO_ASSERT_OK(SetTrivialObjectFromHexString(
      kTestServerHandshakeAuthenticator, &expected_authenticator));

  CleansingVector<uint8_t> authenticator;

  ASSERT_TRUE(ComputeServerHandshakeAuthenticator(
                  CURVE25519_SHA256, authenticator_secret, &authenticator)
                  .ok());

  // Verify that the server handshake authenticator is as expected.
  SafeBytes<kSha256DigestLength> *actual_authenticator =
      SafeBytes<kSha256DigestLength>::Place(&authenticator,
                                            /*offset=*/0);
  EXPECT_EQ(*actual_authenticator, expected_authenticator);
}

}  // namespace
}  // namespace asylo
