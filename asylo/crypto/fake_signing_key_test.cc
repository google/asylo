/*
 *
 * Copyright 2019 Asylo authors
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

#include "asylo/crypto/fake_signing_key.h"

#include <cstdint>
#include <memory>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/status/status.h"
#include "asylo/crypto/signing_key.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/cleansing_types.h"
#include "asylo/util/status.h"

namespace asylo {
namespace {

constexpr char kTestKeyDer[] = "Coffee";

constexpr char kOtherKeyDer[] = "#1";

constexpr char kTestMessage[] = "Fun";

constexpr char kTestMessageSignature[] = "CoffeeFun";

constexpr char kOtherMessageSignature[] = "Coffee#1";

constexpr char kOtherKeySignature[] = "Not coffeeFun";

// Verify that a FakeVerifyingKey produces an equivalent DER-encoding through
// SerializeToDer().
TEST(FakeSigningKeyTest, VerifyingKeySerializeToDer) {
  FakeVerifyingKey verifying_key(UNKNOWN_SIGNATURE_SCHEME, kTestKeyDer);
  EXPECT_THAT(verifying_key.SerializeToDer(), IsOkAndHolds(kTestKeyDer));
}

// Verify that a FakeVerifyingKey with a status passed at construction for the
// DER-encoded key value returns that status for SerializeToDer().
TEST(FakeSigningKeyTest, VerifyingKeyFailsSerializeToDer) {
  FakeVerifyingKey verifying_key(
      UNKNOWN_SIGNATURE_SCHEME,
      Status(absl::StatusCode::kFailedPrecondition, kTestMessage));

  EXPECT_THAT(verifying_key.SerializeToDer().status(),
              StatusIs(absl::StatusCode::kFailedPrecondition, kTestMessage));
}

TEST(FakeSigningKeyTest, VerifyingKeySerializeToKeyProtoSuccess) {
  FakeVerifyingKey verifying_key(UNKNOWN_SIGNATURE_SCHEME, kTestKeyDer);
  AsymmetricSigningKeyProto key_proto;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      key_proto, verifying_key.SerializeToKeyProto(ASYMMETRIC_KEY_DER));
  EXPECT_EQ(key_proto.key_type(), AsymmetricSigningKeyProto::VERIFYING_KEY);
  EXPECT_EQ(key_proto.signature_scheme(), UNKNOWN_SIGNATURE_SCHEME);
  EXPECT_EQ(key_proto.encoding(), ASYMMETRIC_KEY_DER);
  EXPECT_EQ(key_proto.key(), kTestKeyDer);
}

TEST(FakeSigningKeyTest, VerifyingKeySerializeToKeyProtoPemFailure) {
  FakeVerifyingKey verifying_key(UNKNOWN_SIGNATURE_SCHEME, kTestKeyDer);
  AsymmetricSigningKeyProto key_proto;
  EXPECT_THAT(verifying_key.SerializeToKeyProto(ASYMMETRIC_KEY_PEM),
              StatusIs(absl::StatusCode::kUnimplemented));
}

TEST(FakeSigningKeyTest, VerifyingKeySerializeToKeyProtoUnknownFailure) {
  FakeVerifyingKey verifying_key(UNKNOWN_SIGNATURE_SCHEME, kTestKeyDer);
  AsymmetricSigningKeyProto key_proto;
  EXPECT_THAT(
      verifying_key.SerializeToKeyProto(UNKNOWN_ASYMMETRIC_KEY_ENCODING),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

// Verify that a FakeVerifyingKey with a status passed at construction for the
// DER-encoded key value returns that status for Verify().
TEST(FakeSigningKeyTest, VerifyingKeyConstructedWithStatusVerify) {
  FakeVerifyingKey verifying_key(
      UNKNOWN_SIGNATURE_SCHEME,
      Status(absl::StatusCode::kFailedPrecondition, kTestMessage));

  EXPECT_THAT(verifying_key.Verify(kTestMessage, kTestMessageSignature),
              StatusIs(absl::StatusCode::kFailedPrecondition, kTestMessage));
}

// Verify that a FakeVerifyingKey verifies a valid signature.
TEST(FakeSigningKeyTest, VerifySuccess) {
  FakeVerifyingKey verifying_key(UNKNOWN_SIGNATURE_SCHEME, kTestKeyDer);

  ASYLO_EXPECT_OK(verifying_key.Verify(kTestMessage, kTestMessageSignature));
}

// Verify that a FakeVerifyingKey does not verify a signature signed by a
// different key.
TEST(FakeSigningKeyTest, VerifyWithOtherKeySignatureFails) {
  FakeVerifyingKey verifying_key(UNKNOWN_SIGNATURE_SCHEME, kTestKeyDer);

  EXPECT_THAT(verifying_key.Verify(kTestMessage, kOtherKeySignature),
              StatusIs(absl::StatusCode::kUnauthenticated));
}

// Verify that a FakeVerifyingKey does not verify a signature for a different
// message.
TEST(FakeSigningKeyTest, VerifyOtherMessageSignatureFails) {
  FakeVerifyingKey verifying_key(UNKNOWN_SIGNATURE_SCHEME, kTestKeyDer);

  EXPECT_THAT(verifying_key.Verify(kTestMessage, kOtherMessageSignature),
              StatusIs(absl::StatusCode::kUnauthenticated));
}

// Verify that operator== passes when given keys with the same non-OK Status
// and scheme.
TEST(FakeSigningKeyTest, EqualsSucceedsWithEquivalentNonOkKeys) {
  FakeVerifyingKey verifying_key(
      UNKNOWN_SIGNATURE_SCHEME,
      Status(absl::StatusCode::kFailedPrecondition, kTestMessage));
  FakeVerifyingKey other_key(
      UNKNOWN_SIGNATURE_SCHEME,
      Status(absl::StatusCode::kFailedPrecondition, kTestMessage));

  EXPECT_TRUE(verifying_key == other_key);
}

// Verify that operator== fails when given keys with the same non-OK Status and
// different schemes.
TEST(FakeSigningKeyTest, EqualsFailsWithEquivalentNonOkKeysDifferentSchemes) {
  FakeVerifyingKey verifying_key(
      UNKNOWN_SIGNATURE_SCHEME,
      Status(absl::StatusCode::kFailedPrecondition, kTestMessage));
  FakeVerifyingKey other_key(
      ECDSA_P256_SHA256,
      Status(absl::StatusCode::kFailedPrecondition, kTestMessage));

  EXPECT_FALSE(verifying_key == other_key);
}

// Verify that operator== passes when given a key created with the same data.
TEST(FakeSigningKeyTest, EqualsSucceedsWithEquivalentKeys) {
  FakeVerifyingKey verifying_key(UNKNOWN_SIGNATURE_SCHEME, kTestKeyDer);
  FakeVerifyingKey other_key(UNKNOWN_SIGNATURE_SCHEME, kTestKeyDer);

  EXPECT_TRUE(verifying_key == other_key);
}

// Verify that operator== fails when given a key created with a different key
// id.
TEST(FakeSigningKeyTest, EqualsFailsWithDifferentKeys) {
  FakeVerifyingKey verifying_key(UNKNOWN_SIGNATURE_SCHEME, kTestKeyDer);
  FakeVerifyingKey other_key(UNKNOWN_SIGNATURE_SCHEME, kOtherKeyDer);

  EXPECT_FALSE(verifying_key == other_key);
}

// Verify that operator== fails when given a key created with a different
// scheme.
TEST(FakeSigningKeyTest, EqualsFailsWithDifferentSchemes) {
  FakeVerifyingKey verifying_key(UNKNOWN_SIGNATURE_SCHEME, kTestKeyDer);
  FakeVerifyingKey other_key(ECDSA_P256_SHA256, kTestKeyDer);

  EXPECT_FALSE(verifying_key == other_key);
}

// Verify that operator!= fails when given a key created with the same data.
TEST(FakeSigningKeyTest, NotEqualsFailsWithEquivalentKeys) {
  FakeVerifyingKey verifying_key(UNKNOWN_SIGNATURE_SCHEME, kTestKeyDer);
  FakeVerifyingKey other_key(UNKNOWN_SIGNATURE_SCHEME, kTestKeyDer);

  EXPECT_FALSE(verifying_key != other_key);
}

// Verify that operator!= passes when given a key created with different data.
TEST(FakeSigningKeyTest, NotEqualsSucceedsWithDifferentKeys) {
  FakeVerifyingKey verifying_key(UNKNOWN_SIGNATURE_SCHEME, kTestKeyDer);
  FakeVerifyingKey other_key(UNKNOWN_SIGNATURE_SCHEME, kOtherKeyDer);

  EXPECT_TRUE(verifying_key != other_key);
}

// Verify that GetSignatureScheme() indicates the signature scheme passed at
// construction time.
TEST(FakeSigningKeyTest, SignatureScheme) {
  FakeVerifyingKey verifying_key(UNKNOWN_SIGNATURE_SCHEME, kTestKeyDer);
  EXPECT_EQ(verifying_key.GetSignatureScheme(),
            SignatureScheme::UNKNOWN_SIGNATURE_SCHEME);

  FakeSigningKey signing_key(UNKNOWN_SIGNATURE_SCHEME, kTestKeyDer);
  EXPECT_EQ(signing_key.GetSignatureScheme(),
            SignatureScheme::UNKNOWN_SIGNATURE_SCHEME);
}

// Verify that Sign() creates the correct signature.
TEST(FakeSigningKeyTest, CorrectSignature) {
  FakeSigningKey signing_key(UNKNOWN_SIGNATURE_SCHEME, kTestKeyDer);

  std::vector<uint8_t> signature;
  ASYLO_ASSERT_OK(signing_key.Sign(kTestMessage, &signature));

  EXPECT_EQ(ByteContainerView(signature),
            ByteContainerView(kTestMessageSignature));
}

// Verify that a FakeSigningKey produces the correct DER-encoding by
// SerializeToDer().
TEST(FakeSigningKeyTest, SigningKeySerializeToDer) {
  FakeSigningKey signing_key(UNKNOWN_SIGNATURE_SCHEME, kTestKeyDer);

  CleansingVector<uint8_t> serialized_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(serialized_key, signing_key.SerializeToDer());
  EXPECT_EQ(ByteContainerView(serialized_key), ByteContainerView(kTestKeyDer));
}

TEST(FakeSigningKeyTest, SigningKeySerializeToKeyProtoSuccess) {
  FakeSigningKey signing_key(UNKNOWN_SIGNATURE_SCHEME, kTestKeyDer);
  AsymmetricSigningKeyProto key_proto;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      key_proto, signing_key.SerializeToKeyProto(ASYMMETRIC_KEY_DER));
  EXPECT_EQ(key_proto.key_type(), AsymmetricSigningKeyProto::SIGNING_KEY);
  EXPECT_EQ(key_proto.signature_scheme(), UNKNOWN_SIGNATURE_SCHEME);
  EXPECT_EQ(key_proto.encoding(), ASYMMETRIC_KEY_DER);
  EXPECT_EQ(key_proto.key(), kTestKeyDer);
}

TEST(FakeSigningKeyTest, SigningKeySerializeToKeyProtoPemFailure) {
  FakeSigningKey signing_key(UNKNOWN_SIGNATURE_SCHEME, kTestKeyDer);
  AsymmetricSigningKeyProto key_proto;
  EXPECT_THAT(signing_key.SerializeToKeyProto(ASYMMETRIC_KEY_PEM),
              StatusIs(absl::StatusCode::kUnimplemented));
}

TEST(FakeSigningKeyTest, SigningKeySerializeToKeyProtoUnknownFailure) {
  FakeSigningKey signing_key(UNKNOWN_SIGNATURE_SCHEME, kTestKeyDer);
  AsymmetricSigningKeyProto key_proto;
  EXPECT_THAT(signing_key.SerializeToKeyProto(UNKNOWN_ASYMMETRIC_KEY_ENCODING),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

// Verify that a FakeSigningKey returns the non-OK Status passed at construction
// as the error for SerializeToDer().
TEST(FakeSigningKeyTest, SigningKeySerializeToDerFailure) {
  FakeSigningKey signing_key(
      UNKNOWN_SIGNATURE_SCHEME,
      Status(absl::StatusCode::kFailedPrecondition, kTestMessage));

  EXPECT_THAT(signing_key.SerializeToDer(),
              StatusIs(absl::StatusCode::kFailedPrecondition, kTestMessage));
}

// Verify that a FakeSigningKey returns the status passed at construction as the
// error for Sign().
TEST(FakeSigningKeyTest, SigningKeySignFailure) {
  FakeSigningKey signing_key(
      UNKNOWN_SIGNATURE_SCHEME,
      Status(absl::StatusCode::kFailedPrecondition, kTestMessage));

  std::vector<uint8_t> signature;
  EXPECT_THAT(signing_key.Sign(kTestMessage, &signature),
              StatusIs(absl::StatusCode::kFailedPrecondition, kTestMessage));
}

// Verify that GetVerifyingKey produces the correct FakeVerifyingKey.
TEST(FakeSigningKeyTest, SigningKeyGetVerifyingKey) {
  FakeSigningKey signing_key(UNKNOWN_SIGNATURE_SCHEME, kTestKeyDer);

  std::unique_ptr<VerifyingKey> verifying_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(verifying_key, signing_key.GetVerifyingKey());

  EXPECT_EQ(*verifying_key,
            FakeVerifyingKey(UNKNOWN_SIGNATURE_SCHEME, kTestKeyDer));
}

}  // namespace
}  // namespace asylo
