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

#include <google/protobuf/text_format.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/flags/flag.h"
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "asylo/crypto/fake_signing_key.h"
#include "asylo/crypto/keys.pb.h"
#include "asylo/crypto/signing_key.h"
#include "asylo/crypto/util/byte_container_util.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/util/logging.h"
#include "asylo/test/util/proto_matchers.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/test/util/string_matchers.h"
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

// An AsymmetricSigningKeyProto with the DER-encoded signing key.
constexpr char kTestSigningKeyDerProto[] = R"pb(
  key_type: SIGNING_KEY
  signature_scheme: ECDSA_P256_SHA256
  encoding: ASYMMETRIC_KEY_DER
  key: "\x30\x77\x02\x01\x01\x04\x20\xfe\x1d\xd5\xd7\x9b\x11\xd1\xba\x5f\x2f\x7b\xe0\x44\xd8\xb7\xee\xfc\x23\x96\xf7\x7e\x90\x3c\xa9\x1f\xce\x63\x7a\x52\x5f\xe8\x30\xa0\x0a\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\xa1\x44\x03\x42\x00\x04\xea\xed\xa5\x10\x3e\x89\x19\x4f\x43\xbf\xe0\xd8\x44\xf3\xe7\x9f\x00\x09\x57\xfc\x3c\x92\x37\xc7\xea\x8d\xdc\xd6\x7e\x22\xc7\x5c\xd7\x51\x19\xea\x9a\xa0\x2f\x76\xce\xca\xcb\xbf\x1b\x2f\xe6\x1c\x69\xfc\x9e\xea\xda\x1f\xe2\x9a\x56\x7d\x6c\xeb\x46\x8e\x16\xbd"
)pb";

// An AsymmetricSigningKeyProto with the PEM-encoded signing key.
constexpr char kTestSigningKeyPemProto[] = R"pb(
  key_type: SIGNING_KEY
  signature_scheme: ECDSA_P256_SHA256
  encoding: ASYMMETRIC_KEY_PEM
  key: "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIP4d1debEdG6Xy974ETYt+78I5b3fpA8qR/OY3pSX+gwoAoGCCqGSM49\nAwEHoUQDQgAE6u2lED6JGU9Dv+DYRPPnnwAJV/w8kjfH6o3c1n4ix1zXURnqmqAv\nds7Ky78bL+Ycafye6tof4ppWfWzrRo4WvQ==\n-----END EC PRIVATE KEY-----"
)pb";

constexpr uint8_t kBadKey[] = "bad key";

constexpr char kTestMessageHex[] = "436f66666565206973206c6966652e0a";

constexpr char kTestSignatureHex[] =
    "304502207f504d6040ded5ddd1bd2b87b5ae2febe09b579f19c094b7fae24d8f47137eda02"
    "2100b45795608442ed963abac8850d93d37e028ce187d53dc2b7577e2d2190b9ea47";

constexpr char kTestSignatureRHex[] =
    "c62a9ffec314b021e6c29daf2c1c7b314931d455761cf93a141080b60fde49ae";

constexpr char kTestSignatureSHex[] =
    "25d86365742835d4f39fbed6637dd5ef1d4846ba56bab55de45d65880e64bf03";

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

// An AsymmetricSigningKeyProto with the DER-encoded verifying key.
constexpr char kTestVerifyingKeyDerProto[] = R"pb(
  key_type: VERIFYING_KEY
  signature_scheme: ECDSA_P256_SHA256
  encoding: ASYMMETRIC_KEY_DER
  key: "\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00\x04\xea\xed\xa5\x10\x3e\x89\x19\x4f\x43\xbf\xe0\xd8\x44\xf3\xe7\x9f\x00\x09\x57\xfc\x3c\x92\x37\xc7\xea\x8d\xdc\xd6\x7e\x22\xc7\x5c\xd7\x51\x19\xea\x9a\xa0\x2f\x76\xce\xca\xcb\xbf\x1b\x2f\xe6\x1c\x69\xfc\x9e\xea\xda\x1f\xe2\x9a\x56\x7d\x6c\xeb\x46\x8e\x16\xbd"
)pb";

// An AsymmetricSigningKeyProto with the PEM-encoded verifying key.
constexpr char kTestVerifyingKeyPemProto[] = R"pb(
  key_type: VERIFYING_KEY
  signature_scheme: ECDSA_P256_SHA256
  encoding: ASYMMETRIC_KEY_PEM
  key: "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6u2lED6JGU9Dv+DYRPPnnwAJV/w8\nkjfH6o3c1n4ix1zXURnqmqAvds7Ky78bL+Ycafye6tof4ppWfWzrRo4WvQ==\n-----END PUBLIC KEY-----"
)pb";

struct VerifyingKeyParam {
  std::function<StatusOr<std::unique_ptr<VerifyingKey>>(ByteContainerView)>
      factory;
  std::string key_data;
};

void CheckPemKeyProtoResult(StatusOr<AsymmetricSigningKeyProto> actual_result,
                            AsymmetricSigningKeyProto expected) {
  AsymmetricSigningKeyProto actual;
  ASYLO_ASSERT_OK_AND_ASSIGN(actual, actual_result);
  ASSERT_THAT(actual.encoding(), ASYMMETRIC_KEY_PEM);
  EXPECT_EQ(actual.key_type(), expected.key_type());
  EXPECT_EQ(actual.signature_scheme(), expected.signature_scheme());
  EXPECT_THAT(actual.key(), EqualIgnoreWhiteSpace(expected.key()));
}

// Verify that Create() fails when the key has an incorrect group.
TEST(EcdsaP256Sha256VerifyingKeyCreateTest,
     CreateVerifyingKeyWithBadGroupFails) {
  bssl::UniquePtr<EC_KEY> bad_key(EC_KEY_new_by_curve_name(kBadGroup));
  ASSERT_EQ(EC_KEY_generate_key(bad_key.get()), 1);
  ASSERT_THAT(EcdsaP256Sha256VerifyingKey::Create(std::move(bad_key)),
              Not(IsOk()));
}

// Verify that CreateFromProto() fails when the signature scheme is incorrect.
TEST(EcdsaP256Sha256VerifyingKeyCreateTest,
     VerifyingKeyCreateFromProtoUnknownBadSignatureSchemeFails) {
  AsymmetricSigningKeyProto key_proto;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(kTestVerifyingKeyPemProto,
                                                  &key_proto));
  key_proto.set_signature_scheme(UNKNOWN_SIGNATURE_SCHEME);

  EXPECT_THAT(EcdsaP256Sha256VerifyingKey::CreateFromProto(key_proto),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

// Verify that CreateFromProto() fails when the key type is incorrect.
TEST(EcdsaP256Sha256VerifyingKeyCreateTest,
     VerifyingKeyCreateFromProtoWithSigningKeyTypeFails) {
  AsymmetricSigningKeyProto key_proto;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(kTestVerifyingKeyPemProto,
                                                  &key_proto));
  key_proto.set_key_type(AsymmetricSigningKeyProto::SIGNING_KEY);

  EXPECT_THAT(EcdsaP256Sha256VerifyingKey::CreateFromProto(key_proto),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

// Verify that CreateFromProto() fails when the key encoding is invalid.
TEST(EcdsaP256Sha256VerifyingKeyCreateTest,
     VerifyingKeyCreateFromProtoWithUnknownEncodingFails) {
  AsymmetricSigningKeyProto key_proto;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(kTestVerifyingKeyPemProto,
                                                  &key_proto));
  key_proto.set_encoding(UNKNOWN_ASYMMETRIC_KEY_ENCODING);

  EXPECT_THAT(EcdsaP256Sha256VerifyingKey::CreateFromProto(key_proto),
              StatusIs(error::GoogleError::UNIMPLEMENTED));
}

// Verify that CreateFromProto() fails when the key does not match the encoding.
TEST(EcdsaP256Sha256VerifyingKeyCreateTest,
     VerifyingKeyCreateFromProtoWithMismatchedEncodingFails) {
  AsymmetricSigningKeyProto pem_key_proto;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(kTestVerifyingKeyPemProto,
                                                  &pem_key_proto));
  pem_key_proto.set_encoding(ASYMMETRIC_KEY_DER);

  EXPECT_THAT(EcdsaP256Sha256VerifyingKey::CreateFromProto(pem_key_proto),
              StatusIs(error::GoogleError::INTERNAL));
}

// Verify that keys created from CreateFromProto() match equivalent keys created
// from CreateFromPem and CreateFromDer.
TEST(EcdsaP256Sha256VerifyingKeyCreateTest,
     VerifyingKeyCreateFromProtoSuccess) {
  std::unique_ptr<VerifyingKey> expected_pem_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      expected_pem_key,
      EcdsaP256Sha256VerifyingKey::CreateFromPem(kTestVerifyingKeyPem));

  AsymmetricSigningKeyProto pem_key_proto;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(kTestVerifyingKeyPemProto,
                                                  &pem_key_proto));
  std::unique_ptr<VerifyingKey> pem_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      pem_key, EcdsaP256Sha256VerifyingKey::CreateFromProto(pem_key_proto));
  EXPECT_EQ(*pem_key, *expected_pem_key);

  std::unique_ptr<VerifyingKey> expected_der_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(expected_der_key,
                             EcdsaP256Sha256VerifyingKey::CreateFromDer(
                                 absl::HexStringToBytes(kTestVerifyingKeyDer)));

  AsymmetricSigningKeyProto der_key_proto;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(kTestVerifyingKeyDerProto,
                                                  &der_key_proto));
  std::unique_ptr<VerifyingKey> der_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      der_key, EcdsaP256Sha256VerifyingKey::CreateFromProto(der_key_proto));
  EXPECT_EQ(*der_key, *expected_der_key);
}

class EcdsaP256Sha256VerifyingKeyTest
    : public ::testing::TestWithParam<VerifyingKeyParam> {
 public:
  void SetUp() override {
    ASYLO_ASSERT_OK_AND_ASSIGN(verifying_key_,
                               GetParam().factory(GetParam().key_data));
  }

  Signature CreateValidSignatureForTestMessage() {
    Signature signature;
    signature.set_signature_scheme(ECDSA_P256_SHA256);
    signature.mutable_ecdsa_signature()->set_r(
        absl::HexStringToBytes(kTestSignatureRHex));
    signature.mutable_ecdsa_signature()->set_s(
        absl::HexStringToBytes(kTestSignatureSHex));
    return signature;
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

TEST_P(EcdsaP256Sha256VerifyingKeyTest, VerifyingKeySerializeToPem) {
  EXPECT_THAT(verifying_key_->SerializeToPem(),
              IsOkAndHolds(EqualIgnoreWhiteSpace(kTestVerifyingKeyPem)));
}

TEST_P(EcdsaP256Sha256VerifyingKeyTest, SerializeToKeyProtoUnknownFailure) {
  EXPECT_THAT(
      verifying_key_->SerializeToKeyProto(UNKNOWN_ASYMMETRIC_KEY_ENCODING),
      StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST_P(EcdsaP256Sha256VerifyingKeyTest,
       VerifyingKeySerializeToKeyProtoSuccess) {
  AsymmetricSigningKeyProto expected_der_key_proto;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(kTestVerifyingKeyDerProto,
                                                  &expected_der_key_proto));

  EXPECT_THAT(verifying_key_->SerializeToKeyProto(ASYMMETRIC_KEY_DER),
              IsOkAndHolds(EqualsProto(expected_der_key_proto)));

  AsymmetricSigningKeyProto expected_pem_key_proto;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(kTestVerifyingKeyPemProto,
                                                  &expected_pem_key_proto));

  CheckPemKeyProtoResult(
      verifying_key_->SerializeToKeyProto(ASYMMETRIC_KEY_PEM),
      expected_pem_key_proto);
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

// Verify that Verify() with Signature overload does not verify a signature with
// an incorrect signature scheme.
TEST_P(EcdsaP256Sha256VerifyingKeyTest,
       VerifyWithIncorrectSignatureSchemeFails) {
  std::string valid_message(absl::HexStringToBytes(kTestMessageHex));

  Signature signature = CreateValidSignatureForTestMessage();
  signature.set_signature_scheme(UNKNOWN_SIGNATURE_SCHEME);

  EXPECT_THAT(verifying_key_->Verify(valid_message, signature),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

// Verify that Verify() with Signature overload does not verify a signature
// without an ECDSA signature value.
TEST_P(EcdsaP256Sha256VerifyingKeyTest, VerifyWithMissingEcdsaSignatureFails) {
  std::string valid_message(absl::HexStringToBytes(kTestMessageHex));

  Signature signature = CreateValidSignatureForTestMessage();
  signature.clear_ecdsa_signature();

  EXPECT_THAT(verifying_key_->Verify(valid_message, signature),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

// Verify that Verify() with Signature overload fails without an R field.
TEST_P(EcdsaP256Sha256VerifyingKeyTest, VerifyWithMissingRFieldFails) {
  Signature signature = CreateValidSignatureForTestMessage();
  signature.mutable_ecdsa_signature()->clear_r();

  std::unique_ptr<VerifyingKey> verifying_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      verifying_key,
      EcdsaP256Sha256VerifyingKey::CreateFromPem(kTestVerifyingKeyPem));

  EXPECT_THAT(
      verifying_key->Verify(absl::HexStringToBytes(kTestMessageHex), signature),
      StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

// Verify that Verify() with Signature overload fails without an S field.
TEST_P(EcdsaP256Sha256VerifyingKeyTest, VerifyWithMissingSFieldFails) {
  Signature signature = CreateValidSignatureForTestMessage();
  signature.mutable_ecdsa_signature()->clear_s();

  std::unique_ptr<VerifyingKey> verifying_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      verifying_key,
      EcdsaP256Sha256VerifyingKey::CreateFromPem(kTestVerifyingKeyPem));

  EXPECT_THAT(
      verifying_key->Verify(absl::HexStringToBytes(kTestMessageHex), signature),
      StatusIs(error::GoogleError::INVALID_ARGUMENT));
}
// Verify that Verify() with Signature overload fails a short R field.
TEST_P(EcdsaP256Sha256VerifyingKeyTest, VerifyWithShortRFieldFails) {
  Signature signature = CreateValidSignatureForTestMessage();
  signature.mutable_ecdsa_signature()->set_r("too short");

  std::unique_ptr<VerifyingKey> verifying_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      verifying_key,
      EcdsaP256Sha256VerifyingKey::CreateFromPem(kTestVerifyingKeyPem));

  EXPECT_THAT(
      verifying_key->Verify(absl::HexStringToBytes(kTestMessageHex), signature),
      StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

// Verify that Verify() with Signature overload fails with a long S field.
TEST_P(EcdsaP256Sha256VerifyingKeyTest, VerifyWithLongSFieldFails) {
  Signature signature = CreateValidSignatureForTestMessage();
  signature.mutable_ecdsa_signature()->set_s(
      "this is an s field that is way too long");

  std::unique_ptr<VerifyingKey> verifying_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      verifying_key,
      EcdsaP256Sha256VerifyingKey::CreateFromPem(kTestVerifyingKeyPem));

  EXPECT_THAT(
      verifying_key->Verify(absl::HexStringToBytes(kTestMessageHex), signature),
      StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

// Verify that Verify() with Signature overload passes with valid signature.
TEST_P(EcdsaP256Sha256VerifyingKeyTest, VerifySignatureOverloadSuccess) {
  Signature signature = CreateValidSignatureForTestMessage();

  std::unique_ptr<VerifyingKey> verifying_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      verifying_key,
      EcdsaP256Sha256VerifyingKey::CreateFromPem(kTestVerifyingKeyPem));

  ASYLO_EXPECT_OK(verifying_key->Verify(absl::HexStringToBytes(kTestMessageHex),
                                        signature));
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
      ASYLO_ASSERT_OK_AND_ASSIGN(serialized, signing_key_->SerializeToDer());

      LOG(INFO) << "Using random SigningKey: "
                << absl::BytesToHexString(
                       CopyToByteContainer<std::string>(serialized));
    }
  }

  std::unique_ptr<EcdsaP256Sha256SigningKey> signing_key_;
};

// Verify that CreateFromProto() fails when the signature scheme is incorrect.
TEST_F(EcdsaP256Sha256SigningKeyTest,
       SigningKeyCreateFromProtoWithUnknownSignatureSchemeFails) {
  AsymmetricSigningKeyProto key_proto;
  ASSERT_TRUE(
      google::protobuf::TextFormat::ParseFromString(kTestSigningKeyPemProto, &key_proto));
  key_proto.set_signature_scheme(UNKNOWN_SIGNATURE_SCHEME);

  EXPECT_THAT(EcdsaP256Sha256SigningKey::CreateFromProto(key_proto),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

// Verify that CreateFromProto() fails when the key type is incorrect.
TEST_F(EcdsaP256Sha256SigningKeyTest,
       SigningKeyCreateFromProtoWithVerifyingKeyTypeFails) {
  AsymmetricSigningKeyProto key_proto;
  ASSERT_TRUE(
      google::protobuf::TextFormat::ParseFromString(kTestSigningKeyPemProto, &key_proto));
  key_proto.set_key_type(AsymmetricSigningKeyProto::VERIFYING_KEY);

  EXPECT_THAT(EcdsaP256Sha256SigningKey::CreateFromProto(key_proto),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

// Verify that CreateFromProto() fails when the key encoding is invalid.
TEST_F(EcdsaP256Sha256SigningKeyTest,
       SigningKeyCreateFromProtoWithUnknownEncodingFails) {
  AsymmetricSigningKeyProto key_proto;
  ASSERT_TRUE(
      google::protobuf::TextFormat::ParseFromString(kTestSigningKeyPemProto, &key_proto));
  key_proto.set_encoding(UNKNOWN_ASYMMETRIC_KEY_ENCODING);

  EXPECT_THAT(EcdsaP256Sha256SigningKey::CreateFromProto(key_proto),
              StatusIs(error::GoogleError::UNIMPLEMENTED));
}

// Verify that CreateFromProto() fails when the key does not match the encoding.
TEST_F(EcdsaP256Sha256SigningKeyTest,
       SigningKeyCreateFromProtoWithMismatchedEncodingFails) {
  AsymmetricSigningKeyProto pem_key_proto;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(kTestSigningKeyPemProto,
                                                  &pem_key_proto));
  pem_key_proto.set_encoding(ASYMMETRIC_KEY_DER);

  EXPECT_THAT(EcdsaP256Sha256SigningKey::CreateFromProto(pem_key_proto),
              StatusIs(error::GoogleError::INTERNAL));
}

TEST_F(EcdsaP256Sha256SigningKeyTest, SigningKeyCreateFromProtoSuccess) {
  AsymmetricSigningKeyProto pem_key_proto;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(kTestSigningKeyPemProto,
                                                  &pem_key_proto));
  ASYLO_EXPECT_OK(EcdsaP256Sha256SigningKey::CreateFromProto(pem_key_proto));

  AsymmetricSigningKeyProto der_key_proto;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(kTestSigningKeyDerProto,
                                                  &der_key_proto));
  ASYLO_EXPECT_OK(EcdsaP256Sha256SigningKey::CreateFromProto(der_key_proto));
}

// Verify that Create() fails when the key has an incorrect group.
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
  ASYLO_ASSERT_OK_AND_ASSIGN(serialized_der, signing_key_pem->SerializeToDer());

  EXPECT_EQ(ByteContainerView(serialized_der),
            ByteContainerView(absl::HexStringToBytes(kTestSigningKeyDer)));
}

TEST_F(EcdsaP256Sha256SigningKeyTest, CreateSigningKeyFromDerMatchesPem) {
  std::unique_ptr<SigningKey> signing_key_der;
  ASYLO_ASSERT_OK_AND_ASSIGN(signing_key_der,
                             EcdsaP256Sha256SigningKey::CreateFromDer(
                                 absl::HexStringToBytes(kTestSigningKeyDer)));

  CleansingVector<char> serialized_pem;
  ASYLO_ASSERT_OK_AND_ASSIGN(serialized_pem, signing_key_der->SerializeToPem());

  EXPECT_THAT(CopyToByteContainer<std::string>(serialized_pem),
              EqualIgnoreWhiteSpace(kTestSigningKeyPem));
}

TEST_F(EcdsaP256Sha256SigningKeyTest, SerializeToKeyProtoUnknownFailure) {
  EXPECT_THAT(
      signing_key_->SerializeToKeyProto(UNKNOWN_ASYMMETRIC_KEY_ENCODING),
      StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST_F(EcdsaP256Sha256SigningKeyTest, SerializeToKeyProtoSuccess) {
  std::unique_ptr<SigningKey> signing_key_der;
  ASYLO_ASSERT_OK_AND_ASSIGN(signing_key_der,
                             EcdsaP256Sha256SigningKey::CreateFromDer(
                                 absl::HexStringToBytes(kTestSigningKeyDer)));

  AsymmetricSigningKeyProto expected_der_key_proto;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(kTestSigningKeyDerProto,
                                                  &expected_der_key_proto));

  EXPECT_THAT(signing_key_der->SerializeToKeyProto(ASYMMETRIC_KEY_DER),
              IsOkAndHolds(EqualsProto(expected_der_key_proto)));

  std::unique_ptr<SigningKey> signing_key_pem;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      signing_key_pem,
      EcdsaP256Sha256SigningKey::CreateFromPem(kTestSigningKeyPem));

  AsymmetricSigningKeyProto expected_pem_key_proto;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(kTestSigningKeyPemProto,
                                                  &expected_pem_key_proto));

  CheckPemKeyProtoResult(
      signing_key_pem->SerializeToKeyProto(ASYMMETRIC_KEY_PEM),
      expected_pem_key_proto);
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

// Verifies that Sign and Verify work with the Signature overloads.
TEST_F(EcdsaP256Sha256SigningKeyTest, SignAndVerifySignatureOverloads) {
  std::string message(absl::HexStringToBytes(kTestMessageHex));
  Signature signature;
  ASYLO_ASSERT_OK(signing_key_->Sign(message, &signature));

  std::unique_ptr<VerifyingKey> verifying_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(verifying_key, signing_key_->GetVerifyingKey());

  ASYLO_EXPECT_OK(verifying_key->Verify(message, signature));

  // Ensure that signature is not verifiable if one bit is flipped.
  signature.mutable_ecdsa_signature()->mutable_r()->back() ^= 1;
  EXPECT_THAT(verifying_key->Verify(message, signature), Not(IsOk()));
}

// Verify that SerializeToDer() and CreateFromDer() from a serialized key are
// working correctly, and that an EcdsaP256Sha256SigningKey restored from a
// serialized version of another EcdsaP256Sha256SigningKey can verify a
// signature produced by the original key successfully.
TEST_F(EcdsaP256Sha256SigningKeyTest, SerializeToDerAndRestoreSigningKey) {
  CleansingVector<uint8_t> serialized_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(serialized_key, signing_key_->SerializeToDer());

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
  ASYLO_ASSERT_OK_AND_ASSIGN(serialized_key_bin_actual,
                             signing_key2->SerializeToDer());

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

// Verify that we can export and import the public key coordinate.
TEST_F(EcdsaP256Sha256SigningKeyTest, ExportAndImportRawPublicKey) {
  // First export and import key point
  EccP256CurvePoint public_key_point;
  ASYLO_ASSERT_OK_AND_ASSIGN(public_key_point,
                             signing_key_->GetPublicKeyPoint());

  std::unique_ptr<VerifyingKey> verifier;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      verifier, EcdsaP256Sha256VerifyingKey::Create(public_key_point));

  // Second, ensure the verifying key can check signatures properly.
  std::vector<uint8_t> signature;
  ASYLO_EXPECT_OK(signing_key_->Sign("sign this stuff", &signature));
  ASYLO_EXPECT_OK(verifier->Verify("sign this stuff", signature));
}
}  // namespace
}  // namespace asylo
