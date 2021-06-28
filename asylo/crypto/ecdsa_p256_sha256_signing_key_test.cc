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

#include <memory>

#include <gtest/gtest.h>
#include "absl/strings/string_view.h"
#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/ecdsa_signing_key_test.h"
#include "asylo/crypto/util/byte_container_view.h"

namespace asylo {
namespace {

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

// The scalar in kTestSigningKeyDer.
constexpr char kTestSigningKeyScalar[] =
    "fe1dd5d79b11d1ba5f2f7be044d8b7eefc2396f77e903ca91fce637a525fe830";

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

class EcdsaP256Sha256VerifyingKeyTest
    : public EcdsaVerifyingKeyTest<EcdsaP256Sha256VerifyingKey> {
 public:
  using SigningKeyType = EcdsaP256Sha256SigningKey;
  using VerifyingKeyType = EcdsaP256Sha256VerifyingKey;
  using CurvePointType = EccP256CurvePoint;

  EcdsaP256Sha256VerifyingKeyTest()
      : EcdsaVerifyingKeyTest(
            kTestVerifyingKeyDer, kTestVerifyingKeyPem,
            kTestVerifyingKeyDerProto, kTestVerifyingKeyPemProto,
            kOtherVerifyingKeyPem, kTestMessageHex, kTestSignatureHex,
            kTestSignatureRHex, kTestSignatureSHex, kInvalidSignatureHex,
            kBadGroup, SignatureScheme::ECDSA_P256_SHA256) {}

  StatusOr<std::unique_ptr<VerifyingKey>> DerFactory(
      ByteContainerView serialized_key) override {
    return EcdsaP256Sha256VerifyingKey::CreateFromDer(serialized_key);
  }

  StatusOr<std::unique_ptr<VerifyingKey>> PemFactory(
      ByteContainerView serialized_key) override {
    return EcdsaP256Sha256VerifyingKey::CreateFromPem(serialized_key);
  }
};

typedef testing::Types<EcdsaP256Sha256VerifyingKeyTest> VerifyingKeyTypes;
INSTANTIATE_TYPED_TEST_SUITE_P(EcdsaP256Sha256, VerifyingKeyTest,
                               VerifyingKeyTypes);

class EcdsaP256Sha256SigningKeyTest
    : public EcdsaSigningKeyTest<EcdsaP256Sha256SigningKey> {
 public:
  using SigningKeyType = EcdsaP256Sha256SigningKey;
  using VerifyingKeyType = EcdsaP256Sha256VerifyingKey;
  using CurvePointType = EccP256CurvePoint;

  EcdsaP256Sha256SigningKeyTest()
      : EcdsaSigningKeyTest(kTestSigningKeyDer, kTestSigningKeyPem,
                            kTestSigningKeyDerProto, kTestSigningKeyPemProto,
                            kTestSigningKeyScalar, kTestMessageHex, kBadGroup,
                            kMessageSize, SignatureScheme::ECDSA_P256_SHA256,
                            kTestVerifyingKeyDer) {}
};

typedef testing::Types<EcdsaP256Sha256SigningKeyTest> SigningKeyTypes;
INSTANTIATE_TYPED_TEST_SUITE_P(EcdsaP256Sha256, SigningKeyTest,
                               SigningKeyTypes);

}  // namespace
}  // namespace asylo
