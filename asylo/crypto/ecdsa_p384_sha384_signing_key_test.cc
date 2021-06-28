/*
 * Copyright 2020 Asylo authors
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
 */

#include "asylo/crypto/ecdsa_p384_sha384_signing_key.h"

#include <gtest/gtest.h>
#include "asylo/crypto/ecdsa_signing_key_test.h"

namespace asylo {
namespace {

const int kBadGroup = NID_secp224r1;
const int kMessageSize = 1000;

constexpr char kTestSigningKeyDer[] =
    "3081a40201010430b6d096aca3e5557a5e6ea8f49f110c940e02cbdcd2f7"
    "c0f75616b8795cfbfde823ef33f80125cf8e78589434f0a4f7bda0070605"
    "2b81040022a164036200045a93f9d567f629948fe5ebab9c62c139ae83e9"
    "00cd6c536977ead2eeef8238fc775065fd31d07a4a39f83961a2a8d2945e"
    "8bc2d22b85e9a56be9ec8182f0d63f3c38b5acee0af531f2412e314657c4"
    "a0e202e28fa38d069254b74b04c13a6996";

// The PEM-encoded equivalent of kTestSigningKeyDer.
constexpr char kTestSigningKeyPem[] =
    R"(-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDC20Jaso+VVel5uqPSfEQyUDgLL3NL3wPdWFrh5XPv96CPvM/gBJc+O
eFiUNPCk972gBwYFK4EEACKhZANiAARak/nVZ/YplI/l66ucYsE5roPpAM1sU2l3
6tLu74I4/HdQZf0x0HpKOfg5YaKo0pRei8LSK4XppWvp7IGC8NY/PDi1rO4K9THy
QS4xRlfEoOIC4o+jjQaSVLdLBME6aZY=
-----END EC PRIVATE KEY-----)";

// An AsymmetricSigningKeyProto with the DER-encoded signing key.
constexpr char kTestSigningKeyDerProto[] = R"pb(
  key_type: SIGNING_KEY
  signature_scheme: ECDSA_P384_SHA384
  encoding: ASYMMETRIC_KEY_DER
  key: "\x30\x81\xa4\x02\x01\x01\x04\x30\xb6\xd0\x96\xac\xa3\xe5\x55\x7a\x5e\x6e\xa8\xf4\x9f\x11\x0c\x94\x0e\x02\xcb\xdc\xd2\xf7\xc0\xf7\x56\x16\xb8\x79\x5c\xfb\xfd\xe8\x23\xef\x33\xf8\x01\x25\xcf\x8e\x78\x58\x94\x34\xf0\xa4\xf7\xbd\xa0\x07\x06\x05\x2b\x81\x04\x00\x22\xa1\x64\x03\x62\x00\x04\x5a\x93\xf9\xd5\x67\xf6\x29\x94\x8f\xe5\xeb\xab\x9c\x62\xc1\x39\xae\x83\xe9\x00\xcd\x6c\x53\x69\x77\xea\xd2\xee\xef\x82\x38\xfc\x77\x50\x65\xfd\x31\xd0\x7a\x4a\x39\xf8\x39\x61\xa2\xa8\xd2\x94\x5e\x8b\xc2\xd2\x2b\x85\xe9\xa5\x6b\xe9\xec\x81\x82\xf0\xd6\x3f\x3c\x38\xb5\xac\xee\x0a\xf5\x31\xf2\x41\x2e\x31\x46\x57\xc4\xa0\xe2\x02\xe2\x8f\xa3\x8d\x06\x92\x54\xb7\x4b\x04\xc1\x3a\x69\x96"
)pb";

// An AsymmetricSigningKeyProto with the PEM-encoded signing key.
constexpr char kTestSigningKeyPemProto[] = R"pb(
  key_type: SIGNING_KEY
  signature_scheme: ECDSA_P384_SHA384
  encoding: ASYMMETRIC_KEY_PEM
  key: "-----BEGIN EC PRIVATE KEY-----\nMIGkAgEBBDC20Jaso+VVel5uqPSfEQyUDgLL3NL3wPdWFrh5XPv96CPvM/gBJc+O\neFiUNPCk972gBwYFK4EEACKhZANiAARak/nVZ/YplI/l66ucYsE5roPpAM1sU2l3\n6tLu74I4/HdQZf0x0HpKOfg5YaKo0pRei8LSK4XppWvp7IGC8NY/PDi1rO4K9THy\nQS4xRlfEoOIC4o+jjQaSVLdLBME6aZY=\n-----END EC PRIVATE KEY-----"
)pb";

// The scalar in kTestSigningKeyDer.
constexpr char kTestSigningKeyScalar[] =
    "b6d096aca3e5557a5e6ea8f49f110c940e02cbdcd2f7c0f75616b8795cfbfde823ef33f801"
    "25cf8e78589434f0a4f7bd";

constexpr char kTestMessageHex[] =
    "7468697320697320612074657374206d6573736167650a";

constexpr char kTestSignatureHex[] =
    "306402306929f499a5249b5dedb3a2a5f2f502a4d1e24d243ad0c79d72dd240a64fff74fe1"
    "9e573074832d9284d17a154c24d486023012482b369f9d3da86c5334aacb0a98b41d4ae18d"
    "52209dcced8d2655f013aab054b8ec06a78199674764b3e2f6d82df6";

constexpr char kTestSignatureRHex[] =
    "6929f499a5249b5dedb3a2a5f2f502a4d1e24d243ad0c79d72dd240a64fff74fe19e573074"
    "832d9284d17a154c24d486";

constexpr char kTestSignatureSHex[] =
    "12482b369f9d3da86c5334aacb0a98b41d4ae18d52209dcced8d2655f013aab054b8ec06a7"
    "8199674764b3e2f6d82df6";

constexpr char kInvalidSignatureHex[] =
    "3046022100b5071aa5a029409df562d8b71a5f48"
    "dc03d4f1864762bc14d1c5d849ac8fd5660221008e0879f733c326f7855e4d681d809c9374"
    "6390a519edb7acdca752afe2eedc51";

constexpr char kTestVerifyingKeyDer[] =
    "3076301006072a8648ce3d020106052b81040022036200045a93f9d567f6"
    "29948fe5ebab9c62c139ae83e900cd6c536977ead2eeef8238fc775065fd"
    "31d07a4a39f83961a2a8d2945e8bc2d22b85e9a56be9ec8182f0d63f3c38"
    "b5acee0af531f2412e314657c4a0e202e28fa38d069254b74b04c13a6996";

// The PEM-encoded equivalent of kTestVerifyingKeyDer.
constexpr char kTestVerifyingKeyPem[] =
    R"(-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEWpP51Wf2KZSP5eurnGLBOa6D6QDNbFNp
d+rS7u+COPx3UGX9MdB6Sjn4OWGiqNKUXovC0iuF6aVr6eyBgvDWPzw4tazuCvUx
8kEuMUZXxKDiAuKPo40GklS3SwTBOmmW
-----END PUBLIC KEY-----)";

// A different key from kTestVerifyingKeyPem.
constexpr char kOtherVerifyingKeyPem[] =
    R"(-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEDwaQUwzEzNVooyYduSvML7qihjEqpotX
aT9sLht+11XkrMDBRN8R+066YTZGiCY1uIViArBV/Y4eecgBS/Tqk0msmdEAZlGd
LJRGX6csXu0NTcaLtq54Y25OQ04L/evD
-----END PUBLIC KEY-----)";

// An AsymmetricSigningKeyProto with the DER-encoded verifying key.
constexpr char kTestVerifyingKeyDerProto[] = R"pb(
  key_type: VERIFYING_KEY
  signature_scheme: ECDSA_P384_SHA384
  encoding: ASYMMETRIC_KEY_DER
  key: "\x30\x76\x30\x10\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x05\x2b\x81\x04\x00\x22\x03\x62\x00\x04\x5a\x93\xf9\xd5\x67\xf6\x29\x94\x8f\xe5\xeb\xab\x9c\x62\xc1\x39\xae\x83\xe9\x00\xcd\x6c\x53\x69\x77\xea\xd2\xee\xef\x82\x38\xfc\x77\x50\x65\xfd\x31\xd0\x7a\x4a\x39\xf8\x39\x61\xa2\xa8\xd2\x94\x5e\x8b\xc2\xd2\x2b\x85\xe9\xa5\x6b\xe9\xec\x81\x82\xf0\xd6\x3f\x3c\x38\xb5\xac\xee\x0a\xf5\x31\xf2\x41\x2e\x31\x46\x57\xc4\xa0\xe2\x02\xe2\x8f\xa3\x8d\x06\x92\x54\xb7\x4b\x04\xc1\x3a\x69\x96"
)pb";

// An AsymmetricSigningKeyProto with the PEM-encoded verifying key.
constexpr char kTestVerifyingKeyPemProto[] = R"pb(
  key_type: VERIFYING_KEY
  signature_scheme: ECDSA_P384_SHA384
  encoding: ASYMMETRIC_KEY_PEM
  key: "-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEWpP51Wf2KZSP5eurnGLBOa6D6QDNbFNp\nd+rS7u+COPx3UGX9MdB6Sjn4OWGiqNKUXovC0iuF6aVr6eyBgvDWPzw4tazuCvUx\n8kEuMUZXxKDiAuKPo40GklS3SwTBOmmW\n-----END PUBLIC KEY-----"
)pb";

class EcdsaP384Sha384VerifyingKeyTest
    : public EcdsaVerifyingKeyTest<EcdsaP384Sha384VerifyingKey> {
 public:
  using SigningKeyType = EcdsaP384Sha384SigningKey;
  using VerifyingKeyType = EcdsaP384Sha384VerifyingKey;
  using CurvePointType = EccP384CurvePoint;

  EcdsaP384Sha384VerifyingKeyTest()
      : EcdsaVerifyingKeyTest(
            kTestVerifyingKeyDer, kTestVerifyingKeyPem,
            kTestVerifyingKeyDerProto, kTestVerifyingKeyPemProto,
            kOtherVerifyingKeyPem, kTestMessageHex, kTestSignatureHex,
            kTestSignatureRHex, kTestSignatureSHex, kInvalidSignatureHex,
            kBadGroup, SignatureScheme::ECDSA_P384_SHA384) {}

  StatusOr<std::unique_ptr<VerifyingKey>> DerFactory(
      ByteContainerView serialized_key) override {
    return EcdsaP384Sha384VerifyingKey::CreateFromDer(serialized_key);
  }

  StatusOr<std::unique_ptr<VerifyingKey>> PemFactory(
      ByteContainerView serialized_key) override {
    return EcdsaP384Sha384VerifyingKey::CreateFromPem(serialized_key);
  }
};

using VerifyingKeyTypes = testing::Types<EcdsaP384Sha384VerifyingKeyTest>;
INSTANTIATE_TYPED_TEST_SUITE_P(EcdsaP384Sha384, VerifyingKeyTest,
                               VerifyingKeyTypes);

class EcdsaP384Sha384SigningKeyTest
    : public EcdsaSigningKeyTest<EcdsaP384Sha384SigningKey> {
 public:
  using SigningKeyType = EcdsaP384Sha384SigningKey;
  using VerifyingKeyType = EcdsaP384Sha384VerifyingKey;
  using CurvePointType = EccP384CurvePoint;

  EcdsaP384Sha384SigningKeyTest()
      : EcdsaSigningKeyTest(kTestSigningKeyDer, kTestSigningKeyPem,
                            kTestSigningKeyDerProto, kTestSigningKeyPemProto,
                            kTestSigningKeyScalar, kTestMessageHex, kBadGroup,
                            kMessageSize, SignatureScheme::ECDSA_P384_SHA384,
                            kTestVerifyingKeyDer) {}
};

using SigningKeyTypes = testing::Types<EcdsaP384Sha384SigningKeyTest>;
INSTANTIATE_TYPED_TEST_SUITE_P(EcdsaP384Sha384, SigningKeyTest,
                               SigningKeyTypes);

}  // namespace
}  // namespace asylo
