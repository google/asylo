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

#include "asylo/identity/attestation/sgx/internal/pce_util.h"

#include <openssl/base.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/base/macros.h"
#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/util/bssl_util.h"
#include "asylo/crypto/util/bytes.h"
#include "asylo/crypto/util/trivial_object_util.h"
#include "asylo/identity/platform/sgx/internal/identity_key_management_structs.h"
#include "asylo/test/util/proto_matchers.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/proto_enum_util.h"
#include "asylo/util/status_macros.h"
#include "QuoteGeneration/pce_wrapper/inc/sgx_pce_constants.h"

namespace asylo {
namespace sgx {
namespace {

constexpr char kSecretMessage[] = "secret message";

// Hex-encoded RSA_F4 in big-endian format.
constexpr char kExponentBigEndianHex[] = "00010001";

// A hex-encoded RSA-3072 key modulus in big-endian format.
constexpr char kModulusBigEndianHex[] =
    "ecb62879f45c3880514bd2ee7bf1c2373c0de9184a641c250bfe59a3702e0a6632cc5e9e96"
    "ef16c04ca2844b1fa14ca0cdda7fa953fd69e5cb3f2368cab778fcf3e42db4c3b57f6b8a17"
    "c1fa58bc9fb99486668bdb4ddde725762c9f06d488463ece26aa5b57de5200785622d9b485"
    "95ef9523de581c50d98dc40e2605d907f057a66a13b6725b07b60f344cabf6255568a73267"
    "8d2fa9a8ed2c482e23aedf47d4ce2c77a73b622c2712176386cd6ecddff1dc200ede191918"
    "c63a74197d505f264349fdafbc44595e22b3cca2b428b5098c53e360cff8fd0d7053d3a868"
    "855c17dc9e7bf376b077ee4abcea326e46799d983962939a0bd51a6291cf494d8cb61f402f"
    "cfcec220f43ac2df50923e242f7ee0d2a91d2511cd5aa4cfa83d5e651d397f77806fb93ef3"
    "f9d04103097079a2b65d6041f339cf589bd8452dfc7683d7c1d5f7bfacc0039dd263f4a447"
    "af1909db1c1f6f0196218754dfeb2cd9b63f5268c6b51f39124765aed40af4e5dd78626aed"
    "43b51ae86688da36864bb063cab5";

constexpr char kExpectedReportdata[] =
    "df63e2c2dfe6baa281c008fce2c4eee28d2dd5943ef9122c871772539d778999"
    "0000000000000000000000000000000000000000000000000000000000000000";

constexpr char kRsa3072PublicKeyPem[] =
    R"(-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAvxMDugH2cYvUWzjQhSgR
D4nT5Gj/2d2NHK3eZ52hzOfwn7Rv7PvNIzKWZWsI0SWfrOyZ3cZvuqRLvuUp3ouk
NPBfTMDGd6aUXK1U8ujgIIrSIY/Xq88tKoh3b63TuTgaMZuQhe+Yi5ME/JVMsHuc
SiY9SmCNJSLWJbNDnY8tMpnMLo027EN7gBIPinTQJK6IeqDkdsoxFXuydpC367bJ
qYSWSEbEgRpzrs4UUgdVMBc/fJU9zRqB50pFcVzbccFaB7XYiqZtrdqU07eorbpd
XINBBPFdfePByVdiUW6zfsxf8eUXLVXk9TioF1MqcJcVuHMndry2na28vQG9ZNH4
Glrb332S4+gfHYOTv5PJxLteIrWfyRstWxzuegpUcmrGSjgrMdjcuUOJjCnDJ2bW
0r0UE9um8JQodJKpILtTpq1rV+QlseUPu90ZID3OTk5PSne6NtJe7bN+9WeJspQO
C5xYNu944AfU3z0rnYRx0fEkiftBTiunrAioOA5jMQFHAgMBAAE=
-----END PUBLIC KEY-----)";

constexpr char kSerializedRsa3072PublicKeyHex[] =
    "bf1303ba01f6718bd45b38d08528110f89d3e468ffd9dd8d1cadde679da1cce7f09fb46fe"
    "cfbcd233296656b08d1259facec99ddc66fbaa44bbee529de8ba434f05f4cc0c677a6945c"
    "ad54f2e8e0208ad2218fd7abcf2d2a88776fadd3b9381a319b9085ef988b9304fc954cb07"
    "b9c4a263d4a608d2522d625b3439d8f2d3299cc2e8d36ec437b80120f8a74d024ae887aa0"
    "e476ca31157bb27690b7ebb6c9a984964846c4811a73aece1452075530173f7c953dcd1a8"
    "1e74a45715cdb71c15a07b5d88aa66dadda94d3b7a8adba5d5c834104f15d7de3c1c95762"
    "516eb37ecc5ff1e5172d55e4f538a817532a709715b8732776bcb69dadbcbd01bd64d1f81"
    "a5adbdf7d92e3e81f1d8393bf93c9c4bb5e22b59fc91b2d5b1cee7a0a54726ac64a382b31"
    "d8dcb943898c29c32766d6d2bd1413dba6f094287492a920bb53a6ad6b57e425b1e50fbbd"
    "d19203dce4e4e4f4a77ba36d25eedb37ef56789b2940e0b9c5836ef78e007d4df3d2b9d84"
    "71d1f12489fb414e2ba7ac08a8380e6331014700010001";

constexpr char kEcdsaP256SignatureR[] =
    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
constexpr char kEcdsaP256SignatureS[] =
    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

constexpr int kBadPceCryptoSuite = 42;
constexpr int kBadPceSignatureScheme = 42;

using ::testing::Not;
using ::testing::Optional;
using ::testing::SizeIs;

// All encryption schemes supported by the PCE.
constexpr AsymmetricEncryptionScheme kSupportedEncryptionSchemes[] = {
    RSA3072_OAEP};

// The crypto suite corresponding to each scheme in kSupportedEncryptionSchemes.
constexpr uint8_t kTranslatedEncryptionSchemes[] = {PCE_ALG_RSA_OAEP_3072};

// All signature schemes supported by the PCE.
constexpr SignatureScheme kSupportedSignatureSchemes[] = {ECDSA_P256_SHA256};

// The signature scheme corresponding to each scheme in
// kSupportedSignatureSchemes.
constexpr uint8_t kTranslatedSignatureSchemes[] = {PCE_NIST_P256_ECDSA_SHA256};

MATCHER_P(EqualsHexBytes, b, "") {
  return absl::BytesToHexString(absl::string_view(
             reinterpret_cast<const char *>(arg.data()), arg.size())) == b;
}

AsymmetricEncryptionKeyProto Rsa3072PublicKeyProto() {
  AsymmetricEncryptionKeyProto key;
  key.set_key_type(AsymmetricEncryptionKeyProto::ENCRYPTION_KEY);
  key.set_encoding(AsymmetricKeyEncoding::ASYMMETRIC_KEY_PEM);
  key.set_encryption_scheme(AsymmetricEncryptionScheme::RSA3072_OAEP);
  key.set_key(kRsa3072PublicKeyPem);
  return key;
}

Signature EcdsaP256Signature() {
  Signature signature;
  signature.mutable_ecdsa_signature()->set_r(
      absl::HexStringToBytes(kEcdsaP256SignatureR));
  signature.mutable_ecdsa_signature()->set_s(
      absl::HexStringToBytes(kEcdsaP256SignatureS));
  signature.set_signature_scheme(SignatureScheme::ECDSA_P256_SHA256);
  return signature;
}

std::string PckEcdsaP256Signature() {
  std::string signature_hex;
  signature_hex += kEcdsaP256SignatureR;
  signature_hex += kEcdsaP256SignatureS;
  return absl::HexStringToBytes(signature_hex);
}

class PceUtilTest : public ::testing::Test {
 public:
  void SetUp() override {
    supported_encryption_schemes_.reserve(
        ABSL_ARRAYSIZE(kSupportedEncryptionSchemes));
    for (int i = 0; i < ABSL_ARRAYSIZE(kSupportedEncryptionSchemes); ++i) {
      ASSERT_TRUE(supported_encryption_schemes_
                      .emplace(kSupportedEncryptionSchemes[i],
                               kTranslatedEncryptionSchemes[i])
                      .second);
    }
    for (int i = 0; i < AsymmetricEncryptionScheme_ARRAYSIZE; ++i) {
      if (AsymmetricEncryptionScheme_IsValid(i)) {
        AsymmetricEncryptionScheme scheme =
            static_cast<AsymmetricEncryptionScheme>(i);
        if (!supported_encryption_schemes_.contains(scheme)) {
          unsupported_encryption_schemes_.push_back(scheme);
        }
      }
    }

    supported_signature_schemes_.reserve(
        ABSL_ARRAYSIZE(kSupportedSignatureSchemes));
    for (int i = 0; i < ABSL_ARRAYSIZE(kSupportedSignatureSchemes); ++i) {
      ASSERT_TRUE(supported_signature_schemes_
                      .emplace(kSupportedSignatureSchemes[i],
                               kTranslatedSignatureSchemes[i])
                      .second);
    }
    for (int i = 0; i < SignatureScheme_ARRAYSIZE; ++i) {
      if (SignatureScheme_IsValid(i)) {
        SignatureScheme scheme = static_cast<SignatureScheme>(i);
        if (!supported_signature_schemes_.contains(scheme)) {
          unsupported_signature_schemes_.push_back(scheme);
        }
      }
    }

    plaintext_ =
        std::vector<uint8_t>(reinterpret_cast<const uint8_t *>(kSecretMessage),
                             reinterpret_cast<const uint8_t *>(kSecretMessage) +
                                 sizeof(kSecretMessage));
  }

  StatusOr<bssl::UniquePtr<RSA>> CreateRsaPublicKey(int number_of_bits) {
    bssl::UniquePtr<RSA> rsa(RSA_new());
    bssl::UniquePtr<BIGNUM> e(BN_new());

    if (BN_set_word(e.get(), RSA_F4) != 1) {
      return Status(absl::StatusCode::kInternal, BsslLastErrorString());
    }
    if (RSA_generate_key_ex(rsa.get(), number_of_bits, e.get(),
                            /*cb=*/nullptr) != 1) {
      return Status(absl::StatusCode::kInternal, BsslLastErrorString());
    }
    return std::move(rsa);
  }

  absl::flat_hash_map<AsymmetricEncryptionScheme, uint8_t>
      supported_encryption_schemes_;
  absl::flat_hash_map<SignatureScheme, uint8_t> supported_signature_schemes_;

  std::vector<AsymmetricEncryptionScheme> unsupported_encryption_schemes_;
  std::vector<SignatureScheme> unsupported_signature_schemes_;

  std::vector<uint8_t> plaintext_;
};

TEST_F(PceUtilTest, AsymmetricEncryptionSchemeToPceCryptoSuiteSupported) {
  for (const auto &pair : supported_encryption_schemes_) {
    EXPECT_THAT(AsymmetricEncryptionSchemeToPceCryptoSuite(pair.first),
                Optional(pair.second));
  }
}

TEST_F(PceUtilTest, AsymmetricEncryptionSchemeToPceCryptoSuiteUnsupported) {
  for (AsymmetricEncryptionScheme scheme : unsupported_encryption_schemes_) {
    EXPECT_EQ(AsymmetricEncryptionSchemeToPceCryptoSuite(scheme),
              absl::nullopt);
  }
}

TEST_F(PceUtilTest, PceCryptoSuiteToAsymmetricEncryptionSchemeSupported) {
  for (const auto &pair : supported_encryption_schemes_) {
    EXPECT_EQ(PceCryptoSuiteToAsymmetricEncryptionScheme(pair.second),
              pair.first);
  }
}

TEST_F(PceUtilTest, PceCryptoSuiteToAsymmetricEncryptionSchemeUnsupported) {
  EXPECT_EQ(PceCryptoSuiteToAsymmetricEncryptionScheme(kBadPceCryptoSuite),
            UNKNOWN_ASYMMETRIC_ENCRYPTION_SCHEME);
}

TEST_F(PceUtilTest, GetEncryptedDataSizeSupported) {
  EXPECT_THAT(GetEncryptedDataSize(AsymmetricEncryptionScheme::RSA2048_OAEP),
              IsOkAndHolds(2048 / 8));
  EXPECT_THAT(GetEncryptedDataSize(AsymmetricEncryptionScheme::RSA3072_OAEP),
              IsOkAndHolds(3072 / 8));
}

TEST_F(PceUtilTest, GetEncryptedDataSizeInvalidInput) {
  EXPECT_THAT(
      GetEncryptedDataSize(
          AsymmetricEncryptionScheme::UNKNOWN_ASYMMETRIC_ENCRYPTION_SCHEME),
      StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(GetEncryptedDataSize((AsymmetricEncryptionScheme)-1234),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(PceUtilTest, SignatureSchemeToPceSignatureSchemeSupported) {
  for (const auto &pair : supported_signature_schemes_) {
    EXPECT_THAT(SignatureSchemeToPceSignatureScheme(pair.first),
                Optional(pair.second));
  }
}

TEST_F(PceUtilTest, SignatureSchemeToPceSignatureSchemeUnsupported) {
  for (SignatureScheme scheme : unsupported_signature_schemes_) {
    EXPECT_EQ(SignatureSchemeToPceSignatureScheme(scheme), absl::nullopt);
  }
}

TEST_F(PceUtilTest, PceSignatureSchemeToSignatureSchemeSupported) {
  for (const auto &pair : supported_signature_schemes_) {
    EXPECT_EQ(PceSignatureSchemeToSignatureScheme(pair.second), pair.first);
  }
}

TEST_F(PceUtilTest, PceSignatureSchemeToSignatureSchemeUnsupported) {
  EXPECT_EQ(PceSignatureSchemeToSignatureScheme(kBadPceSignatureScheme),
            UNKNOWN_SIGNATURE_SCHEME);
}

TEST_F(PceUtilTest, CreateSignatureFromPckEcdasP256Sha256SignatureSuccess) {
  EXPECT_THAT(
      CreateSignatureFromPckEcdsaP256Sha256Signature(PckEcdsaP256Signature()),
      IsOkAndHolds(EqualsProto(EcdsaP256Signature())));
}

TEST_F(
    PceUtilTest,
    CreateSignatureFromPckEcdasP256Sha256SignatureFailsWithInvalidSignature) {
  const std::string kBadSignature = "signature";
  EXPECT_THAT(
      CreateSignatureFromPckEcdsaP256Sha256Signature(kBadSignature),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Signature is the wrong size for ECDSA-P256-SHA256: ",
                       kBadSignature.size(), " (expected ",
                       kEcdsaP256SignatureSize, ")")));
}

TEST_F(PceUtilTest, ParseRsa3072PublicKeyInvalidSize) {
  std::vector<uint8_t> public_key(0);
  ASSERT_THAT(ParseRsa3072PublicKey(absl::MakeSpan(public_key)),
              StatusIs(error::INVALID_ARGUMENT));
}

// Verify that an RSA public key serialized according to what is expected by the
// PCE can be parsed and restored to an RSA key, and that its exponent and
// modulus are as expected.
TEST_F(PceUtilTest, ParseRsa3072PublicKeySuccess) {
  std::string modulus = absl::HexStringToBytes(kModulusBigEndianHex);
  std::string exponent = absl::HexStringToBytes(kExponentBigEndianHex);

  std::vector<uint8_t> public_key;
  public_key.insert(public_key.end(), modulus.cbegin(), modulus.cend());
  public_key.insert(public_key.end(), exponent.cbegin(), exponent.cend());

  auto result = ParseRsa3072PublicKey(absl::MakeSpan(public_key));
  ASYLO_ASSERT_OK(result);

  bssl::UniquePtr<RSA> rsa = std::move(result).value();

  EXPECT_EQ(RSA_size(rsa.get()), modulus.size());

  const BIGNUM *n;
  const BIGNUM *e;

  // The private exponent, d, is not set for a public key.
  RSA_get0_key(rsa.get(), &n, &e, /*out_d=*/nullptr);

  // Compare against expected public exponent.
  EXPECT_EQ(BN_is_word(e, RSA_F4), 1);

  bssl::UniquePtr<BIGNUM> expected_n(BN_new());
  BN_bin2bn(reinterpret_cast<const uint8_t *>(modulus.data()), modulus.size(),
            expected_n.get());

  // Compare against expected modulus.
  EXPECT_EQ(BN_cmp(n, expected_n.get()), 0);
}

// Verify that an RSA public key can be serialized, and the serialization result
// contains correct modulus and exponent data in expected format.
TEST_F(PceUtilTest, SerializeRsa3072PublicKeySuccess) {
  bssl::UniquePtr<RSA> rsa(RSA_new());
  ASYLO_ASSERT_OK_AND_ASSIGN(rsa, CreateRsaPublicKey(/*number_of_bits=*/3072));

  auto result = SerializeRsa3072PublicKey(rsa.get());
  ASYLO_ASSERT_OK(result);
  std::vector<uint8_t> serialized_key = std::move(result).value();
  ASSERT_THAT(serialized_key,
              SizeIs(RSA_size(rsa.get()) + kRsa3072SerializedExponentSize));

  const BIGNUM *expected_n;
  const BIGNUM *expected_e;

  // The private exponent, d, is not set for a public key.
  RSA_get0_key(rsa.get(), &expected_n, &expected_e, /*out_d=*/nullptr);

  // Verify that both modulus and exponent are correct.
  bssl::UniquePtr<BIGNUM> actual_n(BN_new());
  BN_bin2bn(serialized_key.data(), RSA_size(rsa.get()), actual_n.get());
  EXPECT_EQ(BN_cmp(actual_n.get(), expected_n), 0);

  bssl::UniquePtr<BIGNUM> actual_e(BN_new());
  BN_bin2bn(serialized_key.data() + RSA_size(rsa.get()),
            kRsa3072SerializedExponentSize, actual_e.get());
  EXPECT_EQ(BN_cmp(actual_e.get(), expected_e), 0);
}

TEST_F(PceUtilTest, SerializePpidekWithDecryptionKeyFails) {
  AsymmetricEncryptionKeyProto ppidek = Rsa3072PublicKeyProto();
  ppidek.set_key_type(AsymmetricEncryptionKeyProto::DECRYPTION_KEY);

  EXPECT_THAT(SerializePpidek(ppidek),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       "PPIDEK must be an encryption key"));
}

TEST_F(PceUtilTest, SerializePpidekWithUnsupportedEncryptionSchemeFails) {
  AsymmetricEncryptionKeyProto ppidek = Rsa3072PublicKeyProto();
  ppidek.set_encryption_scheme(AsymmetricEncryptionScheme::RSA2048_OAEP);

  EXPECT_THAT(SerializePpidek(ppidek),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       "Unsupported encryption scheme: RSA2048_OAEP"));
}

TEST_F(PceUtilTest, SerializePpidekWithUnsupportedKeyEncodingFails) {
  AsymmetricEncryptionKeyProto ppidek = Rsa3072PublicKeyProto();
  ppidek.set_encoding(AsymmetricKeyEncoding::UNKNOWN_ASYMMETRIC_KEY_ENCODING);

  EXPECT_THAT(
      SerializePpidek(ppidek),
      StatusIs(absl::StatusCode::kInvalidArgument,
               "Unsupported key encoding: UNKNOWN_ASYMMETRIC_KEY_ENCODING"));
}

TEST_F(PceUtilTest, SerializePpidekWithBadKeyFails) {
  AsymmetricEncryptionKeyProto ppidek = Rsa3072PublicKeyProto();
  ppidek.set_key("Not really a key");

  EXPECT_THAT(SerializePpidek(ppidek), Not(IsOk()));
}

TEST_F(PceUtilTest, SerializePpidekRsa3072Success) {
  EXPECT_THAT(SerializePpidek(Rsa3072PublicKeyProto()),
              IsOkAndHolds(EqualsHexBytes(kSerializedRsa3072PublicKeyHex)));
}

// Verify that an RSA public key can be serialized and then restored, and that
// the original key can decrypt a message encrypted by the restored key.
TEST_F(PceUtilTest, ParseRsa3072PublicKeyRestoreFromSerializedKey) {
  bssl::UniquePtr<RSA> rsa1(RSA_new());
  ASYLO_ASSERT_OK_AND_ASSIGN(rsa1, CreateRsaPublicKey(/*number_of_bits=*/3072));

  auto result1 = SerializeRsa3072PublicKey(rsa1.get());
  ASYLO_ASSERT_OK(result1);

  std::vector<uint8_t> serialized_key = std::move(result1).value();

  auto result2 = ParseRsa3072PublicKey(absl::MakeSpan(serialized_key));
  ASYLO_ASSERT_OK(result2);

  bssl::UniquePtr<RSA> rsa2(std::move(result2).value());

  // Verify that both keys have the same modulus size.
  EXPECT_EQ(RSA_size(rsa2.get()), RSA_size(rsa1.get()));

  // Verify that the original key can decrypt a message encrypted by the
  // restored key.
  std::vector<uint8_t> ciphertext(RSA_size(rsa1.get()));
  size_t out_len;
  ASSERT_EQ(
      RSA_encrypt(rsa2.get(), &out_len, ciphertext.data(), ciphertext.size(),
                  plaintext_.data(), plaintext_.size(), RSA_PKCS1_OAEP_PADDING),
      1)
      << BsslLastErrorString();
  ciphertext.resize(out_len);

  std::vector<uint8_t> decrypted(RSA_size(rsa2.get()));
  ASSERT_EQ(
      RSA_decrypt(rsa1.get(), &out_len, decrypted.data(), decrypted.size(),
                  ciphertext.data(), ciphertext.size(), RSA_PKCS1_OAEP_PADDING),
      1)
      << BsslLastErrorString();
  decrypted.resize(out_len);

  EXPECT_EQ(decrypted, plaintext_);
}

TEST_F(PceUtilTest, CreateReportdataForGetPceInfoSuccess) {
  Reportdata expected_reportdata;
  ASYLO_ASSERT_OK(SetTrivialObjectFromBinaryString(
      absl::HexStringToBytes(kExpectedReportdata), &expected_reportdata.data));

  AsymmetricEncryptionKeyProto ppidek = Rsa3072PublicKeyProto();
  Reportdata reportdata;
  ASYLO_ASSERT_OK_AND_ASSIGN(reportdata, CreateReportdataForGetPceInfo(ppidek));

  EXPECT_EQ(reportdata.data, expected_reportdata.data);
}

TEST_F(PceUtilTest,
       CreateReportdataForGetPceInfoInvalidAsymmetricEncryptionSchemeFails) {
  AsymmetricEncryptionKeyProto ppidek = Rsa3072PublicKeyProto();
  ppidek.set_encryption_scheme(AsymmetricEncryptionScheme::RSA2048_OAEP);

  EXPECT_THAT(
      CreateReportdataForGetPceInfo(ppidek),
      StatusIs(absl::StatusCode::kInvalidArgument,
               absl::StrCat("Unsupported encryption scheme: ",
                            ProtoEnumValueName(
                                AsymmetricEncryptionScheme::RSA2048_OAEP))));
}

TEST_F(PceUtilTest, CreateReportdataForGetPceInfoInvalidKeyTypeFails) {
  AsymmetricEncryptionKeyProto ppidek = Rsa3072PublicKeyProto();
  ppidek.set_key_type(AsymmetricEncryptionKeyProto::DECRYPTION_KEY);

  EXPECT_THAT(CreateReportdataForGetPceInfo(ppidek),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       "PPIDEK must be an encryption key"));
}

TEST_F(PceUtilTest, CreateReportdataForGetPceInfoInvalidEncodingFails) {
  AsymmetricEncryptionKeyProto ppidek = Rsa3072PublicKeyProto();
  ppidek.set_encoding(AsymmetricKeyEncoding::UNKNOWN_ASYMMETRIC_KEY_ENCODING);

  EXPECT_THAT(
      CreateReportdataForGetPceInfo(ppidek),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat(
              "Unsupported key encoding: ",
              ProtoEnumValueName(
                  AsymmetricKeyEncoding::UNKNOWN_ASYMMETRIC_KEY_ENCODING))));
}

}  // namespace
}  // namespace sgx
}  // namespace asylo
