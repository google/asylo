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

#include "asylo/identity/sgx/pce_util.h"

#include <openssl/base.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>

#include <cstdint>
#include <utility>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/base/macros.h"
#include "absl/container/flat_hash_map.h"
#include "absl/strings/escaping.h"
#include "absl/types/optional.h"
#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/util/bssl_util.h"
#include "asylo/crypto/util/bytes.h"
#include "asylo/crypto/util/trivial_object_util.h"
#include "asylo/identity/sgx/identity_key_management_structs.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status_macros.h"
#include "QuoteGeneration/psw/pce_wrapper/inc/sgx_pce.h"

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
    "7d9c51052da08dede50b007ff0c2abcc105761b8252243f3b8f627560401ea970000000000"
    "000000000000000000000000000000000000000000000000000000";

using ::testing::Eq;
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
      return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
    }
    if (RSA_generate_key_ex(rsa.get(), number_of_bits, e.get(),
                            /*cb=*/nullptr) != 1) {
      return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
    }
    return rsa;
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
    EXPECT_THAT(AsymmetricEncryptionSchemeToPceCryptoSuite(scheme),
                Eq(absl::nullopt));
  }
}

TEST_F(PceUtilTest, SignatureSchemeToPceSignatureSchemeSupported) {
  for (const auto &pair : supported_signature_schemes_) {
    EXPECT_THAT(SignatureSchemeToPceSignatureScheme(pair.first),
                Optional(pair.second));
  }
}

TEST_F(PceUtilTest, SignatureSchemeToPceSignatureSchemeUnsupported) {
  for (SignatureScheme scheme : unsupported_signature_schemes_) {
    EXPECT_THAT(SignatureSchemeToPceSignatureScheme(scheme), Eq(absl::nullopt));
  }
}

TEST_F(PceUtilTest, ParseRsa3072PublicKeyInvalidSize) {
  std::vector<uint8_t> public_key(0);
  ASSERT_THAT(ParseRsa3072PublicKey(absl::MakeSpan(public_key)).status(),
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
  ASYLO_ASSERT_OK(result.status());

  bssl::UniquePtr<RSA> rsa = std::move(result).ValueOrDie();

  EXPECT_THAT(RSA_size(rsa.get()), modulus.size());

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
  std::vector<uint8_t> serialized_key = std::move(result).ValueOrDie();
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

// Verify that an RSA public key can be serialized and then restored, and that
// the original key can decrypt a message encrypted by the restored key.
TEST_F(PceUtilTest, ParseRsa3072PublicKeyRestoreFromSerializedKey) {
  bssl::UniquePtr<RSA> rsa1(RSA_new());
  ASYLO_ASSERT_OK_AND_ASSIGN(rsa1, CreateRsaPublicKey(/*number_of_bits=*/3072));

  auto result1 = SerializeRsa3072PublicKey(rsa1.get());
  ASYLO_ASSERT_OK(result1);

  std::vector<uint8_t> serialized_key = std::move(result1).ValueOrDie();

  auto result2 = ParseRsa3072PublicKey(absl::MakeSpan(serialized_key));
  ASYLO_ASSERT_OK(result2);

  bssl::UniquePtr<RSA> rsa2(std::move(result2).ValueOrDie());

  // Verify that both keys have the same modulus size.
  EXPECT_THAT(RSA_size(rsa2.get()), Eq(RSA_size(rsa1.get())));

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

  EXPECT_THAT(decrypted, Eq(plaintext_));
}

TEST_F(PceUtilTest, CreateReportdataForGetPceInfoSuccess) {
  std::string modulus = absl::HexStringToBytes(kModulusBigEndianHex);
  std::string exponent = absl::HexStringToBytes(kExponentBigEndianHex);

  std::vector<uint8_t> public_key;
  public_key.insert(public_key.end(), modulus.cbegin(), modulus.cend());
  public_key.insert(public_key.end(), exponent.cbegin(), exponent.cend());

  bssl::UniquePtr<RSA> rsa;
  ASYLO_ASSERT_OK_AND_ASSIGN(rsa,
                             ParseRsa3072PublicKey(absl::MakeSpan(public_key)));

  Reportdata reportdata;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      reportdata, CreateReportdataForGetPceInfo(
                      AsymmetricEncryptionScheme::RSA3072_OAEP, rsa.get()));

  Reportdata expected_reportdata;
  ASYLO_ASSERT_OK(SetTrivialObjectFromHexString(kExpectedReportdata,
                                                &expected_reportdata.data));
  EXPECT_THAT(reportdata.data, Eq(expected_reportdata.data));
}

TEST_F(PceUtilTest,
       CreateReportdataForGetPceInfoInvalidAsymmetricEncryptionSchemeFails) {
  bssl::UniquePtr<RSA> rsa(RSA_new());
  ASYLO_ASSERT_OK_AND_ASSIGN(rsa, CreateRsaPublicKey(/*number_of_bits=*/3072));

  EXPECT_THAT(
      CreateReportdataForGetPceInfo(AsymmetricEncryptionScheme::RSA2048_OAEP,
                                    rsa.get())
          .status(),
      StatusIs(error::GoogleError::INVALID_ARGUMENT,
               absl::StrCat("Unsupported encryption scheme: ",
                            AsymmetricEncryptionScheme_Name(
                                AsymmetricEncryptionScheme::RSA2048_OAEP))));
}

TEST_F(PceUtilTest, CreateReportdataForGetPceInfoInvalidRsaModulusSizeFails) {
  bssl::UniquePtr<RSA> rsa(RSA_new());
  ASYLO_ASSERT_OK_AND_ASSIGN(rsa, CreateRsaPublicKey(/*number_of_bits=*/2048));

  EXPECT_THAT(
      CreateReportdataForGetPceInfo(AsymmetricEncryptionScheme::RSA3072_OAEP,
                                    rsa.get())
          .status(),
      StatusIs(error::GoogleError::INVALID_ARGUMENT,
               absl::StrCat("Invalid modulus size: ", RSA_size(rsa.get()))));
}

}  // namespace
}  // namespace sgx
}  // namespace asylo
