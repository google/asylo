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

#include "asylo/crypto/rsa_oaep_encryption_key.h"

#include <openssl/base.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>

#include <cstdint>
#include <memory>
#include <string>
#include <type_traits>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/strings/escaping.h"
#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/asymmetric_encryption_key.h"
#include "asylo/crypto/util/bssl_util.h"
#include "asylo/crypto/util/byte_container_util.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/cleansing_types.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"

namespace asylo {
namespace {

using ::testing::ElementsAreArray;
using ::testing::Eq;
using ::testing::NotNull;
using ::testing::Test;

constexpr char kPlaintext[] = "secret message";

constexpr char kRsa2048PublicKeyPem[] =
    R"(-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAraSmrCLtfrx6PegYeGCP
GlsUGraa26UrykBj0Aw88oXpr3TivLoC1w2SQcng0+DKL93dJGqxp1if02YUdc1b
TibUpVc6NqofTXOn68crKeGw8QVh+l5Vtgnr655yzNFJzu6F4bV64KdaZizsAzPR
bd5US+MHlUB8cB18dQUOKxp+Glyi2oaJ9gzX3hr6nBScdwjGXmJFI68zd663CmLq
JH9MvEnvHx8vG9znVVDZH1FmDXoDabt5nBFJUNroQ0q9kyoOGgmR1zkybMMdup92
HvoTOkINnS7okRbynpM/XwC+qCMW+xVoJ1kQrwNeVikds7T9LG010j2RszY/86Z+
LwIDAQAB
-----END PUBLIC KEY-----)";

constexpr char kRsa1024PublicKeyPem[] =
    R"(-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDYnYrGRm3xBDGNiviKgWg7LgNoa
EjkU18VTqQidk2/Fywd2ZM/fk2sKNaY4zy/9RTaLeC8zrErqPoztQ8ETuVfgYZ/+3
j11zrxTT4MUeI4YTtYGP6XYEi2noWbP9Ui1t+r9vvdfuB19JdZCyYjEMHwby4Aifo
iUUOItX7JXuQTSQIDAQAB
-----END PUBLIC KEY-----)";

constexpr char kBadPublicKeyPem[] =
    R"(-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAvxMDugH2cYvUWzjQhSgR
-----END PUBLIC KEY-----)";

constexpr char kRsa1024PrivateKeyDer[] =
    "3082025b02010002818100c537377b28058c788df870bbd59841b3d30fcb0f302c19a3578d"
    "af20f0e204b480c41ecf2b9416ebc77af7e77faef0bf0c9befecbff99ffb9e4e973eaa33c0"
    "ced710ce7dda4c0e55d969d9e04e28899b8cc293b1544b713162bd62e62e66f053fcab65fa"
    "bc5bf814a1cca1b5be2bebddfe826608c632bb20ac9930bda277fa03020301000102818029"
    "75a9b6bcdba9c3c048ddde47118aa274b909bdc829453c870ff4a4aeaf3d40fb1effc11ace"
    "b7a0da9f59d5738cc1f4d0004a4891b537324cfe05a2b96246e2765588348102c5e34c5319"
    "bbce5e977f3aa02e853001f177e3c420af19607dd314188cd7397baa618d54f00a1c6d1227"
    "fc51c3d25f39a6c0acc3871e09035191024100eb663ea5d90113b9818e2d21ed3b762df18e"
    "feb0e5011746b495c0853f337664681de3907ff09c2328aa93e6faa96dd29bbc7654dc5d4f"
    "08dcc2776ab78c18f3024100d679869e1ca3959cbd1e04692081f0b1bb357e406d5fc8ee9f"
    "d8dc698948520a8634b17e82dcaff40aeddf1cd77fe154c342803931b6c3936016b81b0d28"
    "deb10240152705e01f44d281ebdb5bc0ddb167282fb99ab7488cb58bbbf46ced4c459290e9"
    "2e2e61b0ad6d4a578024742ff8038f5641341ce2045c72be6b971176d6d6f302403ec2ed3b"
    "d391a3346cbb1dfb4d81f8d769bb2ba8dad8cec9d588f66703bf6012a8573f219055d83f87"
    "fb37f10eb6e34f949c1f3d9d68a82eb64dafae6ad96ce102400c7105b1974382316747ec39"
    "ad158c6d1a32f623b4eac34ae1118608c22574ec874e9028f956645f9a16300e3bd961cf24"
    "2809db58b848c403a2ab446cac03ef";

// This public key corresponds with kRsa3072PrivateKeyDerBase64
constexpr char kRsa3072PublicKeyPem[] =
    R"(-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAzhyEsC43bxgIYmVMYWXq
C0H0D0o9uYR1nw8SeCmj7ywTfTFkPtkeUFFGhd3pmP+/cJdCNcxlJrBAsnUOBMLW
ZO+pVeeuLLt6CAtohH50mm+x0VE7GkKbaA10yNryBWT1EeeblJ3l5SOT+W7pVp2o
q+MaMGMpJOFrMEjUCFMutdt9uCQlnfDpU297ai/luGrdufRet6Y9CPYINqwdizMI
jYwG8medtD9L2i2GlPKn0aeJpoyXp4W9BKj+DlNcue9VBsa85Bw3Fq/P2f/5gizq
wb0+ucQOUNaWNtp2To1t/I/XpCEXbkuYIyjhrjkLEFS5Lo4yvadjHb72Rm/xosJ9
jDaRc+ySlEmp9kiXEQJsEzhxd16+m/7wufsdgNLSHNoRua+y5KK5oP77OIwkgv01
NWavmYjDLWdZJ3w+dlv/F6HgxmsigZoHz1PfesgDfTQ6pZPTGopavgVf0twU93Nd
I7mFs4MtE8RKDJgiyGm29vGqQ+cX8ubGrQXTM4soVd/TAgMBAAE=
-----END PUBLIC KEY-----)";

constexpr char kRsa3072PublicKeyDer[] =
    "MIIBigKCAYEAzhyEsC43bxgIYmVMYWXqC0H0D0o9uYR1nw8SeCmj7ywTfTFkPtkeUFFGhd3pmP"
    "+/cJdCNcxlJrBAsnUOBMLWZO+pVeeuLLt6CAtohH50mm+x0VE7GkKbaA10yNryBWT1EeeblJ3l"
    "5SOT+W7pVp2oq+MaMGMpJOFrMEjUCFMutdt9uCQlnfDpU297ai/luGrdufRet6Y9CPYINqwdiz"
    "MIjYwG8medtD9L2i2GlPKn0aeJpoyXp4W9BKj+DlNcue9VBsa85Bw3Fq/P2f/5gizqwb0+ucQO"
    "UNaWNtp2To1t/I/XpCEXbkuYIyjhrjkLEFS5Lo4yvadjHb72Rm/xosJ9jDaRc+ySlEmp9kiXEQ"
    "JsEzhxd16+m/7wufsdgNLSHNoRua+y5KK5oP77OIwkgv01NWavmYjDLWdZJ3w+dlv/F6Hgxmsi"
    "gZoHz1PfesgDfTQ6pZPTGopavgVf0twU93NdI7mFs4MtE8RKDJgiyGm29vGqQ+cX8ubGrQXTM4"
    "soVd/TAgMBAAE=";

// This private key corresponds with kRsa3072PublicKeyPem above.
constexpr char kRsa3072PrivateKeyDerBase64[] =
    "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";

constexpr uint8_t kBadKey[] = "bad key";

StatusOr<std::unique_ptr<RsaOaepDecryptionKey>> CreateDecryptionKeyFromTestDer(
    HashAlgorithm hash_alg) {
  std::string der;
  if (!absl::Base64Unescape(kRsa3072PrivateKeyDerBase64, &der)) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "Base64 data is not properly encoded");
  }
  std::unique_ptr<RsaOaepDecryptionKey> key;
  ASYLO_ASSIGN_OR_RETURN(key,
                         RsaOaepDecryptionKey::CreateFromDer(der, hash_alg));
  // Explicit move is required by some versions of GCC.
  return std::move(key);
}

void VerifyEncryptionDecryptionSuccess(
    const AsymmetricEncryptionKey &encryption_key,
    const AsymmetricDecryptionKey &decryption_key) {
  std::vector<uint8_t> ciphertext;
  ASYLO_ASSERT_OK(encryption_key.Encrypt(kPlaintext, &ciphertext));
  CleansingVector<uint8_t> plaintext;
  ASYLO_ASSERT_OK(decryption_key.Decrypt(ciphertext, &plaintext));
  std::string decrypted_text =
      CopyToByteContainer<std::string>({plaintext.data(), plaintext.size()});
  EXPECT_THAT(decrypted_text, Eq(kPlaintext));
}

class RsaOaepHashAlgorithmTest
    : public ::testing::TestWithParam<HashAlgorithm> {
 protected:
  void SetUp() override { ASSERT_TRUE(HashAlgorithm_IsValid(GetParam())); }
};

INSTANTIATE_TEST_SUITE_P(
    RsaOaepHashAlgorithmTests, RsaOaepHashAlgorithmTest,
    ::testing::Range(
        static_cast<HashAlgorithm>(HashAlgorithm::UNKNOWN_HASH_ALGORITHM + 1),
        static_cast<HashAlgorithm>(HashAlgorithm_MAX + 1)));

TEST_P(RsaOaepHashAlgorithmTest, EncryptDecryptSuccess) {
  std::unique_ptr<AsymmetricDecryptionKey> decryption_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(decryption_key,
                             CreateDecryptionKeyFromTestDer(GetParam()));
  std::unique_ptr<AsymmetricEncryptionKey> encryption_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(encryption_key,
                             decryption_key->GetEncryptionKey());
  VerifyEncryptionDecryptionSuccess(*encryption_key, *decryption_key);
}

TEST_P(RsaOaepHashAlgorithmTest, EncryptDecryptFailsOnHashMismatch) {
  std::unique_ptr<AsymmetricDecryptionKey> decryption_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(decryption_key,
                             CreateDecryptionKeyFromTestDer(GetParam()));

  HashAlgorithm mismatched_hash_alg = HashAlgorithm::SHA256;
  if (GetParam() == mismatched_hash_alg) {
    mismatched_hash_alg = HashAlgorithm::SHA_1;
  }

  std::unique_ptr<AsymmetricEncryptionKey> encryption_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      encryption_key, RsaOaepEncryptionKey::CreateFromPem(kRsa3072PublicKeyPem,
                                                          mismatched_hash_alg));

  std::vector<uint8_t> ciphertext;
  CleansingVector<uint8_t> plaintext;
  ASYLO_ASSERT_OK(encryption_key->Encrypt(kPlaintext, &ciphertext));
  EXPECT_THAT(decryption_key->Decrypt(ciphertext, &plaintext),
              StatusIs(error::GoogleError::INTERNAL));
}

TEST(RsaOaepEncryptionKeyTest, CreateWithInvalidHashAlgorithmFails) {
  std::string pubkey_der;
  ASSERT_TRUE(absl::Base64Unescape(kRsa3072PublicKeyDer, &pubkey_der));

  EXPECT_THAT(RsaOaepEncryptionKey::CreateFromDer(
                  pubkey_der, HashAlgorithm::UNKNOWN_HASH_ALGORITHM),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
  EXPECT_THAT(RsaOaepEncryptionKey::CreateFromPem(
                  kRsa3072PublicKeyPem, HashAlgorithm::UNKNOWN_HASH_ALGORITHM),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
  EXPECT_THAT(
      CreateDecryptionKeyFromTestDer(HashAlgorithm::UNKNOWN_HASH_ALGORITHM),
      StatusIs(error::GoogleError::INVALID_ARGUMENT));
  EXPECT_THAT(RsaOaepDecryptionKey::CreateRsa3072OaepDecryptionKey(
                  HashAlgorithm::UNKNOWN_HASH_ALGORITHM),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(RsaOaepEncryptionKeyTest, CreateWithBoringSslKeyPointerSuccess) {
  std::unique_ptr<RsaOaepEncryptionKey> encryption_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(encryption_key,
                             RsaOaepEncryptionKey::CreateFromPem(
                                 kRsa3072PublicKeyPem, HashAlgorithm::SHA256));

  bssl::UniquePtr<RSA> rsa(RSAPublicKey_dup(encryption_key->GetRsaPublicKey()));
  ASSERT_THAT(rsa.get(), NotNull());
  EXPECT_THAT(RsaOaepEncryptionKey::Create(
                  std::move(rsa), HashAlgorithm::UNKNOWN_HASH_ALGORITHM),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));

  rsa.reset(RSAPublicKey_dup(encryption_key->GetRsaPublicKey()));
  ASSERT_THAT(rsa.get(), NotNull());
  std::unique_ptr<RsaOaepEncryptionKey> encryption_key_copy;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      encryption_key_copy,
      RsaOaepEncryptionKey::Create(std::move(rsa), HashAlgorithm::SHA256));

  std::string der;
  ASYLO_ASSERT_OK_AND_ASSIGN(der, encryption_key->SerializeToDer());
  EXPECT_THAT(encryption_key_copy->SerializeToDer(), IsOkAndHolds(der));
}

TEST(RsaOaepEncryptionKeyTest, CreateFromPemSerializationSuccess) {
  constexpr auto kHashAlg = HashAlgorithm::SHA256;

  std::unique_ptr<RsaOaepEncryptionKey> encryption_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      encryption_key,
      RsaOaepEncryptionKey::CreateFromPem(kRsa3072PublicKeyPem, kHashAlg));
  std::vector<uint8_t> ciphertext;
  ASYLO_ASSERT_OK(encryption_key->Encrypt(kPlaintext, &ciphertext));

  std::unique_ptr<AsymmetricDecryptionKey> decryption_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(decryption_key,
                             CreateDecryptionKeyFromTestDer(kHashAlg));

  CleansingVector<uint8_t> kDecryptedPlaintext;
  ASYLO_ASSERT_OK(decryption_key->Decrypt(ciphertext, &kDecryptedPlaintext));
  EXPECT_THAT(kDecryptedPlaintext,
              ElementsAreArray(kPlaintext, sizeof(kPlaintext) - 1));
}

TEST(RsaOaepEncryptionKeyTest, GetAsymmetricEncryptionKeySchemeOaep3072) {
  std::unique_ptr<RsaOaepEncryptionKey> encryption_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(encryption_key,
                             RsaOaepEncryptionKey::CreateFromPem(
                                 kRsa3072PublicKeyPem, HashAlgorithm::SHA256));
  EXPECT_THAT(RSA_bits(encryption_key->GetRsaPublicKey()), Eq(3072));
  EXPECT_THAT(encryption_key->GetEncryptionScheme(),
              Eq(AsymmetricEncryptionScheme::RSA3072_OAEP));
}

TEST(RsaOaepEncryptionKeyTest, GetAsymmetricEncryptionKeySchemeOaep2048) {
  std::unique_ptr<RsaOaepEncryptionKey> encryption_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(encryption_key,
                             RsaOaepEncryptionKey::CreateFromPem(
                                 kRsa2048PublicKeyPem, HashAlgorithm::SHA256));
  EXPECT_THAT(RSA_bits(encryption_key->GetRsaPublicKey()), Eq(2048));
  EXPECT_THAT(encryption_key->GetEncryptionScheme(),
              Eq(AsymmetricEncryptionScheme::RSA2048_OAEP));
}

TEST(RsaOaepEncryptionKeyTest,
     TestCreateAsymmetricEncryptionKeyWithInvalidSizeFails) {
  EXPECT_THAT(
      RsaOaepEncryptionKey::CreateFromPem(kRsa1024PublicKeyPem,
                                          HashAlgorithm::SHA_1),
      StatusIs(error::GoogleError::INVALID_ARGUMENT, "Invalid key size: 1024"));
}

TEST(RsaOaepEncryptionKeyTest, CreateFromInvalidPemSerializationFails) {
  EXPECT_THAT(RsaOaepEncryptionKey::CreateFromPem(kBadPublicKeyPem,
                                                  HashAlgorithm::SHA256),
              StatusIs(error::GoogleError::INTERNAL));
}

TEST(RsaOaepEncryptionKeyTest, DecryptInvalidInputFails) {
  std::unique_ptr<AsymmetricDecryptionKey> decryption_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      decryption_key, CreateDecryptionKeyFromTestDer(HashAlgorithm::SHA256));

  std::unique_ptr<AsymmetricEncryptionKey> encryption_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(encryption_key,
                             decryption_key->GetEncryptionKey());
  std::vector<uint8_t> ciphertext;
  ASYLO_ASSERT_OK(encryption_key->Encrypt(kPlaintext, &ciphertext));

  // Flip a bit to make ciphertext invalid.
  ciphertext[0] ^= 1;
  CleansingVector<uint8_t> plaintext;
  EXPECT_THAT(decryption_key->Decrypt(ciphertext, &plaintext),
              StatusIs(error::GoogleError::INTERNAL));
}

TEST(RsaOaepEncryptionKeyTest, CreateRsa3072OaepDecryptionKeySuccess) {
  std::unique_ptr<AsymmetricDecryptionKey> decryption_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      decryption_key, RsaOaepDecryptionKey::CreateRsa3072OaepDecryptionKey(
                          HashAlgorithm::SHA256));
  std::unique_ptr<AsymmetricEncryptionKey> encryption_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(encryption_key,
                             decryption_key->GetEncryptionKey());
  VerifyEncryptionDecryptionSuccess(*encryption_key, *decryption_key);
}

TEST(RsaOaepEncryptionKeyTest, EncryptionKeySerializeAndRestoreSuccess) {
  std::unique_ptr<AsymmetricDecryptionKey> decryption_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      decryption_key, CreateDecryptionKeyFromTestDer(HashAlgorithm::SHA256));

  std::unique_ptr<AsymmetricEncryptionKey> encryption_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(encryption_key,
                             decryption_key->GetEncryptionKey());

  std::string serialized_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(serialized_key, encryption_key->SerializeToDer());
  std::unique_ptr<AsymmetricEncryptionKey> restored_encryption_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(restored_encryption_key,
                             RsaOaepEncryptionKey::CreateFromDer(
                                 serialized_key, HashAlgorithm::SHA256));

  VerifyEncryptionDecryptionSuccess(*restored_encryption_key, *decryption_key);
}

TEST(RsaOaepEncryptionKeyTest, DecryptionKeySerializeAndRestoreSuccess) {
  std::unique_ptr<AsymmetricDecryptionKey> decryption_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      decryption_key, CreateDecryptionKeyFromTestDer(HashAlgorithm::SHA256));

  std::unique_ptr<AsymmetricEncryptionKey> encryption_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(encryption_key,
                             decryption_key->GetEncryptionKey());

  CleansingVector<uint8_t> serialized_key;
  ASYLO_ASSERT_OK(decryption_key->SerializeToDer(&serialized_key));
  std::unique_ptr<AsymmetricDecryptionKey> restored_decryption_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(restored_decryption_key,
                             RsaOaepDecryptionKey::CreateFromDer(
                                 serialized_key, HashAlgorithm::SHA256));

  VerifyEncryptionDecryptionSuccess(*encryption_key, *restored_decryption_key);
}

TEST(RsaOaepEncryptionKeyTest, CreateFromInvalidDerSerializationFails) {
  std::vector<uint8_t> serialized_key(kBadKey, kBadKey + sizeof(kBadKey));
  EXPECT_THAT(
      RsaOaepDecryptionKey::CreateFromDer(serialized_key, HashAlgorithm::SHA_1),
      StatusIs(error::GoogleError::INTERNAL));
}

TEST(RsaOaepEncryptionKeyTest,
     TestCreateAsymmetricDecryptionKeyWithInvalidKeySizeFails) {
  EXPECT_THAT(
      RsaOaepDecryptionKey::CreateFromDer(
          absl::HexStringToBytes(kRsa1024PrivateKeyDer), HashAlgorithm::SHA256),
      StatusIs(error::GoogleError::INVALID_ARGUMENT, "Invalid key size: 1024"));
}

}  // namespace
}  // namespace asylo
