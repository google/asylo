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

namespace asylo {
namespace {

using ::testing::Eq;
using ::testing::Test;

constexpr char kPlaintext[] = "secret message";

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

constexpr uint8_t kBadKey[] = "bad key";

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

TEST(RsaOaepEncryptionKeyTest, TestCreateFromPemSerializationSuccess) {
  std::unique_ptr<RsaOaepEncryptionKey> encryption_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      encryption_key,
      RsaOaepEncryptionKey::CreateFromPem(kRsa3072PublicKeyPem));
  std::vector<uint8_t> ciphertext;
  ASYLO_ASSERT_OK(encryption_key->Encrypt(kPlaintext, &ciphertext));
}

TEST(RsaOaepEncryptionKeyTest, TestGetAsymmetricEncryptionKeySchemeOaep3072) {
  std::unique_ptr<RsaOaepEncryptionKey> encryption_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      encryption_key,
      RsaOaepEncryptionKey::CreateFromPem(kRsa3072PublicKeyPem));
  EXPECT_THAT(RSA_bits(encryption_key->GetRsaPublicKey()), Eq(3072));
  EXPECT_THAT(encryption_key->GetEncryptionScheme(),
              Eq(AsymmetricEncryptionScheme::RSA3072_OAEP));
}

TEST(RsaOaepEncryptionKeyTest, TestGetAsymmetricEncryptionKeySchemeOaep2048) {
  std::unique_ptr<RsaOaepEncryptionKey> encryption_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      encryption_key,
      RsaOaepEncryptionKey::CreateFromPem(kRsa2048PublicKeyPem));
  EXPECT_THAT(RSA_bits(encryption_key->GetRsaPublicKey()), Eq(2048));
  EXPECT_THAT(encryption_key->GetEncryptionScheme(),
              Eq(AsymmetricEncryptionScheme::RSA2048_OAEP));
}

TEST(RsaOaepEncryptionKeyTest,
     TestCreateAsymmetricEncryptionKeyWithInvalidSizeFails) {
  EXPECT_THAT(
      RsaOaepEncryptionKey::CreateFromPem(kRsa1024PublicKeyPem).status(),
      StatusIs(error::GoogleError::INVALID_ARGUMENT, "Invalid key size: 1024"));
}

TEST(RsaOaepEncryptionKeyTest, TestCreateFromInvalidPemSerializationFails) {
  EXPECT_THAT(RsaOaepEncryptionKey::CreateFromPem(kBadPublicKeyPem).status(),
              StatusIs(error::GoogleError::INTERNAL));
}

TEST(RsaOaepEncryptionKeyTest, TestDecryptInvalidInputFails) {
  std::unique_ptr<AsymmetricDecryptionKey> decryption_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      decryption_key, RsaOaepDecryptionKey::CreateRsa3072OaepDecryptionKey());

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

TEST(RsaOaepEncryptionKeyTest, TestEncryptDecryptSuccess) {
  std::unique_ptr<AsymmetricDecryptionKey> decryption_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      decryption_key, RsaOaepDecryptionKey::CreateRsa3072OaepDecryptionKey());

  std::unique_ptr<AsymmetricEncryptionKey> encryption_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(encryption_key,
                             decryption_key->GetEncryptionKey());

  VerifyEncryptionDecryptionSuccess(*encryption_key, *decryption_key);
}

TEST(RsaOaepEncryptionKeyTest, TestEncryptionKeySerializeAndRestoreSuccess) {
  std::unique_ptr<AsymmetricDecryptionKey> decryption_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      decryption_key, RsaOaepDecryptionKey::CreateRsa3072OaepDecryptionKey());

  std::unique_ptr<AsymmetricEncryptionKey> encryption_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(encryption_key,
                             decryption_key->GetEncryptionKey());

  std::string serialized_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(serialized_key, encryption_key->SerializeToDer());
  std::unique_ptr<AsymmetricEncryptionKey> restored_encryption_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      restored_encryption_key,
      RsaOaepEncryptionKey::CreateFromDer(serialized_key));

  VerifyEncryptionDecryptionSuccess(*restored_encryption_key, *decryption_key);
}

TEST(RsaOaepEncryptionKeyTest, TestDecryptionKeySerializeAndRestoreSuccess) {
  std::unique_ptr<AsymmetricDecryptionKey> decryption_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      decryption_key, RsaOaepDecryptionKey::CreateRsa3072OaepDecryptionKey());

  std::unique_ptr<AsymmetricEncryptionKey> encryption_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(encryption_key,
                             decryption_key->GetEncryptionKey());

  CleansingVector<uint8_t> serialized_key;
  ASYLO_ASSERT_OK(decryption_key->SerializeToDer(&serialized_key));
  std::unique_ptr<AsymmetricDecryptionKey> restored_decryption_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      restored_decryption_key,
      RsaOaepDecryptionKey::CreateFromDer(
          {serialized_key.data(), serialized_key.size()}));

  VerifyEncryptionDecryptionSuccess(*encryption_key, *restored_decryption_key);
}

TEST(RsaOaepEncryptionKeyTest, TestCreateFromInvalidDerSerializationFails) {
  std::vector<uint8_t> serialized_key(kBadKey, kBadKey + sizeof(kBadKey));
  EXPECT_THAT(RsaOaepDecryptionKey::CreateFromDer(serialized_key).status(),
              StatusIs(error::GoogleError::INTERNAL));
}

TEST(RsaOaepEncryptionKeyTest,
     TestCreateAsymmetricDecryptionKeyWithInvalidKeySizeFails) {
  EXPECT_THAT(
      RsaOaepDecryptionKey::CreateFromDer(
          absl::HexStringToBytes(kRsa1024PrivateKeyDer))
          .status(),
      StatusIs(error::GoogleError::INVALID_ARGUMENT, "Invalid key size: 1024"));
}

}  // namespace
}  // namespace asylo
