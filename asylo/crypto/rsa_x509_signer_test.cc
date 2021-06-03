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

#include "asylo/crypto/rsa_x509_signer.h"

#include <openssl/evp.h>

#include <cstdint>
#include <memory>
#include <string>

#include "absl/strings/escaping.h"
#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/certificate.pb.h"
#include "asylo/crypto/certificate_interface.h"
#include "asylo/crypto/keys.pb.h"
#include "asylo/crypto/util/byte_container_util.h"
#include "asylo/crypto/x509_certificate.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/test/util/string_matchers.h"
#include "asylo/util/error_codes.h"

namespace asylo {
namespace {

constexpr char kTestRootPublicKeyDerHex[] =
    "3059301306072a8648ce3d020106082a8648ce3d03010703420004eaeda5103e89194f43bf"
    "e0d844f3e79f000957fc3c9237c7ea8ddcd67e22c75cd75119ea9aa02f76cecacbbf1b2fe6"
    "1c69fc9eeada1fe29a567d6ceb468e16bd";

constexpr char kTestSigningKeyPem[] =
    R"(-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAr71dV1Dg5yU1EbzmHyfr8JgoV8xd74kw0PSCAu+RziVwjTpG
+8OcV/7iFVk3/o4RV5pZTRLPLGs3kCvbCjykeklrmpkaWurjLziN3Gep3MQloMA9
jZ0oMhkCHpLkaoTXbHQVnwjnTSNNA2ntD/v5gtMTi9nImObGB7CrSNLp4YnxpUD8
5MrZxdSJr8Srl+20xkU1sEPyEL2C+30qjutknW1yduoZOppG/Kn3x5SudJrmi7iS
psQVsLhkvkd1/0MbX64IKbpdGUkP7HzO4poifXmKwKwoE7yzJwraXvdsAva0zsk3
K5apgCP+yyddSJD718Qsia6cDKuGrHpd4HdcewIDAQABAoIBAEZJ0t9tdcZ9VzB1
AQVNDkz4TopvLtLzaBbq9GUANKzixJV3zZQ8tHdtdjdbq82gPMdw8G6nKz101JBR
OhZqEs7mNqdqvOPINn1YfUS+IW4u9W3J9dSCGuWOow5fagRAhXjXJR6qjPiJOfA3
mZ1fBniQu6yful+NTX8d5iQGV4zg2XVHnEYCcu4BrothSU0Im/k0nIlyfPIUiFka
oLb2PUbY51SraugdZmDGvAP8MGnn6SOy5nJa3h7xfwM/VKZlUz/V5xWZZxhSnxww
dv25S/dK7RTtgKLC+Ta//IFZ7XKsqw1Rzf53KwlEb150bvAWIcqKZOoWkQ5XK81H
V4MhV6ECgYEA3Xm/zleGWvkZWNpiFmQO9L3gtBTxyQDMBNOjXnh1zISwgHdb6m+j
RHx/V7SF8wGvQcZgOW1Wc2FbF0LObj2F41WDWuqhRADypivZlecC2EKMf9HTiXsi
1i1YwtP9tYvKaU5PQHQAQQSGsY3k0MLgUbPF2bwjNHr46biY/AE5p5cCgYEAyyJ4
THXrJFt5AeehbvksmVby4pZye9Z2czOAoXN8Y6jK3uEsmZCi4EvsnqQ5n3UG4cvA
ZkyYzCHRMU70IOYDIZC881/8prFXtTNg+XqhjD7/6HBnMgdlb87UFjOZlTbjf3q5
r+1AwrikDc6McsXJfgdHL9+FH4+9/90S/Q6yrr0CgYEAtHJByEifeveBo1cqm7ui
Q92Aeril1nMDxtr4PDxBHgTuGX0mMngKuf4FctvuVvOEaz7Jn4Bp80/a+7S+pCsU
Lwi5IRYRlmp/SMxpVy0EsFZoSqwWgekFlSMVMoeuKoBexjW7dHQO0OpzI67MQxrD
0U17Yc9bj6Kxsxtn6crFwrkCgYEAwnl6wID4IPOuEwPGSu8lIpzapdGxQxwchMge
8vMUeHkF2IGtaEvPk3s8ytihDidE8nFV/tqAQpZxp4pWMRTklIL0UvBnetM4DBNn
WRFtjk5WRBswwPXRyEw0QhkehXtqLAa7tVEn+gQ5k7pWPh9be1vObGfLFF9SYJ4v
arRinuUCgYAk5krb6GrAwJKWJbdrpXXxImpQhu1bulscSv0MY3C+vbSYDPdZA9OS
ha4neT5oIgt8QLlArA5ht1upi98lpDKV8FdAlvrTzaCijc0uRbFxB47a+823wnom
cqVY/gERtlxncjBb+w3nJ4PjFH8I8r6sPNw0tkXe/vOoMZpy0IQ2iw==
-----END RSA PRIVATE KEY-----)";

// Public key component of kTestSigningKeyPem.
constexpr char kTestSigningKeyPublicDerHex[] =
    "30820122300d06092a864886f70d01010105000382010f003082010a0282010100afbd5d57"
    "50e0e7253511bce61f27ebf0982857cc5def8930d0f48202ef91ce25708d3a46fbc39c57fe"
    "e2155937fe8e11579a594d12cf2c6b37902bdb0a3ca47a496b9a991a5aeae32f388ddc67a9"
    "dcc425a0c03d8d9d283219021e92e46a84d76c74159f08e74d234d0369ed0ffbf982d3138b"
    "d9c898e6c607b0ab48d2e9e189f1a540fce4cad9c5d489afc4ab97edb4c64535b043f210bd"
    "82fb7d2a8eeb649d6d7276ea193a9a46fca9f7c794ae749ae68bb892a6c415b0b864be4775"
    "ff431b5fae0829ba5d19490fec7ccee29a227d798ac0ac2813bcb3270ada5ef76c02f6b4ce"
    "c9372b96a98023fecb275d4890fbd7c42c89ae9c0cab86ac7a5de0775c7b0203010001";

constexpr char kVerifyingCert[] =
    R"(-----BEGIN CERTIFICATE-----
MIIERTCCAy2gAwIBAgIUXDJ9cbadmHmEY/gn2ahwSzwJH6EwDQYJKoZIhvcNAQEL
BQAwgbExCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJXQTERMA8GA1UEBwwIS2lya2xh
bmQxKjAoBgNVBAoMIUZha2UgQ2VydGlmaWNhdGUgRm9yIFRlc3RpbmcgT25seTEq
MCgGA1UECwwhRmFrZSBDZXJ0aWZpY2F0ZSBGb3IgVGVzdGluZyBPbmx5MSowKAYD
VQQDDCFGYWtlIENlcnRpZmljYXRlIEZvciBUZXN0aW5nIE9ubHkwHhcNMjAxMjI5
MTc0NzQwWhcNMjExMjI5MTc0NzQwWjCBsTELMAkGA1UEBhMCVVMxCzAJBgNVBAgM
AldBMREwDwYDVQQHDAhLaXJrbGFuZDEqMCgGA1UECgwhRmFrZSBDZXJ0aWZpY2F0
ZSBGb3IgVGVzdGluZyBPbmx5MSowKAYDVQQLDCFGYWtlIENlcnRpZmljYXRlIEZv
ciBUZXN0aW5nIE9ubHkxKjAoBgNVBAMMIUZha2UgQ2VydGlmaWNhdGUgRm9yIFRl
c3RpbmcgT25seTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK+9XVdQ
4OclNRG85h8n6/CYKFfMXe+JMND0ggLvkc4lcI06RvvDnFf+4hVZN/6OEVeaWU0S
zyxrN5Ar2wo8pHpJa5qZGlrq4y84jdxnqdzEJaDAPY2dKDIZAh6S5GqE12x0FZ8I
500jTQNp7Q/7+YLTE4vZyJjmxgewq0jS6eGJ8aVA/OTK2cXUia/Eq5fttMZFNbBD
8hC9gvt9Ko7rZJ1tcnbqGTqaRvyp98eUrnSa5ou4kqbEFbC4ZL5Hdf9DG1+uCCm6
XRlJD+x8zuKaIn15isCsKBO8sycK2l73bAL2tM7JNyuWqYAj/ssnXUiQ+9fELImu
nAyrhqx6XeB3XHsCAwEAAaNTMFEwHQYDVR0OBBYEFEoLle8Fybij/Vuxq10C/sDc
ZxvbMB8GA1UdIwQYMBaAFEoLle8Fybij/Vuxq10C/sDcZxvbMA8GA1UdEwEB/wQF
MAMBAf8wDQYJKoZIhvcNAQELBQADggEBADZ2zTwJJfHtif6xlj9aE8Jyu9UohilP
E0pcUepP1tT1tZ7NQHpStMoFsFJl4BWZwhR0hXtPy5aaLxDW3hZtAwHH3vnRVnEk
qAnvp1Mz9Ir7QqMXWLvKY5vuKpgeXOHs7P5a5Tm5CHI8odq0yy1xX6km+Dh6VKsY
wppI2UmnGvEbvccVKDMLDW/3CqC3EtMw7KIUKEy020d4MCQ9CjObCCZ2jwyPledA
B8v6Fs1P5rKnPooi6KFNDhH8LAggLfYHpFnt8L1zgAvRvGBXf6gJPgaaV3M2uA7w
uNZQZ2H9Nq5WzIlFDF3bgwUj/U27gJYG6YVHwVvjG0TYtpIfjyj6Gmc=
-----END CERTIFICATE-----)";

class RsaX509SignerTest : public ::testing::Test {
 public:
  void SetUp() override {
    ASYLO_ASSERT_OK_AND_ASSIGN(
        signing_key_,
        RsaX509Signer::CreateFromPem(kTestSigningKeyPem,
                                     RsaX509Signer::RSASSA_PSS_WITH_SHA384));

    // Initialize X509Builder
    static constexpr int kSerialNumberByteSize = 20;
    static const asylo::X509Name *kIssuer = new asylo::X509Name(
        {{asylo::ObjectId::CreateFromShortName("CN").value(),
          "Fake Certificate For Testing Only"},
         {asylo::ObjectId::CreateFromShortName("O").value(),
          "Fake Certificate For Testing Only"},
         {asylo::ObjectId::CreateFromShortName("OU").value(),
          "Fake Certificate For Testing Only"},
         {asylo::ObjectId::CreateFromShortName("L").value(), "Kirkland"},
         {asylo::ObjectId::CreateFromShortName("ST").value(), "WA"},
         {asylo::ObjectId::CreateFromShortName("C").value(), "US"}});
    static const asylo::X509Name *kSubject = new asylo::X509Name(
        {{asylo::ObjectId::CreateFromShortName("CN").value(),
          "Also a Fake Certificate For Testing Only"},
         {asylo::ObjectId::CreateFromShortName("O").value(),
          "Also a Fake Certificate For Testing Only"},
         {asylo::ObjectId::CreateFromShortName("OU").value(),
          "Also a Fake Certificate For Testing Only"},
         {asylo::ObjectId::CreateFromShortName("L").value(), "Kirkland"},
         {asylo::ObjectId::CreateFromShortName("ST").value(), "WA"},
         {asylo::ObjectId::CreateFromShortName("C").value(), "US"}});

    // Set fake serial number.
    uint8_t serial_number_bytes[kSerialNumberByteSize] = {0};
    ASYLO_ASSERT_OK_AND_ASSIGN(
        builder_.serial_number,
        asylo::BignumFromBigEndianBytes(serial_number_bytes));

    // Set fake issuer.
    builder_.issuer = *kIssuer;

    // Set fake validity.
    absl::Time now = absl::Now();
    builder_.validity = {now, now + absl::Hours(24 * 365 * 7)};

    // Set fake subject.
    builder_.subject = *kSubject;

    // Set fake public key info.
    builder_.subject_public_key_der.emplace(
        absl::HexStringToBytes(kTestRootPublicKeyDerHex));
  }

  StatusOr<std::unique_ptr<X509Certificate>> CreateX509Cert(
      Certificate::CertificateFormat format, const std::string &data) {
    Certificate cert;
    cert.set_format(format);
    cert.set_data(data);
    return X509Certificate::Create(cert);
  }

  asylo::X509CertificateBuilder builder_;
  std::unique_ptr<RsaX509Signer> signing_key_;
};

// Verify that an RsaX509Signer created from a PEM-encoded key
// and reserialized to PEM matches the original encoding.
TEST_F(RsaX509SignerTest, CreateAndSerializePemMatchesOriginal) {
  std::unique_ptr<X509Signer> signing_key_pem;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      signing_key_pem,
      RsaX509Signer::CreateFromPem(kTestSigningKeyPem,
                                   RsaX509Signer::RSASSA_PSS_WITH_SHA384));

  CleansingVector<char> serialized_pem;
  ASYLO_ASSERT_OK_AND_ASSIGN(serialized_pem, signing_key_pem->SerializeToPem());

  EXPECT_THAT(CopyToByteContainer<std::string>(serialized_pem),
              EqualIgnoreWhiteSpace(kTestSigningKeyPem));
}

TEST_F(RsaX509SignerTest, SerializePublicKeytoDer) {
  std::unique_ptr<RsaX509Signer> signing_key_pem;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      signing_key_pem,
      RsaX509Signer::CreateFromPem(kTestSigningKeyPem,
                                   RsaX509Signer::RSASSA_PSS_WITH_SHA384));

  std::string der_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(der_key,
                             signing_key_pem->SerializePublicKeyToDer());
  EXPECT_EQ(absl::BytesToHexString(der_key), kTestSigningKeyPublicDerHex);
}

// Verify that the test RsaX509Signer is created with the expected key size.
TEST_F(RsaX509SignerTest, KeySizeInBitsReturns2048ForTestKey) {
  EXPECT_EQ(signing_key_->KeySizeInBits(), 2048);
}

// Verify that an X509Certificate signed by an X509Signer is a valid Certificate
// and can be verified by the issuer certificate.
TEST_F(RsaX509SignerTest, SignX509SucceedsInX509CertificateSignAndBuild) {
  // Create certificate.
  std::unique_ptr<X509Certificate> certificate;
  ASYLO_ASSERT_OK_AND_ASSIGN(certificate, builder_.SignAndBuild(*signing_key_));

  Certificate cert;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      cert, certificate->ToCertificateProto(asylo::Certificate::X509_PEM));
  LOG(INFO) << cert.data();

  // Create verifying certificate.
  std::unique_ptr<CertificateInterface> verifying_x509;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      verifying_x509, CreateX509Cert(Certificate::X509_PEM, kVerifyingCert));

  VerificationConfig config(/*all_fields=*/false);
  ASYLO_EXPECT_OK(certificate->Verify(*verifying_x509, config));
}

}  // namespace
}  // namespace asylo
