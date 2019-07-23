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
#include "asylo/crypto/x509_certificate_util.h"

#include <algorithm>
#include <cctype>
#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/strings/escaping.h"
#include "asylo/crypto/certificate.pb.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status.h"

namespace asylo {
namespace {

constexpr char kTestRootCertPem[] =
    "-----BEGIN CERTIFICATE-----\nMIIB+TCCAaCgAwIBAgIRYXN5bG8gdGVzdCBjZXJ0IDEwC"
    "gYIKoZIzj0EAwIwVDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAldBMREwDwYDVQQHDAhLaXJrbGF"
    "uZDEOMAwGA1UECwwFQXN5bG8xFTATBgNVBAMMDFRlc3QgUm9vdCBDQTAeFw0xOTA1MDMxODEzM"
    "jBaFw0xOTA1MDQxODEzMjBaMFQxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJXQTERMA8GA1UEBww"
    "IS2lya2xhbmQxDjAMBgNVBAsMBUFzeWxvMRUwEwYDVQQDDAxUZXN0IFJvb3QgQ0EwWTATBgcqh"
    "kjOPQIBBggqhkjOPQMBBwNCAATq7aUQPokZT0O/4NhE8+efAAlX/DySN8fqjdzWfiLHXNdRGeq"
    "aoC92zsrLvxsv5hxp/J7q2h/imlZ9bOtGjha9o1MwUTAdBgNVHQ4EFgQUcN3IQ2MRK/eH7KSED"
    "3q+9it1/a0wHwYDVR0jBBgwFoAUcN3IQ2MRK/eH7KSED3q+9it1/a0wDwYDVR0TAQH/BAUwAwE"
    "B/zAKBggqhkjOPQQDAgNHADBEAiAcTIfVdk3xKvgka85I96uGdWSDYWYlShzXaUDB04crYAIgB"
    "tdS1WkwPDgfyWZcUO+ImDG38iEOwuPXSk18GRwMrFY=\n-----END CERTIFICATE-----";

constexpr char kTestRootPublicKeyDerHex[] =
    "3059301306072a8648ce3d020106082a8648ce3d03010703420004eaeda5103e89194f43bf"
    "e0d844f3e79f000957fc3c9237c7ea8ddcd67e22c75cd75119ea9aa02f76cecacbbf1b2fe6"
    "1c69fc9eeada1fe29a567d6ceb468e16bd";

constexpr char kTestIntermediateCertDerHex[] =
    "308201a73082014e02140d9515303866bec91552428b7a58d1238209d3bb300a06082a8648"
    "ce3d0403023054310b3009060355040613025553310b300906035504080c0257413111300f"
    "06035504070c084b69726b6c616e64310e300c060355040b0c054173796c6f311530130603"
    "5504030c0c5465737420526f6f74204341301e170d3139303530373139313134395a170d31"
    "39303630363139313134395a3059310b3009060355040613025553310b300906035504080c"
    "0257413111300f06035504070c084b69726b6c616e64310e300c060355040b0c054173796c"
    "6f311a301806035504030c115465737420496e7465726d6564696174653059301306072a86"
    "48ce3d020106082a8648ce3d030107034200040079945224636910452c088d3d791ece3fda"
    "7546603e14fe76fcafcdd75fcb7e7d63bfb32a894790bf6f128fe69f7da2f85394d2fac420"
    "8305100212c10f22d9300a06082a8648ce3d0403020347003044022018da6c0477107a95fc"
    "742866a01f9c86c9e43792889ff998f7911633feb5adb902200dcedad82ef2fd10f6ad8720"
    "0a918793545d986e6bbbef3ae62f9837954950de";

constexpr char kOtherIntermediateCertPem[] =
    R"(-----BEGIN CERTIFICATE-----
MIICIDCCAcagAwIBAgIRYXN5bG8gdGVzdCBjZXJ0IDEwCgYIKoZIzj0EAwIwZzEL
MAkGA1UEBhMCVVMxEzARBgNVBAgMCldhc2hpbmd0b24xETAPBgNVBAcMCEtpcmts
YW5kMQ4wDAYDVQQLDAVBc3lsbzEgMB4GA1UEAwwXSW52YWxpZCBJbnRlcm1lZGlh
dGUgQ0EwHhcNMTkwNTA3MTkyMDUzWhcNMTkwNTA4MTkyMDUzWjBnMQswCQYDVQQG
EwJVUzETMBEGA1UECAwKV2FzaGluZ3RvbjERMA8GA1UEBwwIS2lya2xhbmQxDjAM
BgNVBAsMBUFzeWxvMSAwHgYDVQQDDBdJbnZhbGlkIEludGVybWVkaWF0ZSBDQTBZ
MBMGByqGSM49AgEGCCqGSM49AwEHA0IABAB5lFIkY2kQRSwIjT15Hs4/2nVGYD4U
/nb8r83XX8t+fWO/syqJR5C/bxKP5p99ovhTlNL6xCCDBRACEsEPItmjUzBRMB0G
A1UdDgQWBBSfHP9sDcdJkKYWtYbhoVCI7vrP5zAfBgNVHSMEGDAWgBSfHP9sDcdJ
kKYWtYbhoVCI7vrP5zAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUC
IG8L4bp5asRJpYU+j7YRcYBYBqZ2gu6giTrW+uLgLsESAiEAlOSvH5aPHvFJI1i2
oCq4WeALVjmSdQsnZr5/efkiSAI=
-----END CERTIFICATE-----)";

constexpr char kUnsupportedSigAlgCertPem[] =
    R"(-----BEGIN CERTIFICATE-----
MIIB4DCCAYegAwIBAgIUM19Uuuf4Q1M+Rc4axkL8C57qtuwwCgYIKoZIzj0EAwQw
RjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCldhc2hpbmd0b24xDzANBgNVBAoMBkNv
ZmZlZTERMA8GA1UECwwIRXNwcmVzc28wHhcNMTkwNzAyMTk1MjM1WhcNMTkwODAx
MTk1MjM1WjBGMQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGluZ3RvbjEPMA0G
A1UECgwGQ29mZmVlMREwDwYDVQQLDAhFc3ByZXNzbzBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABOrtpRA+iRlPQ7/g2ETz558ACVf8PJI3x+qN3NZ+Isdc11EZ6pqg
L3bOysu/Gy/mHGn8nuraH+KaVn1s60aOFr2jUzBRMB0GA1UdDgQWBBRw3chDYxEr
94fspIQPer72K3X9rTAfBgNVHSMEGDAWgBRw3chDYxEr94fspIQPer72K3X9rTAP
BgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMEA0cAMEQCIEigLII+z73mlp3n7kLG
gFUdwCjX4E/PJUF2kHQnhJMTAiAqBuLE2juxSLSV4OHWGIO//6McjDkCmPiqDXBs
ovillA==
-----END CERTIFICATE-----)";

constexpr char kBadData[] = "c0ff33";

// CSRs with the root subject key.

constexpr char kCsrPem[] =
    R"(-----BEGIN CERTIFICATE REQUEST-----
MIH7MIGhAgEAMAAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATq7aUQPokZT0O/
4NhE8+efAAlX/DySN8fqjdzWfiLHXNdRGeqaoC92zsrLvxsv5hxp/J7q2h/imlZ9
bOtGjha9oD8wPQYJKoZIhvcNAQkOMTAwLjAsBgiBQGNrY2VydAQgXZGA1KkHHOtx
boMoQM/3uAjk6cpOLuJpWqOejdt79JowCgYIKoZIzj0EAwIDSQAwRgIhAMUE52Cw
oaGJtGujUxAnJnpORdixQ8zSd2ZGRF/nTVXAAiEAz/Yc1at8SK+kkyU91TSl/4sU
NqE+OQ+u66hUMUKYffc=
-----END CERTIFICATE REQUEST-----)";

constexpr char kCsrDerHex[] =
    "3081fb3081a102010030003059301306072a8648ce3d020106082a8648ce3d030107034200"
    "04eaeda5103e89194f43bfe0d844f3e79f000957fc3c9237c7ea8ddcd67e22c75cd75119ea"
    "9aa02f76cecacbbf1b2fe61c69fc9eeada1fe29a567d6ceb468e16bda03f303d06092a8648"
    "86f70d01090e3130302e302c06088140636b6365727404205d9180d4a9071ceb716e832840"
    "cff7b808e4e9ca4e2ee2695aa39e8ddb7bf49a300a06082a8648ce3d040302034900304602"
    "2100c504e760b0a1a189b46ba3531027267a4e45d8b143ccd2776646445fe74d55c0022100"
    "cff61cd5ab7c48afa493253dd534a5ff8b1436a13e390faeeba8543142987df7";

using ::testing::Eq;
using ::testing::Not;
using ::testing::Test;

MATCHER_P(EqualIgnoreWhiteSpace, expected_arg, "") {
  // Make copies for modification.
  std::string actual = arg;
  std::string expected = expected_arg;

  actual.erase(std::remove_if(actual.begin(), actual.end(),
                              [](unsigned char x) { return std::isspace(x); }),
               actual.end());
  expected.erase(
      std::remove_if(expected.begin(), expected.end(),
                     [](unsigned char x) { return std::isspace(x); }),
      expected.end());

  return actual == expected;
}

class X509CertificateUtilTest : public Test {
 public:
  X509CertificateUtilTest()
      : root_public_key_(absl::HexStringToBytes(kTestRootPublicKeyDerHex)) {}

  std::string root_public_key_;
  X509CertificateUtil util_;
};

// Verifies that CertificateToX509 returns an OK Status with a valid
// PEM-encoded certificate.
TEST_F(X509CertificateUtilTest, CertificateX509ValidPem) {
  Certificate cert;
  cert.set_format(Certificate::X509_PEM);
  cert.set_data(kOtherIntermediateCertPem);

  ASYLO_EXPECT_OK(X509CertificateUtil::CertificateToX509(cert));
}

// Verifies that CertificateToX509 returns an OK Status with a valid
// DER-encoded certificate.
TEST_F(X509CertificateUtilTest, CertificateX509ValidDer) {
  Certificate cert;
  cert.set_format(Certificate::X509_DER);
  cert.set_data(absl::HexStringToBytes(kTestIntermediateCertDerHex));

  ASYLO_EXPECT_OK(X509CertificateUtil::CertificateToX509(cert));
}

// Verifies that CertificateToX509 returns an INVALID_ARGUMENT Status with an
// unsupported certificate type.
TEST_F(X509CertificateUtilTest, CertificateX509UnknownFormat) {
  Certificate cert;
  cert.set_format(Certificate::UNKNOWN);
  cert.set_data(kOtherIntermediateCertPem);

  EXPECT_THAT(X509CertificateUtil::CertificateToX509(cert).status(),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

// Verifies that CertificateToX509 returns a non-OK Status if the certificate
// data is not encoded correctly.
TEST_F(X509CertificateUtilTest, CertificateX509BadData) {
  Certificate cert;
  cert.set_format(Certificate::X509_PEM);
  cert.set_data(kBadData);

  EXPECT_THAT(X509CertificateUtil::CertificateToX509(cert).status(),
              StatusIs(error::GoogleError::INTERNAL));
}

// Verifies that CertificateToX509 followed by X509ToPemCertificate returns the
// original PEM-encoded certificate.
TEST_F(X509CertificateUtilTest,
       CertificateToX509andX509ToPemCertificateSuccess) {
  Certificate cert;
  cert.set_format(Certificate::X509_PEM);
  cert.set_data(kTestRootCertPem);

  bssl::UniquePtr<X509> x509;
  ASYLO_ASSERT_OK_AND_ASSIGN(x509,
                             X509CertificateUtil::CertificateToX509(cert));

  Certificate pem_formatted_cert;
  ASYLO_ASSERT_OK_AND_ASSIGN(pem_formatted_cert,
                             X509CertificateUtil::X509ToPemCertificate(*x509));

  EXPECT_THAT(pem_formatted_cert.format(), Eq(Certificate::X509_PEM));
  EXPECT_THAT(pem_formatted_cert.data(), EqualIgnoreWhiteSpace(cert.data()));
}

// Verifies that CertificateToX509 returns a different PEM-encoding when passed
// an X509 object with a different value.
TEST_F(X509CertificateUtilTest,
       CertificateToX509ModifyX509ToPemCertificateDifferent) {
  Certificate cert;
  cert.set_format(Certificate::X509_PEM);
  cert.set_data(kOtherIntermediateCertPem);

  bssl::UniquePtr<X509> x509;
  ASYLO_ASSERT_OK_AND_ASSIGN(x509,
                             X509CertificateUtil::CertificateToX509(cert));

  Certificate pem_formatted_cert;
  ASYLO_ASSERT_OK_AND_ASSIGN(pem_formatted_cert,
                             X509CertificateUtil::X509ToPemCertificate(*x509));

  EXPECT_THAT(pem_formatted_cert.data(),
              Not(EqualIgnoreWhiteSpace(kTestRootCertPem)));
}

// Verifies that CertificateSigningRequestToX509Req returns an error with
// malformed data.
TEST_F(X509CertificateUtilTest,
       CertificateSigningRequestToX509ReqMalformedData) {
  CertificateSigningRequest csr;
  csr.set_format(CertificateSigningRequest::PKCS10_PEM);
  csr.set_data(kBadData);

  EXPECT_THAT(
      X509CertificateUtil::CertificateSigningRequestToX509Req(csr).status(),
      StatusIs(error::GoogleError::INTERNAL));
}

// Verifies that CertificateSigningRequestToX509Req returns an INVALID_ARGUMENT
// error when the csr has a format other than PKCS10_DER or PKCS10_PEM.
TEST_F(X509CertificateUtilTest,
       CertificateSigningRequestToX509ReqInvalidFormat) {
  CertificateSigningRequest csr;
  csr.set_format(CertificateSigningRequest::UNKNOWN);
  csr.set_data(kCsrDerHex);

  EXPECT_THAT(
      X509CertificateUtil::CertificateSigningRequestToX509Req(csr).status(),
      StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

// Verifies that CertificateSigningRequestToX509Req then
// X509ReqToDerCertificateSigningRequest returns the same data.
TEST_F(X509CertificateUtilTest,
       CertificateSigningRequestToX509ToDerCertificateSigningRequest) {
  CertificateSigningRequest expected_csr;
  expected_csr.set_format(CertificateSigningRequest::PKCS10_DER);
  expected_csr.set_data(absl::HexStringToBytes(kCsrDerHex));

  bssl::UniquePtr<X509_REQ> x509_req;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      x509_req,
      X509CertificateUtil::CertificateSigningRequestToX509Req(expected_csr));

  CertificateSigningRequest actual_csr;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      actual_csr,
      X509CertificateUtil::X509ReqToDerCertificateSigningRequest(*x509_req));
  EXPECT_THAT(actual_csr.format(), Eq(expected_csr.format()));
  EXPECT_THAT(actual_csr.data(), EqualIgnoreWhiteSpace(expected_csr.data()));
}

// Verifies that ExtractSubjectKeyDer(csr) returns the correct subject key.
TEST_F(X509CertificateUtilTest, ExtractSubjectKeyDerCsrSuccess) {
  CertificateSigningRequest csr;
  csr.set_format(CertificateSigningRequest::PKCS10_PEM);
  csr.set_data(kCsrPem);

  EXPECT_THAT(X509CertificateUtil::ExtractSubjectKeyDer(csr),
              IsOkAndHolds(root_public_key_));
}

// Verifies that ExtractSubjectKeyDer(csr) returns an error with malformed data.
TEST_F(X509CertificateUtilTest, ExtractSubjectKeyDerCsrMalformedData) {
  CertificateSigningRequest csr;
  csr.set_format(CertificateSigningRequest::PKCS10_DER);
  csr.set_data(kBadData);

  EXPECT_THAT(X509CertificateUtil::ExtractSubjectKeyDer(csr).status(),
              StatusIs(error::GoogleError::INTERNAL));
}

// Verifies that ExtractSubjectKeyDer(csr) returns an INVALID_ARGUMENT error if
// the format is not PKCS10_DER or PKCS10_PEM.
TEST_F(X509CertificateUtilTest, ExtractSubjectKeyDerCsrInvalidFormat) {
  CertificateSigningRequest csr;
  csr.set_format(CertificateSigningRequest::UNKNOWN);
  csr.set_data(kCsrPem);

  EXPECT_THAT(X509CertificateUtil::ExtractSubjectKeyDer(csr).status(),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

// Verifies that a certificate signed by the signing-key counterpart to the
// public key is verified by VerifyCertificate.
TEST_F(X509CertificateUtilTest, VerifyCertificateSucceeds) {
  Certificate intermediate_cert;
  intermediate_cert.set_format(Certificate::X509_DER);
  intermediate_cert.set_data(
      absl::HexStringToBytes(kTestIntermediateCertDerHex));

  ASYLO_EXPECT_OK(util_.VerifyCertificate(intermediate_cert, root_public_key_));
}

// Verifies that a certificate signed by a different signing key than the
// counterpart to the given public key fails to verify the certificate.
TEST_F(X509CertificateUtilTest, VerifyCertificateFailsWithDifferentPublicKeys) {
  Certificate cert;
  cert.set_format(Certificate::X509_PEM);
  cert.set_data(kOtherIntermediateCertPem);

  EXPECT_THAT(util_.VerifyCertificate(cert, root_public_key_),
              StatusIs(error::GoogleError::INTERNAL));
}

// Verifies that VerifyCertificate fails when the certificate cannot be
// transformed to X.509 certificate.
TEST_F(X509CertificateUtilTest, VerifyCertificateFailsNonX509Certificate) {
  Certificate cert;
  cert.set_format(Certificate::UNKNOWN);
  cert.set_data(kOtherIntermediateCertPem);

  EXPECT_THAT(util_.VerifyCertificate(cert, root_public_key_),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

// Verifies that VerifyCertificate fails when the certificate data is malformed.
TEST_F(X509CertificateUtilTest,
       VerifyCertificateFailsWithMalformedCertificate) {
  Certificate cert;
  cert.set_format(Certificate::X509_PEM);
  cert.set_data(kBadData);

  EXPECT_THAT(util_.VerifyCertificate(cert, root_public_key_),
              StatusIs(error::GoogleError::INTERNAL));
}

// Verifies that VerifyCertificate returns an UNIMPLEMENTED error when passed a
// certificate with an unsupported signature algorithm.
TEST_F(X509CertificateUtilTest, VerifyWithUnsupportedSignatureAlgorithmFails) {
  Certificate cert;
  cert.set_format(Certificate::X509_PEM);
  cert.set_data(kUnsupportedSigAlgCertPem);

  EXPECT_THAT(util_.VerifyCertificate(cert, root_public_key_),
              StatusIs(error::GoogleError::UNIMPLEMENTED));
}

// Verifies that ExtractSubjectKeyDer returns the expected key value.
TEST_F(X509CertificateUtilTest, ExtractPublicKeyFromCertificateSucceeds) {
  Certificate root_cert;
  root_cert.set_format(Certificate::X509_PEM);
  root_cert.set_data(kTestRootCertPem);

  EXPECT_THAT(util_.ExtractSubjectKeyDer(root_cert),
              IsOkAndHolds(root_public_key_));
}

// Verifies that ExtractSubjectKeyDer fails when the certificate cannot be
// transformed to an X.509 certificate.
TEST_F(X509CertificateUtilTest, ExtractPublicKeyFromNonX509CertificateFails) {
  Certificate cert;
  cert.set_format(Certificate::UNKNOWN);
  cert.set_data(kOtherIntermediateCertPem);

  EXPECT_THAT(util_.ExtractSubjectKeyDer(cert).status(),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

// Verifies that ExtractSubjectKeyDer fails when the data is malformed.
TEST_F(X509CertificateUtilTest,
       ExtractPublicKeyFromMalformedX509CertificateFails) {
  Certificate cert;
  cert.set_format(Certificate::X509_PEM);
  cert.set_data(kBadData);

  EXPECT_THAT(util_.ExtractSubjectKeyDer(cert).status(),
              StatusIs(error::GoogleError::INTERNAL));
}

}  // namespace
}  // namespace asylo
