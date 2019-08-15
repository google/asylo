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
#include "asylo/crypto/x509_certificate.h"

#include <algorithm>
#include <cctype>
#include <memory>
#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/strings/escaping.h"
#include "asylo/crypto/certificate.pb.h"
#include "asylo/crypto/certificate_interface.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status.h"

namespace asylo {
namespace {

// This root certificate has the same root key as all the other root
// certificates, and the only verification-relevant extension is a CA value of
// true.
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

// The DER-encoded ppublic key in the root certificates and CSRs.
constexpr char kTestRootPublicKeyDerHex[] =
    "3059301306072a8648ce3d020106082a8648ce3d03010703420004eaeda5103e89194f43bf"
    "e0d844f3e79f000957fc3c9237c7ea8ddcd67e22c75cd75119ea9aa02f76cecacbbf1b2fe6"
    "1c69fc9eeada1fe29a567d6ceb468e16bd";

// An intermediate cert signed by the root key. No extensions are set.
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

// A cert signed by the intermediate cert above. No extensions are set.
constexpr char kTestEndUserCertPem[] =
    R"(-----BEGIN CERTIFICATE-----
MIIBsTCCAVcCFANGO/7xEmkKZTrRmnVs6ChLYYbqMAoGCCqGSM49BAMCMFkxCzAJ
BgNVBAYTAlVTMQswCQYDVQQIDAJXQTERMA8GA1UEBwwIS2lya2xhbmQxDjAMBgNV
BAsMBUFzeWxvMRowGAYDVQQDDBFUZXN0IEludGVybWVkaWF0ZTAeFw0xOTA1MDcx
OTM2NDVaFw0xOTA2MDYxOTM2NDVaMF0xCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApX
YXNoaW5ndG9uMREwDwYDVQQHDAhLaXJrbGFuZDEOMAwGA1UECwwFQXN5bG8xFjAU
BgNVBAMMDUVuZCBVc2VyIENlcnQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASQ
k96GaZ45U/PP4xB/b4gIz4Klm9AWrsA0NhWSL9pz+MsSAYkoBIgS1Lc7dlp2nRzW
eYSH07qoYfPYcp4nBQRzMAoGCCqGSM49BAMCA0gAMEUCIQCymQ9ERdjk+DlZ5v3y
kmNQbC8XbmwBZfI6i+2XM1z4tQIgDj+9hkLhd2pCK9XhSwMsPojKiBvU/QLIkCKN
5WFOMbA=
-----END CERTIFICATE-----)";

// An intermediate cert signed by a root key other than the one in the root
// certificates.
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

// A certificate signed using SHA-512 as the digest function, which is currently
// unsupported.
constexpr char kUnsupportedSigAlgCertPem[] =
    R"(-----BEGIN CERTIFICATE-----
MIIBzTCCAXICFA2VFTA4Zr7JFVJCi3pY0SOCCdO9MAoGCCqGSM49BAMEMFQxCzAJ
BgNVBAYTAlVTMQswCQYDVQQIDAJXQTERMA8GA1UEBwwIS2lya2xhbmQxDjAMBgNV
BAsMBUFzeWxvMRUwEwYDVQQDDAxUZXN0IFJvb3QgQ0EwHhcNMTkwNzMwMjIzODE2
WhcNMTkwODI5MjIzODE2WjB9MQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGlu
Z3RvbjERMA8GA1UEBwwIS2lya2xhbmQxDzANBgNVBAoMBkdvb2dsZTEOMAwGA1UE
CwwFQXN5bG8xJTAjBgNVBAMMHEFub3RoZXIgSW50ZXJtZWRpYXRlIENBIENlcnQw
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQAeZRSJGNpEEUsCI09eR7OP9p1RmA+
FP52/K/N11/Lfn1jv7MqiUeQv28Sj+affaL4U5TS+sQggwUQAhLBDyLZMAoGCCqG
SM49BAMEA0kAMEYCIQD2H9OtA3pxRlnVHJGp5R9ap4rnooHbzfgkz8i42jjxVAIh
AK7p2n5Xdcj7lN2fphfi5znlHb/Y+L7Bpdh2ZLawBQUc
-----END CERTIFICATE-----)";

// Other root and intermediate cert for validity checks.

// This root has the same key as the other root, but has a CA extension set to
// false and key usage of "digital signature".
constexpr char kExtensionInvalidRootPem[] =
    R"(-----BEGIN CERTIFICATE-----
MIIB7zCCAZWgAwIBAgIURn/c6qy0oCNFDtuNw64FAvIjWE4wCgYIKoZIzj0EAwIw
aDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAldBMREwDwYDVQQHDAhLaXJrbGFuZDEP
MA0GA1UECgwGR29vZ2xlMQ4wDAYDVQQLDAVBc3lsbzEYMBYGA1UEAwwPVGVzdCBO
byBDQSBSb290MB4XDTE5MDgwODIyMjI0N1oXDTE5MDkwNzIyMjI0N1owaDELMAkG
A1UEBhMCVVMxCzAJBgNVBAgMAldBMREwDwYDVQQHDAhLaXJrbGFuZDEPMA0GA1UE
CgwGR29vZ2xlMQ4wDAYDVQQLDAVBc3lsbzEYMBYGA1UEAwwPVGVzdCBObyBDQSBS
b290MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6u2lED6JGU9Dv+DYRPPnnwAJ
V/w8kjfH6o3c1n4ix1zXURnqmqAvds7Ky78bL+Ycafye6tof4ppWfWzrRo4WvaMd
MBswDAYDVR0TAQH/BAIwADALBgNVHQ8EBAMCB4AwCgYIKoZIzj0EAwIDSAAwRQIh
AOGDEYY4obuB8Cyhtp8vJsufljgQNV5hPaJeIr9fTYhXAiBS44DmVEjX9ZuLnkUO
x6XazQooZOsRK5vPLAjQj0Covw==
-----END CERTIFICATE-----)";

// The root certificate with the same public key, but with the CA extension set
// to true, a pathlength of 1, and key usage for certificate signing.
constexpr char kTestRealCaCertPem[] =
    R"(-----BEGIN CERTIFICATE-----
MIICCzCCAbGgAwIBAgIUF/94/Naw8+Gb8bjA+ya6Zg9YHKswCgYIKoZIzj0EAwIw
cjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCldhc2hpbmd0b24xETAPBgNVBAcMCEtp
cmtsYW5kMQ8wDQYDVQQKDAZHb29nbGUxDjAMBgNVBAsMBUFzeWxvMRowGAYDVQQD
DBFUZXN0IFJlYWwgUm9vdCBDQTAgFw0xOTA3MzAyMjU4MTFaGA8yMjkzMDUxNDIy
NTgxMVowcjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCldhc2hpbmd0b24xETAPBgNV
BAcMCEtpcmtsYW5kMQ8wDQYDVQQKDAZHb29nbGUxDjAMBgNVBAsMBUFzeWxvMRow
GAYDVQQDDBFUZXN0IFJlYWwgUm9vdCBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEH
A0IABOrtpRA+iRlPQ7/g2ETz558ACVf8PJI3x+qN3NZ+Isdc11EZ6pqgL3bOysu/
Gy/mHGn8nuraH+KaVn1s60aOFr2jIzAhMBIGA1UdEwEB/wQIMAYBAf8CAQEwCwYD
VR0PBAQDAgIEMAoGCCqGSM49BAMCA0gAMEUCIA/rSJ6o/oIRuTk1MV0XjlZGF7+N
HQAOOAfPvg/KSecOAiEAx1o+05huNjGLOMl37Ee0Sy1elzyo12WgcVQVbTY47z4=
-----END CERTIFICATE-----)";

// An intermediate certificate which can be verified by the root public key. It
// has a CA:true extension and key usage for certificate signing.
constexpr char kTestRealIntermediateCaCertPem[] =
    R"(-----BEGIN CERTIFICATE-----
MIICqTCCAk+gAwIBAgIUSo/tyfQQ7/ol8IJ26jnsjIo/AM4wCgYIKoZIzj0EAwIw
cjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCldhc2hpbmd0b24xETAPBgNVBAcMCEtp
cmtsYW5kMQ8wDQYDVQQKDAZHb29nbGUxDjAMBgNVBAsMBUFzeWxvMRowGAYDVQQD
DBFUZXN0IFJlYWwgUm9vdCBDQTAeFw0xOTA3MzEyMDU2MTVaFw0xOTA4MzAyMDU2
MTVaMHoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApXYXNoaW5ndG9uMREwDwYDVQQH
DAhLaXJrbGFuZDEPMA0GA1UECgwGR29vZ2xlMQ4wDAYDVQQLDAVBc3lsbzEiMCAG
A1UEAwwZVGVzdCBSZWFsIEludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABAB5lFIkY2kQRSwIjT15Hs4/2nVGYD4U/nb8r83XX8t+fWO/syqJ
R5C/bxKP5p99ovhTlNL6xCCDBRACEsEPItmjgbowgbcwgZkGA1UdIwSBkTCBjqF2
pHQwcjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCldhc2hpbmd0b24xETAPBgNVBAcM
CEtpcmtsYW5kMQ8wDQYDVQQKDAZHb29nbGUxDjAMBgNVBAsMBUFzeWxvMRowGAYD
VQQDDBFUZXN0IFJlYWwgUm9vdCBDQYIUF/94/Naw8+Gb8bjA+ya6Zg9YHKswDAYD
VR0TBAUwAwEB/zALBgNVHQ8EBAMCAgQwCgYIKoZIzj0EAwIDSAAwRQIhAJYMDmCx
ZFiXTso2utX7YgmqWOvy50gwl2Wi7d7DRK6fAiAPaH9cWF3+Tht/BvYOJb/PZRdR
73/w00vfv28TFgppmQ==
-----END CERTIFICATE-----)";

constexpr char kNotACert[] = "c0ff33";

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
using ::testing::Optional;
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

class X509CertificateTest : public Test {
 public:
  X509CertificateTest()
      : root_public_key_(absl::HexStringToBytes(kTestRootPublicKeyDerHex)) {}

  StatusOr<std::unique_ptr<X509Certificate>> CreateX509Cert(
      Certificate::CertificateFormat format, const std::string &data) {
    Certificate cert;
    cert.set_format(format);
    cert.set_data(data);
    return X509Certificate::Create(cert);
  }

  std::string root_public_key_;
};

// Verifies that X509Certificate::Create returns an OK Status with a valid
// PEM-encoded certificate.
TEST_F(X509CertificateTest, CertificateX509CreateValidPem) {
  ASYLO_EXPECT_OK(CreateX509Cert(Certificate::X509_PEM, kTestRootCertPem));
}

// Verifies that X509Certificate::Create returns an OK Status with a valid
// DER-encoded certificate.
TEST_F(X509CertificateTest, CertificateX509CreateValidDer) {
  ASYLO_EXPECT_OK(
      CreateX509Cert(Certificate::X509_DER,
                     absl::HexStringToBytes(kTestIntermediateCertDerHex)));
}

// Verifies that Create fails with an non-X509 certificate format.
TEST_F(X509CertificateTest, CreateFromNonX509CertificateFails) {
  EXPECT_THAT(
      CreateX509Cert(Certificate::UNKNOWN, kOtherIntermediateCertPem).status(),
      StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

// Verifies that Create fails when the data is malformed.
TEST_F(X509CertificateTest, CreateFromMalformedX509CertificateFails) {
  EXPECT_THAT(CreateX509Cert(Certificate::X509_PEM, kNotACert).status(),
              StatusIs(error::GoogleError::INTERNAL));
}

// Verifies that Create followed by ToPemCertificate returns the
// original PEM-encoded certificate.
TEST_F(X509CertificateTest, CreateAndToPemCertificateSuccess) {
  std::unique_ptr<X509Certificate> x509_cert;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      x509_cert, CreateX509Cert(Certificate::X509_PEM, kTestRootCertPem));

  Certificate pem_formatted_cert;
  ASYLO_ASSERT_OK_AND_ASSIGN(pem_formatted_cert, x509_cert->ToPemCertificate());

  EXPECT_THAT(pem_formatted_cert.format(), Eq(Certificate::X509_PEM));
  EXPECT_THAT(pem_formatted_cert.data(),
              EqualIgnoreWhiteSpace(kTestRootCertPem));
}

// Verifies that CertificateSigningRequestToX509Req returns an error with
// malformed data.
TEST_F(X509CertificateTest, CertificateSigningRequestToX509ReqMalformedData) {
  CertificateSigningRequest csr;
  csr.set_format(CertificateSigningRequest::PKCS10_PEM);
  csr.set_data(kNotACert);

  EXPECT_THAT(CertificateSigningRequestToX509Req(csr).status(),
              StatusIs(error::GoogleError::INTERNAL));
}

// Verifies that CertificateSigningRequestToX509Req returns an INVALID_ARGUMENT
// error when the csr has a format other than PKCS10_DER or PKCS10_PEM.
TEST_F(X509CertificateTest, CertificateSigningRequestToX509ReqInvalidFormat) {
  CertificateSigningRequest csr;
  csr.set_format(CertificateSigningRequest::UNKNOWN);
  csr.set_data(kCsrDerHex);

  EXPECT_THAT(CertificateSigningRequestToX509Req(csr).status(),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

// Verifies that CertificateSigningRequestToX509Req then
// X509ReqToDerCertificateSigningRequest returns the same data.
TEST_F(X509CertificateTest,
       CertificateSigningRequestToX509ToDerCertificateSigningRequest) {
  CertificateSigningRequest expected_csr;
  expected_csr.set_format(CertificateSigningRequest::PKCS10_DER);
  expected_csr.set_data(absl::HexStringToBytes(kCsrDerHex));

  bssl::UniquePtr<X509_REQ> x509_req;
  ASYLO_ASSERT_OK_AND_ASSIGN(x509_req,
                             CertificateSigningRequestToX509Req(expected_csr));

  CertificateSigningRequest actual_csr;
  ASYLO_ASSERT_OK_AND_ASSIGN(actual_csr,
                             X509ReqToDerCertificateSigningRequest(*x509_req));
  EXPECT_THAT(actual_csr.format(), Eq(expected_csr.format()));
  EXPECT_THAT(actual_csr.data(), EqualIgnoreWhiteSpace(expected_csr.data()));
}

// Verifies that ExtractPkcs10SubjectKeyDer(csr) returns the correct subject
// key.
TEST_F(X509CertificateTest, ExtractPkcs10SubjectKeyDerCsrSuccess) {
  CertificateSigningRequest csr;
  csr.set_format(CertificateSigningRequest::PKCS10_PEM);
  csr.set_data(kCsrPem);

  EXPECT_THAT(ExtractPkcs10SubjectKeyDer(csr), IsOkAndHolds(root_public_key_));
}

// Verifies that ExtractPkcs10SubjectKeyDer(csr) returns an error with malformed
// data.
TEST_F(X509CertificateTest, ExtractPkcs10SubjectKeyDerCsrMalformedData) {
  CertificateSigningRequest csr;
  csr.set_format(CertificateSigningRequest::PKCS10_DER);
  csr.set_data(kNotACert);

  EXPECT_THAT(ExtractPkcs10SubjectKeyDer(csr).status(),
              StatusIs(error::GoogleError::INTERNAL));
}

// Verifies that ExtractPkcs10SubjectKeyDer(csr) returns an INVALID_ARGUMENT
// error if the format is not PKCS10_DER or PKCS10_PEM.
TEST_F(X509CertificateTest, ExtractPkcs10SubjectKeyDerCsrInvalidFormat) {
  CertificateSigningRequest csr;
  csr.set_format(CertificateSigningRequest::UNKNOWN);
  csr.set_data(kCsrPem);

  EXPECT_THAT(ExtractPkcs10SubjectKeyDer(csr).status(),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

// Verifies that a certificate signed by the signing-key counterpart to the
// public key is verified by VerifyCertificate.
TEST_F(X509CertificateTest, VerifyCertificateSucceeds) {
  std::unique_ptr<CertificateInterface> x509_root;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      x509_root, CreateX509Cert(Certificate::X509_PEM, kTestRootCertPem));

  std::unique_ptr<CertificateInterface> x509_intermediate;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      x509_intermediate,
      CreateX509Cert(Certificate::X509_DER,
                     absl::HexStringToBytes(kTestIntermediateCertDerHex)));

  VerificationConfig config(/*all_fields=*/true);
  ASYLO_EXPECT_OK(x509_intermediate->Verify(*x509_root, config));
}

// Verifies that a certificate signed by a different signing key than the
// counterpart to the given public key fails to verify the certificate.
TEST_F(X509CertificateTest, VerifyCertificateFailsWithDifferentIssuer) {
  std::unique_ptr<CertificateInterface> x509_root;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      x509_root, CreateX509Cert(Certificate::X509_PEM, kTestRootCertPem));

  std::unique_ptr<CertificateInterface> x509_intermediate;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      x509_intermediate,
      CreateX509Cert(Certificate::X509_PEM, kOtherIntermediateCertPem));

  VerificationConfig config = VerificationConfig();
  EXPECT_THAT(x509_intermediate->Verify(*x509_root, config),
              StatusIs(error::GoogleError::UNAUTHENTICATED));
}

// Verifies that Verify returns an UNAUTHENTICATED error when the issuer_ca
// check is required but fails.
TEST_F(X509CertificateTest, VerifyCertificateFailedIsCaCheck) {
  std::unique_ptr<CertificateInterface> x509_root;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      x509_root,
      CreateX509Cert(Certificate::X509_PEM, kExtensionInvalidRootPem));

  std::unique_ptr<CertificateInterface> x509_intermediate;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      x509_intermediate,
      CreateX509Cert(Certificate::X509_PEM, kTestRealIntermediateCaCertPem));

  VerificationConfig config(/*all_fields=*/false);
  config.issuer_ca = true;
  EXPECT_THAT(x509_intermediate->Verify(*x509_root, config),
              StatusIs(error::GoogleError::UNAUTHENTICATED));
}

// Verifies that Verify succeeds with invalid extensions when the issuer_ca
// and key_usage checks are not required.
TEST_F(X509CertificateTest, VerifyCertificateSuccessNoChecks) {
  std::unique_ptr<CertificateInterface> x509_root;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      x509_root,
      CreateX509Cert(Certificate::X509_PEM, kExtensionInvalidRootPem));

  std::unique_ptr<CertificateInterface> x509_intermediate;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      x509_intermediate,
      CreateX509Cert(Certificate::X509_PEM, kTestRealIntermediateCaCertPem));

  VerificationConfig config(/*all_fields=*/false);
  ASYLO_EXPECT_OK(x509_intermediate->Verify(*x509_root, config));
}

// Verifies that Verify succeeds when the issuer_ca check is required and the
// CA extension is not set.
TEST_F(X509CertificateTest, VerifyCertificateSuccessIsCaCheckNoExtension) {
  std::unique_ptr<CertificateInterface> x509_issuer;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      x509_issuer,
      CreateX509Cert(Certificate::X509_DER,
                     absl::HexStringToBytes(kTestIntermediateCertDerHex)));

  std::unique_ptr<CertificateInterface> x509_subject;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      x509_subject, CreateX509Cert(Certificate::X509_PEM, kTestEndUserCertPem));

  VerificationConfig config(/*all_fields=*/false);
  config.issuer_ca = true;
  ASYLO_EXPECT_OK(x509_subject->Verify(*x509_issuer, config));
}

// Verifies that Verify returns an UNAUTHENTICATED error when the key_usage
// check is required but fails.
TEST_F(X509CertificateTest, VerifyCertificateFailedKeyUsageCheck) {
  std::unique_ptr<CertificateInterface> x509_root;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      x509_root,
      CreateX509Cert(Certificate::X509_PEM, kExtensionInvalidRootPem));

  std::unique_ptr<CertificateInterface> x509_intermediate;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      x509_intermediate,
      CreateX509Cert(Certificate::X509_PEM, kTestRealIntermediateCaCertPem));

  VerificationConfig config(/*all_fields=*/false);
  config.issuer_key_usage = true;
  EXPECT_THAT(x509_intermediate->Verify(*x509_root, config),
              StatusIs(error::GoogleError::UNAUTHENTICATED));
}

// Verifies that Verify returns an OK Status when the key_usage check is
// required and the key usage extension is not set.
TEST_F(X509CertificateTest, VerifyCertificateKeyUsageNoExtension) {
  std::unique_ptr<CertificateInterface> x509_issuer;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      x509_issuer,
      CreateX509Cert(Certificate::X509_DER,
                     absl::HexStringToBytes(kTestIntermediateCertDerHex)));

  std::unique_ptr<CertificateInterface> x509_subject;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      x509_subject, CreateX509Cert(Certificate::X509_PEM, kTestEndUserCertPem));

  VerificationConfig config(/*all_fields=*/false);
  config.issuer_key_usage = true;
  ASYLO_EXPECT_OK(x509_subject->Verify(*x509_issuer, config));
}

// Verify success case with additional verification checks.
TEST_F(X509CertificateTest, VerifyCertificateSuccessVerificationConfigChecks) {
  std::unique_ptr<CertificateInterface> real_ca_cert;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      real_ca_cert, CreateX509Cert(Certificate::X509_PEM, kTestRealCaCertPem));

  std::unique_ptr<CertificateInterface> real_intermediate_ca_cert;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      real_intermediate_ca_cert,
      CreateX509Cert(Certificate::X509_PEM, kTestRealIntermediateCaCertPem));

  VerificationConfig config(/*all_fields=*/true);
  ASYLO_EXPECT_OK(real_intermediate_ca_cert->Verify(*real_ca_cert, config));
}

// Verifies that Verify returns an UNIMPLEMENTED error when passed a certificate
// with an unsupported signature algorithm.
TEST_F(X509CertificateTest, VerifyWithUnsupportedSignatureAlgorithmFails) {
  std::unique_ptr<CertificateInterface> root_cert;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      root_cert, CreateX509Cert(Certificate::X509_PEM, kTestRootCertPem));

  std::unique_ptr<CertificateInterface> unsupported_sig_alg_cert;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      unsupported_sig_alg_cert,
      CreateX509Cert(Certificate::X509_PEM, kUnsupportedSigAlgCertPem));

  VerificationConfig config = VerificationConfig();
  EXPECT_THAT(unsupported_sig_alg_cert->Verify(*root_cert, config),
              StatusIs(error::GoogleError::UNIMPLEMENTED));
}

// Verifies that SubjectKeyDer() returns the expected key value.
TEST_F(X509CertificateTest, SubjectKeyDerSucceeds) {
  std::unique_ptr<CertificateInterface> x509;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      x509, CreateX509Cert(Certificate::X509_PEM, kTestRootCertPem));
  EXPECT_THAT(x509->SubjectKeyDer(), IsOkAndHolds(root_public_key_));
}

// Verifies that IsCa() returns an expected true value.
TEST_F(X509CertificateTest, IsCaExtensionTrue) {
  std::unique_ptr<CertificateInterface> x509;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      x509, CreateX509Cert(Certificate::X509_PEM, kTestRealCaCertPem));

  EXPECT_THAT(x509->IsCa(), Optional(true));
}

// Verifies that IsCa() returns an expected false value.
TEST_F(X509CertificateTest, IsCaExtensionFalse) {
  std::unique_ptr<CertificateInterface> x509;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      x509, CreateX509Cert(Certificate::X509_PEM, kExtensionInvalidRootPem));

  EXPECT_THAT(x509->IsCa(), Optional(false));
}

// Verifies that IsCa() returns an expected absl::nullopt value.
TEST_F(X509CertificateTest, IsCaNoExtension) {
  std::unique_ptr<CertificateInterface> x509;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      x509,
      CreateX509Cert(Certificate::X509_DER,
                     absl::HexStringToBytes(kTestIntermediateCertDerHex)));

  EXPECT_THAT(x509->IsCa(), Eq(absl::nullopt));
}

// Verifies that CertPathLength() returns the expected value.
TEST_F(X509CertificateTest, CertPathLengthCorrectValue) {
  std::unique_ptr<CertificateInterface> x509;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      x509, CreateX509Cert(Certificate::X509_PEM, kTestRealCaCertPem));

  EXPECT_THAT(x509->CertPathLength(), Optional(1));
}

// Verifies that CertPathLength() returns an expected absl::nullopt.
TEST_F(X509CertificateTest, CertPathLengthCorrectNullopt) {
  std::unique_ptr<CertificateInterface> x509;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      x509, CreateX509Cert(Certificate::X509_PEM, kTestRootCertPem));

  EXPECT_THAT(x509->CertPathLength(), Eq(absl::nullopt));
}

// Verifies that KeyUsage() returns the expected values.
TEST_F(X509CertificateTest, KeyUsageCorrectValues) {
  std::unique_ptr<CertificateInterface> x509;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      x509, CreateX509Cert(Certificate::X509_PEM, kTestRealCaCertPem));

  absl::optional<KeyUsageInformation> key_usage = x509->KeyUsage();
  ASSERT_TRUE(key_usage.has_value());
  KeyUsageInformation key_usage_values = key_usage.value();
  EXPECT_TRUE(key_usage_values.certificate_signing);
  EXPECT_FALSE(key_usage_values.crl_signing);
  EXPECT_FALSE(key_usage_values.digital_signature);
}

// Verifies that KeyUsage() returns an expected absl::nullopt.
TEST_F(X509CertificateTest, KeyUsageNoExtension) {
  std::unique_ptr<CertificateInterface> x509;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      x509,
      CreateX509Cert(Certificate::X509_DER,
                     absl::HexStringToBytes(kTestIntermediateCertDerHex)));

  EXPECT_THAT(x509->KeyUsage(), Eq(absl::nullopt));
}

}  // namespace
}  // namespace asylo
