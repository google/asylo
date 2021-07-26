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

#include <openssl/base.h>
#include <openssl/bn.h>
#include <openssl/x509.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <memory>
#include <sstream>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "absl/types/optional.h"
#include "absl/types/span.h"
#include "asylo/crypto/asn1.h"
#include "asylo/crypto/bignum_util.h"
#include "asylo/crypto/certificate.pb.h"
#include "asylo/crypto/certificate_interface.h"
#include "asylo/crypto/ecdsa_p256_sha256_signing_key.h"
#include "asylo/crypto/fake_certificate.h"
#include "asylo/crypto/util/byte_container_util.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/test/util/string_matchers.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"

namespace asylo {
namespace {

using ::testing::ElementsAreArray;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::IsEmpty;
using ::testing::Ne;
using ::testing::Not;
using ::testing::Optional;
using ::testing::SizeIs;
using ::testing::StrEq;
using ::testing::Test;

// A private key to use for testing. Unrelated to the keys and certificates in
// the rest of the test data.
constexpr char kTestPrivateKeyDerHex[] =
    "30770201010420cb1bc570d3819aba58f1069e2a8850f40ffdc9f72295f565be845f1efbbe"
    "bb94a00a06082a8648ce3d030107a144034200044af7b0c4b084a83cd7ffb80493cfaf0222"
    "367b617c54c996c5d50a79ee94b150db9f332f628dde57cf0a48111799a01d763b8ebeac0e"
    "3ee99d899bbedd31e22f";

// This root certificate has the same root key as all the other root
// certificates, and the only verification-relevant extension is a CA value of
// true.
constexpr char kTestRootCertPem[] =
    R"(-----BEGIN CERTIFICATE-----
MIICIDCCAcWgAwIBAgIULkih5ZufUjhWlLQoUWwpExC3zwcwCgYIKoZIzj0EAwIw
ZDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCldhc2hpbmd0b24xEDAOBgNVBAcMB1Nl
YXR0bGUxDzANBgNVBAoMBkdvb2dsZTENMAsGA1UECwwEVGVzdDEOMAwGA1UEAwwF
QXN5bG8wIBcNMjAwOTIxMjI1MjEyWhgPMjE1NzA4MTQyMjUyMTJaMGQxCzAJBgNV
BAYTAlVTMRMwEQYDVQQIDApXYXNoaW5ndG9uMRAwDgYDVQQHDAdTZWF0dGxlMQ8w
DQYDVQQKDAZHb29nbGUxDTALBgNVBAsMBFRlc3QxDjAMBgNVBAMMBUFzeWxvMFkw
EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6u2lED6JGU9Dv+DYRPPnnwAJV/w8kjfH
6o3c1n4ix1zXURnqmqAvds7Ky78bL+Ycafye6tof4ppWfWzrRo4WvaNTMFEwHQYD
VR0OBBYEFHDdyENjESv3h+ykhA96vvYrdf2tMB8GA1UdIwQYMBaAFHDdyENjESv3
h+ykhA96vvYrdf2tMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIh
ALrU8G1GlTpoZMkywq37nEkltBwJY5OQhyCKv+Ca0/fLAiEA/vgihzv9O4uVMJeC
7xrH1OhW49CIbzE+CY89+eGjdwY=
-----END CERTIFICATE-----)";

// The DER-encoded public key in the root certificates and CSRs.
constexpr char kTestRootPublicKeyDerHex[] =
    "3059301306072a8648ce3d020106082a8648ce3d03010703420004eaeda5103e89194f43bf"
    "e0d844f3e79f000957fc3c9237c7ea8ddcd67e22c75cd75119ea9aa02f76cecacbbf1b2fe6"
    "1c69fc9eeada1fe29a567d6ceb468e16bd";

// The SHA-1 digest of the public key BIT STRING in kTestRootPublicKeyDerHex.
constexpr char kTestRootPublicKeySha1Hex[] =
    "70ddc84363112bf787eca4840f7abef62b75fdad";

// An intermediate cert signed by the root key. No extensions are set.
constexpr char kTestIntermediateCertDerHex[] =
    "308201c53082016b021426b475554e271a15e4eabc11e5a3251eebbd965b300a06082a8648"
    "ce3d0403023064310b30090603550406130255533113301106035504080c0a57617368696e"
    "67746f6e3110300e06035504070c0753656174746c65310f300d060355040a0c06476f6f67"
    "6c65310d300b060355040b0c0454657374310e300c06035504030c054173796c6f3020170d"
    "3230303932323030313832385a180f32313537303831353030313832385a3064310b300906"
    "03550406130255533113301106035504080c0a57617368696e67746f6e3110300e06035504"
    "070c0753656174746c65310f300d060355040a0c06476f6f676c65310d300b060355040b0c"
    "0454657374310e300c06035504030c054173796c6f3059301306072a8648ce3d020106082a"
    "8648ce3d030107034200040079945224636910452c088d3d791ece3fda7546603e14fe76fc"
    "afcdd75fcb7e7d63bfb32a894790bf6f128fe69f7da2f85394d2fac4208305100212c10f22"
    "d9300a06082a8648ce3d0403020348003045022100c6b838458a48b89838fcac657e870c9d"
    "dff5e5a8fec37bd74955a730d2549ace02204480fab3dccb57175b28985968fcb702cbde18"
    "4a383c60e4094d3641977ee79a";

// Same as kTestIntermediateCertDerHex but PEM-encoded.
constexpr char kTestIntermediateCertPem[] =
    R"(-----BEGIN CERTIFICATE-----
MIIBxTCCAWsCFCa0dVVOJxoV5Oq8EeWjJR7rvZZbMAoGCCqGSM49BAMCMGQxCzAJ
BgNVBAYTAlVTMRMwEQYDVQQIDApXYXNoaW5ndG9uMRAwDgYDVQQHDAdTZWF0dGxl
MQ8wDQYDVQQKDAZHb29nbGUxDTALBgNVBAsMBFRlc3QxDjAMBgNVBAMMBUFzeWxv
MCAXDTIwMDkyMjAwMTgyOFoYDzIxNTcwODE1MDAxODI4WjBkMQswCQYDVQQGEwJV
UzETMBEGA1UECAwKV2FzaGluZ3RvbjEQMA4GA1UEBwwHU2VhdHRsZTEPMA0GA1UE
CgwGR29vZ2xlMQ0wCwYDVQQLDARUZXN0MQ4wDAYDVQQDDAVBc3lsbzBZMBMGByqG
SM49AgEGCCqGSM49AwEHA0IABAB5lFIkY2kQRSwIjT15Hs4/2nVGYD4U/nb8r83X
X8t+fWO/syqJR5C/bxKP5p99ovhTlNL6xCCDBRACEsEPItkwCgYIKoZIzj0EAwID
SAAwRQIhAMa4OEWKSLiYOPysZX6HDJ3f9eWo/sN710lVpzDSVJrOAiBEgPqz3MtX
F1somFlo/LcCy94YSjg8YOQJTTZBl37nmg==
-----END CERTIFICATE-----)";

// A cert signed by kTestIntermediateCertPem. No extensions are set. The
// validity period is not current.
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
MIICqjCCAlGgAwIBAgIUSo/tyfQQ7/ol8IJ26jnsjIo/ANAwCgYIKoZIzj0EAwIw
cjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCldhc2hpbmd0b24xETAPBgNVBAcMCEtp
cmtsYW5kMQ8wDQYDVQQKDAZHb29nbGUxDjAMBgNVBAsMBUFzeWxvMRowGAYDVQQD
DBFUZXN0IFJlYWwgUm9vdCBDQTAgFw0yMDA5MjIwMjEzNDRaGA8yMTU3MDgxNTAy
MTM0NFowejELMAkGA1UEBhMCVVMxEzARBgNVBAgMCldhc2hpbmd0b24xETAPBgNV
BAcMCEtpcmtsYW5kMQ8wDQYDVQQKDAZHb29nbGUxDjAMBgNVBAsMBUFzeWxvMSIw
IAYDVQQDDBlUZXN0IFJlYWwgSW50ZXJtZWRpYXRlIENBMFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAEAHmUUiRjaRBFLAiNPXkezj/adUZgPhT+dvyvzddfy359Y7+z
KolHkL9vEo/mn32i+FOU0vrEIIMFEAISwQ8i2aOBujCBtzCBmQYDVR0jBIGRMIGO
oXakdDByMQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGluZ3RvbjERMA8GA1UE
BwwIS2lya2xhbmQxDzANBgNVBAoMBkdvb2dsZTEOMAwGA1UECwwFQXN5bG8xGjAY
BgNVBAMMEVRlc3QgUmVhbCBSb290IENBghQX/3j81rDz4ZvxuMD7JrpmD1gcqzAM
BgNVHRMEBTADAQH/MAsGA1UdDwQEAwICBDAKBggqhkjOPQQDAgNHADBEAiAW+71+
BkxYHPzSI9LuzJZ6BcdJGGCkRhkMQGek4zE8rwIgUF1aq9kdBzeGDSrNjfZfhGFy
uER4gbhFnSl46j4F1XM=
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

// A fake serial number to be used in certificates.
constexpr int64_t kFakeSerialNumber = 8675309;

MATCHER(Nullopt, negation ? "has a value" : "is equal to absl::nullopt") {
  return !arg.has_value();
}

// Returns an X509CertificateBuilder with all mandatory fields filled, but all
// optional fields set to absl::nullopt and no |other_extensions|.
//
// Uses kFakeSerialNumber for the serial number of the return builder.
X509CertificateBuilder CreateMinimalCertificateBuilder() {
  X509NameEntry issuer_name_entry;
  issuer_name_entry.field = ObjectId::CreateFromLongName("commonName").value();
  issuer_name_entry.value = "Fake CA";

  X509NameEntry subject_name_entry;
  subject_name_entry.field = ObjectId::CreateFromLongName("commonName").value();
  subject_name_entry.value = "Fake leaf certificate";

  X509CertificateBuilder builder;
  builder.version = X509Version::kVersion3;
  builder.serial_number =
      std::move(BignumFromInteger(kFakeSerialNumber)).value();
  builder.issuer.emplace({issuer_name_entry});
  // Truncate the validity periods to seconds to match the precision of ASN.1
  // time structures.
  builder.validity.emplace();
  builder.validity->not_before =
      absl::FromUnixSeconds(absl::ToUnixSeconds(absl::Now()));
  builder.validity->not_after =
      builder.validity->not_before + absl::Hours(24 * 1000);
  builder.subject.emplace({subject_name_entry});
  builder.subject_public_key_der.emplace(
      absl::HexStringToBytes(kTestRootPublicKeyDerHex));
  return builder;
}

X509CsrBuilder CreateMinimalCsrBuilder() {
  X509NameEntry subject_name;
  subject_name.field = ObjectId::CreateFromLongName("commonName").value();
  subject_name.value = "Intermediate CA";

  X509CsrBuilder builder;
  builder.subject.emplace({subject_name});
  builder.key = EcdsaP256Sha256SigningKey::CreateFromDer(
                    absl::HexStringToBytes(kTestPrivateKeyDerHex))
                    .value();
  return builder;
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
  EXPECT_THAT(CreateX509Cert(Certificate::UNKNOWN, kOtherIntermediateCertPem),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

// Verifies that Create fails when the data is malformed.
TEST_F(X509CertificateTest, CreateFromMalformedX509CertificateFails) {
  EXPECT_THAT(CreateX509Cert(Certificate::X509_PEM, kNotACert),
              StatusIs(absl::StatusCode::kInternal));
}

// Verifies that X509Certificate::CreateFromPem returns an OK Status with a
// valid PEM-encoded X.509 string.
TEST_F(X509CertificateTest, CreateFromPemSuccess) {
  ASYLO_EXPECT_OK(X509Certificate::CreateFromPem(kTestRootCertPem));
}

// Verifies that X509Certificate::CreateFromPem returns an error with an invalid
// PEM-encoding.
TEST_F(X509CertificateTest, CreateFromPemFailure) {
  EXPECT_THAT(X509Certificate::CreateFromPem(
                  absl::HexStringToBytes(kTestIntermediateCertDerHex)),
              StatusIs(absl::StatusCode::kInternal));
}
// Verifies that X509Certificate::CreateFromDer returns an OK Status with a
// valid DER-encoded X.509 string.
TEST_F(X509CertificateTest, CreateFromDerSuccess) {
  ASYLO_EXPECT_OK(X509Certificate::CreateFromDer(
      absl::HexStringToBytes(kTestIntermediateCertDerHex)));
}
// Verifies that X509Certificate::CreateFromDer returns an error with an invalid
// DER-encoding.
TEST_F(X509CertificateTest, CreateFromDerFailure) {
  EXPECT_THAT(X509Certificate::CreateFromDer(kTestRootCertPem),
              StatusIs(absl::StatusCode::kInternal));
}

TEST_F(X509CertificateTest, CreateAndToDerCertificateSuccess) {
  std::unique_ptr<X509Certificate> x509_cert;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      x509_cert,
      CreateX509Cert(Certificate::X509_DER,
                     absl::HexStringToBytes(kTestIntermediateCertDerHex)));

  Certificate der_formatted_cert;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      der_formatted_cert, x509_cert->ToCertificateProto(Certificate::X509_DER));

  EXPECT_THAT(der_formatted_cert.format(), Eq(Certificate::X509_DER));
  EXPECT_EQ(der_formatted_cert.data(),
            absl::HexStringToBytes(kTestIntermediateCertDerHex));
}

TEST_F(X509CertificateTest, CreateAndToPemCertificateSuccess) {
  std::unique_ptr<X509Certificate> x509_cert;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      x509_cert, CreateX509Cert(Certificate::X509_PEM, kTestRootCertPem));

  Certificate pem_formatted_cert;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      pem_formatted_cert, x509_cert->ToCertificateProto(Certificate::X509_PEM));

  EXPECT_THAT(pem_formatted_cert.format(), Eq(Certificate::X509_PEM));
  EXPECT_THAT(pem_formatted_cert.data(),
              EqualIgnoreWhiteSpace(kTestRootCertPem));
}

TEST_F(X509CertificateTest, ToCertificateProtoInvalidEncodingFailure) {
  std::unique_ptr<X509Certificate> x509_cert;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      x509_cert,
      CreateX509Cert(Certificate::X509_DER,
                     absl::HexStringToBytes(kTestIntermediateCertDerHex)));

  EXPECT_THAT(x509_cert->ToCertificateProto(
                  Certificate::SGX_ATTESTATION_KEY_CERTIFICATE),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(X509CertificateTest, ToCertificateProtoUnknownFailure) {
  std::unique_ptr<X509Certificate> x509_cert;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      x509_cert,
      CreateX509Cert(Certificate::X509_DER,
                     absl::HexStringToBytes(kTestIntermediateCertDerHex)));

  EXPECT_THAT(x509_cert->ToCertificateProto(Certificate::UNKNOWN),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(X509CertificateTest, EqualsSuccess) {
  std::unique_ptr<X509Certificate> x509_cert_from_der;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      x509_cert_from_der, X509Certificate::CreateFromDer(absl::HexStringToBytes(
                              kTestIntermediateCertDerHex)));

  std::unique_ptr<X509Certificate> x509_cert_from_pem;
  ASYLO_ASSERT_OK_AND_ASSIGN(x509_cert_from_pem, X509Certificate::CreateFromPem(
                                                     kTestIntermediateCertPem));

  EXPECT_TRUE(*x509_cert_from_der == *x509_cert_from_pem);
}

TEST_F(X509CertificateTest, EqualsX509CertFailure) {
  std::unique_ptr<X509Certificate> x509_cert;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      x509_cert, X509Certificate::CreateFromPem(kTestIntermediateCertPem));

  std::unique_ptr<X509Certificate> other_x509_cert;
  ASYLO_ASSERT_OK_AND_ASSIGN(other_x509_cert, X509Certificate::CreateFromPem(
                                                  kOtherIntermediateCertPem));

  EXPECT_FALSE(*x509_cert == *other_x509_cert);
}

TEST_F(X509CertificateTest, EqualsNonX509Failure) {
  std::unique_ptr<X509Certificate> x509_cert;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      x509_cert, X509Certificate::CreateFromPem(kTestIntermediateCertPem));

  FakeCertificate fake_cert(/*subject_key=*/"Subject key",
                            /*issuer_key=*/"Issuer key",
                            /*is_ca=*/absl::nullopt,
                            /*pathlength=*/absl::nullopt,
                            /*subject_name=*/absl::nullopt);

  EXPECT_FALSE(*x509_cert == fake_cert);
}

// Verifies that CertificateSigningRequestToX509Req returns an error with
// malformed data.
TEST_F(X509CertificateTest, CertificateSigningRequestToX509ReqMalformedData) {
  CertificateSigningRequest csr;
  csr.set_format(CertificateSigningRequest::PKCS10_PEM);
  csr.set_data(kNotACert);

  EXPECT_THAT(CertificateSigningRequestToX509Req(csr),
              StatusIs(absl::StatusCode::kInternal));
}

// Verifies that CertificateSigningRequestToX509Req returns an INVALID_ARGUMENT
// error when the csr has a format other than PKCS10_DER or PKCS10_PEM.
TEST_F(X509CertificateTest, CertificateSigningRequestToX509ReqInvalidFormat) {
  CertificateSigningRequest csr;
  csr.set_format(CertificateSigningRequest::UNKNOWN);
  csr.set_data(kCsrDerHex);

  EXPECT_THAT(CertificateSigningRequestToX509Req(csr),
              StatusIs(absl::StatusCode::kInvalidArgument));
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

  EXPECT_THAT(ExtractPkcs10SubjectKeyDer(csr),
              StatusIs(absl::StatusCode::kInternal));
}

// Verifies that ExtractPkcs10SubjectKeyDer(csr) returns an INVALID_ARGUMENT
// error if the format is not PKCS10_DER or PKCS10_PEM.
TEST_F(X509CertificateTest, ExtractPkcs10SubjectKeyDerCsrInvalidFormat) {
  CertificateSigningRequest csr;
  csr.set_format(CertificateSigningRequest::UNKNOWN);
  csr.set_data(kCsrPem);

  EXPECT_THAT(ExtractPkcs10SubjectKeyDer(csr),
              StatusIs(absl::StatusCode::kInvalidArgument));
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
              StatusIs(absl::StatusCode::kInternal));
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
              StatusIs(absl::StatusCode::kUnauthenticated));
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
              StatusIs(absl::StatusCode::kUnauthenticated));
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

// Verify that Verify returns an UNAUTHENTICATED error when
// subject_validity_period check is required but fails.
TEST_F(X509CertificateTest, VerifyCertificateValidityPeriodFails) {
  std::unique_ptr<CertificateInterface> x509_issuer;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      x509_issuer,
      CreateX509Cert(Certificate::X509_DER,
                     absl::HexStringToBytes(kTestIntermediateCertDerHex)));

  std::unique_ptr<CertificateInterface> x509_subject;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      x509_subject, CreateX509Cert(Certificate::X509_PEM, kTestEndUserCertPem));

  VerificationConfig config(/*all_fields=*/false);
  config.subject_validity_period =
      absl::FromCivil(absl::CivilDay(2020, 9, 30), absl::UTCTimeZone());
  EXPECT_THAT(x509_subject->Verify(*x509_issuer, config),
              StatusIs(absl::StatusCode::kUnauthenticated, HasSubstr("time")));
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

  VerificationConfig config(
      /*all_fields=*/true,
      absl::FromCivil(absl::CivilDay(2020, 9, 30), absl::UTCTimeZone()));
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
              StatusIs(absl::StatusCode::kUnimplemented));
}

// Verifies that SubjectKeyDer() returns the expected key value.
TEST_F(X509CertificateTest, SubjectKeyDerSucceeds) {
  std::unique_ptr<CertificateInterface> x509;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      x509, CreateX509Cert(Certificate::X509_PEM, kTestRootCertPem));
  EXPECT_THAT(x509->SubjectKeyDer(), IsOkAndHolds(root_public_key_));
}

// Verifies that SubjectName() returns the expected subject name.
TEST_F(X509CertificateTest, SubjectNameMatches) {
  std::unique_ptr<CertificateInterface> x509;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      x509, CreateX509Cert(Certificate::X509_PEM, kTestRealCaCertPem));

  EXPECT_THAT(
      x509->SubjectName(),
      Optional(StrEq("CN=Test Real Root "
                     "CA,OU=Asylo,O=Google,L=Kirkland,ST=Washington,C=US")));
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

TEST_F(X509CertificateTest,
       X509CertificateBuilderSignAndBuildSucceedsWithExtensions) {
  constexpr char kFakeOid[] = "1.3.6.1.4.1.11129.24.1729";

  X509Extension other_extension;
  ASYLO_ASSERT_OK_AND_ASSIGN(other_extension.oid,
                             ObjectId::CreateFromOidString(kFakeOid));
  other_extension.is_critical = true;
  ASYLO_ASSERT_OK_AND_ASSIGN(other_extension.value,
                             Asn1Value::CreateOctetString("foobar"));

  X509CertificateBuilder builder = CreateMinimalCertificateBuilder();
  builder.authority_key_identifier = {8, 6, 7, 5, 3, 0, 9};
  builder.subject_key_identifier_method =
      SubjectKeyIdMethod::kSubjectPublicKeySha1;
  builder.key_usage.emplace();
  builder.key_usage->certificate_signing = true;
  builder.key_usage->crl_signing = true;
  builder.key_usage->digital_signature = true;
  builder.basic_constraints.emplace();
  builder.basic_constraints->is_ca = true;
  builder.basic_constraints->pathlen.emplace(3);
  builder.crl_distribution_points.emplace();
  builder.crl_distribution_points->uri =
      "https://en.wikipedia.org/wiki/Dark_Side_of_the_Rainbow";
  builder.crl_distribution_points->reasons.emplace();
  builder.crl_distribution_points->reasons->key_compromise = true;
  builder.crl_distribution_points->reasons->ca_compromise = true;
  builder.crl_distribution_points->reasons->priviledge_withdrawn = true;
  builder.other_extensions = {other_extension};

  std::unique_ptr<SigningKey> signing_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      signing_key, EcdsaP256Sha256SigningKey::CreateFromDer(
                       absl::HexStringToBytes(kTestPrivateKeyDerHex)));
  std::unique_ptr<X509Certificate> certificate;
  ASYLO_ASSERT_OK_AND_ASSIGN(certificate, builder.SignAndBuild(*signing_key));

  EXPECT_THAT(certificate->GetVersion(), Eq(builder.version));

  bssl::UniquePtr<BIGNUM> final_serial_number;
  ASYLO_ASSERT_OK_AND_ASSIGN(final_serial_number,
                             certificate->GetSerialNumber());
  EXPECT_THAT(IntegerFromBignum<int64_t>(*final_serial_number),
              IsOkAndHolds(kFakeSerialNumber));

  X509Name final_issuer;
  ASYLO_ASSERT_OK_AND_ASSIGN(final_issuer, certificate->GetIssuerName());
  ASSERT_THAT(final_issuer, SizeIs(builder.issuer->size()));
  for (int i = 0; i < final_issuer.size(); ++i) {
    EXPECT_THAT(final_issuer[i].field, Eq((*builder.issuer)[i].field));
    EXPECT_THAT(final_issuer[i].value, StrEq((*builder.issuer)[i].value));
  }

  X509Validity final_validity;
  ASYLO_ASSERT_OK_AND_ASSIGN(final_validity, certificate->GetValidity());
  EXPECT_THAT(final_validity.not_before, Eq(builder.validity->not_before));
  EXPECT_THAT(final_validity.not_after, Eq(builder.validity->not_after));

  X509Name final_subject;
  ASYLO_ASSERT_OK_AND_ASSIGN(final_subject, certificate->GetSubjectName());
  ASSERT_THAT(final_subject, SizeIs(builder.subject->size()));
  for (int i = 0; i < final_subject.size(); ++i) {
    EXPECT_THAT(final_subject[i].field, Eq((*builder.subject)[i].field));
    EXPECT_THAT(final_subject[i].value, StrEq((*builder.subject)[i].value));
  }

  EXPECT_THAT(certificate->SubjectKeyDer(),
              IsOkAndHolds(StrEq(builder.subject_public_key_der.value())));

  EXPECT_THAT(certificate->GetAuthorityKeyIdentifier(),
              IsOkAndHolds(Optional(builder.authority_key_identifier.value())));

  EXPECT_THAT(certificate->GetSubjectKeyIdentifier(),
              IsOkAndHolds(
                  Optional(ElementsAreArray(MakeView<absl::Span<const uint8_t>>(
                      absl::HexStringToBytes(kTestRootPublicKeySha1Hex))))));

  absl::optional<KeyUsageInformation> final_key_usage = certificate->KeyUsage();
  ASSERT_TRUE(final_key_usage.has_value());
  EXPECT_THAT(final_key_usage->certificate_signing,
              Eq(builder.key_usage->certificate_signing));
  EXPECT_THAT(final_key_usage->crl_signing, Eq(builder.key_usage->crl_signing));
  EXPECT_THAT(final_key_usage->digital_signature,
              Eq(builder.key_usage->digital_signature));

  absl::optional<BasicConstraints> final_constraints;
  ASYLO_ASSERT_OK_AND_ASSIGN(final_constraints,
                             certificate->GetBasicConstraints());
  ASSERT_TRUE(final_constraints.has_value());
  EXPECT_THAT(final_constraints->is_ca, Eq(builder.basic_constraints->is_ca));
  EXPECT_THAT(final_constraints->pathlen,
              Optional(builder.basic_constraints->pathlen.value()));

  absl::optional<CrlDistributionPoints> final_crl_distribution_points;
  ASYLO_ASSERT_OK_AND_ASSIGN(final_crl_distribution_points,
                             certificate->GetCrlDistributionPoints());
  ASSERT_TRUE(final_crl_distribution_points.has_value());
  EXPECT_THAT(final_crl_distribution_points->uri,
              StrEq(builder.crl_distribution_points->uri));
  ASSERT_TRUE(final_crl_distribution_points->reasons.has_value());
  EXPECT_THAT(final_crl_distribution_points->reasons->key_compromise,
              Eq(builder.crl_distribution_points->reasons->key_compromise));
  EXPECT_THAT(final_crl_distribution_points->reasons->ca_compromise,
              Eq(builder.crl_distribution_points->reasons->ca_compromise));
  EXPECT_THAT(
      final_crl_distribution_points->reasons->affiliation_changed,
      Eq(builder.crl_distribution_points->reasons->affiliation_changed));
  EXPECT_THAT(final_crl_distribution_points->reasons->superseded,
              Eq(builder.crl_distribution_points->reasons->superseded));
  EXPECT_THAT(
      final_crl_distribution_points->reasons->cessation_of_operation,
      Eq(builder.crl_distribution_points->reasons->cessation_of_operation));
  EXPECT_THAT(final_crl_distribution_points->reasons->certificate_hold,
              Eq(builder.crl_distribution_points->reasons->certificate_hold));
  EXPECT_THAT(
      final_crl_distribution_points->reasons->priviledge_withdrawn,
      Eq(builder.crl_distribution_points->reasons->priviledge_withdrawn));
  EXPECT_THAT(final_crl_distribution_points->reasons->aa_compromise,
              Eq(builder.crl_distribution_points->reasons->aa_compromise));

  std::vector<X509Extension> final_extensions;
  ASYLO_ASSERT_OK_AND_ASSIGN(final_extensions,
                             certificate->GetOtherExtensions());
  ASSERT_THAT(final_extensions, SizeIs(builder.other_extensions.size()));
  for (int i = 0; i < final_extensions.size(); ++i) {
    EXPECT_THAT(final_extensions[i].oid, Eq(builder.other_extensions[i].oid));
    EXPECT_THAT(final_extensions[i].is_critical,
                Eq(builder.other_extensions[i].is_critical));
    EXPECT_THAT(final_extensions[i].value,
                Eq(builder.other_extensions[i].value));
  }
}

TEST_F(X509CertificateTest,
       X509CertificateBuilderSignAndBuildSucceedsWithoutExtensions) {
  X509CertificateBuilder builder = CreateMinimalCertificateBuilder();

  std::unique_ptr<SigningKey> signing_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      signing_key, EcdsaP256Sha256SigningKey::CreateFromDer(
                       absl::HexStringToBytes(kTestPrivateKeyDerHex)));
  std::unique_ptr<X509Certificate> certificate;
  ASYLO_ASSERT_OK_AND_ASSIGN(certificate, builder.SignAndBuild(*signing_key));

  EXPECT_THAT(certificate->GetVersion(), Eq(builder.version));

  bssl::UniquePtr<BIGNUM> final_serial_number;
  ASYLO_ASSERT_OK_AND_ASSIGN(final_serial_number,
                             certificate->GetSerialNumber());
  EXPECT_THAT(IntegerFromBignum<int64_t>(*final_serial_number),
              IsOkAndHolds(kFakeSerialNumber));

  X509Name final_issuer;
  ASYLO_ASSERT_OK_AND_ASSIGN(final_issuer, certificate->GetIssuerName());
  ASSERT_THAT(final_issuer, SizeIs(builder.issuer->size()));
  for (int i = 0; i < final_issuer.size(); ++i) {
    EXPECT_THAT(final_issuer[i].field, Eq((*builder.issuer)[i].field));
    EXPECT_THAT(final_issuer[i].value, StrEq((*builder.issuer)[i].value));
  }

  X509Validity final_validity;
  ASYLO_ASSERT_OK_AND_ASSIGN(final_validity, certificate->GetValidity());
  EXPECT_THAT(final_validity.not_before, Eq(builder.validity->not_before));
  EXPECT_THAT(final_validity.not_after, Eq(builder.validity->not_after));

  X509Name final_subject;
  ASYLO_ASSERT_OK_AND_ASSIGN(final_subject, certificate->GetSubjectName());
  ASSERT_THAT(final_subject, SizeIs(builder.subject->size()));
  for (int i = 0; i < final_subject.size(); ++i) {
    EXPECT_THAT(final_subject[i].field, Eq((*builder.subject)[i].field));
    EXPECT_THAT(final_subject[i].value, StrEq((*builder.subject)[i].value));
  }

  EXPECT_THAT(certificate->SubjectKeyDer(),
              IsOkAndHolds(StrEq(*builder.subject_public_key_der)));

  EXPECT_THAT(certificate->GetAuthorityKeyIdentifier(),
              IsOkAndHolds(Nullopt()));

  EXPECT_THAT(certificate->GetSubjectKeyIdentifier(), IsOkAndHolds(Nullopt()));

  EXPECT_THAT(certificate->KeyUsage(), Nullopt());

  EXPECT_THAT(certificate->GetBasicConstraints(), IsOkAndHolds(Nullopt()));

  EXPECT_THAT(certificate->GetCrlDistributionPoints(), IsOkAndHolds(Nullopt()));

  EXPECT_THAT(certificate->GetOtherExtensions(), IsOkAndHolds(IsEmpty()));
}

TEST_F(X509CertificateTest,
       X509CertificateBuilderSignAndBuildFailsWithMissingFields) {
  std::unique_ptr<SigningKey> signing_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      signing_key, EcdsaP256Sha256SigningKey::CreateFromDer(
                       absl::HexStringToBytes(kTestPrivateKeyDerHex)));

  X509CertificateBuilder builder = CreateMinimalCertificateBuilder();
  BN_set_negative(builder.serial_number.get(), /*sign=*/1);
  EXPECT_THAT(builder.SignAndBuild(*signing_key),
              StatusIs(absl::StatusCode::kInvalidArgument));

  builder = CreateMinimalCertificateBuilder();
  builder.issuer.reset();
  EXPECT_THAT(builder.SignAndBuild(*signing_key),
              StatusIs(absl::StatusCode::kInvalidArgument));

  builder = CreateMinimalCertificateBuilder();
  builder.validity.reset();
  EXPECT_THAT(builder.SignAndBuild(*signing_key),
              StatusIs(absl::StatusCode::kInvalidArgument));

  builder = CreateMinimalCertificateBuilder();
  builder.subject.reset();
  EXPECT_THAT(builder.SignAndBuild(*signing_key),
              StatusIs(absl::StatusCode::kInvalidArgument));

  builder = CreateMinimalCertificateBuilder();
  builder.subject_public_key_der.reset();
  EXPECT_THAT(builder.SignAndBuild(*signing_key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(X509CertificateTest, X509NameEntryEqualityComparisonSucceeds) {
  X509NameEntry first;
  ASYLO_ASSERT_OK_AND_ASSIGN(first.field, ObjectId::CreateFromShortName("OU"));
  first.value = "value";

  X509NameEntry second = first;
  EXPECT_THAT(first, Eq(second));
  EXPECT_THAT(first, Not(Ne(second)));
}

TEST_F(X509CertificateTest, X509NameEntryEqualityComparisonFailsOnField) {
  X509NameEntry first;
  ASYLO_ASSERT_OK_AND_ASSIGN(first.field, ObjectId::CreateFromShortName("CN"));

  X509NameEntry second;
  ASYLO_ASSERT_OK_AND_ASSIGN(first.field, ObjectId::CreateFromShortName("OU"));

  first.value = "foo";
  second.value = first.value;

  EXPECT_THAT(first, Ne(second));
  EXPECT_THAT(first, Not(Eq(second)));
}

TEST_F(X509CertificateTest, X509NameEntryEqualityComparisonFailsOnValue) {
  X509NameEntry first;
  ASYLO_ASSERT_OK_AND_ASSIGN(first.field, ObjectId::CreateFromShortName("CN"));
  first.value = "something";

  X509NameEntry second = first;
  second.value = "something else";

  EXPECT_THAT(first, Ne(second));
  EXPECT_THAT(first, Not(Eq(second)));
}

TEST_F(X509CertificateTest, X509NameEntryOutputShortName) {
  X509NameEntry entry;
  ASYLO_ASSERT_OK_AND_ASSIGN(entry.field, ObjectId::CreateFromShortName("CN"));
  entry.value = "GoogleDotCom";

  std::ostringstream out;
  out << entry;
  EXPECT_THAT(out.str(), Eq("CN=GoogleDotCom"));
}

TEST_F(X509CertificateTest, X509NameEntryOutputOid) {
  X509NameEntry entry;
  ASYLO_ASSERT_OK_AND_ASSIGN(entry.field,
                             ObjectId::CreateFromOidString("1.2.3.4"));
  entry.value = "A B C D";

  std::ostringstream out;
  out << entry;
  EXPECT_THAT(out.str(), Eq("1.2.3.4=A B C D"));
}

TEST_F(X509CertificateTest, X509NameEntryOutputUnknown) {
  X509NameEntry entry;
  entry.value = "should not happen";

  std::ostringstream out;
  out << entry;
  EXPECT_THAT(out.str(), Eq("UNKNOWN_OID=should not happen"));
}

TEST_F(X509CertificateTest, X509CsrBuilderSignAndBuildFailsMissingKey) {
  X509CsrBuilder builder = CreateMinimalCsrBuilder();
  builder.key = nullptr;
  EXPECT_THAT(builder.SignAndBuild(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(X509CertificateTest, X509CsrBuilderSignAndBuildFailsMissingSubject) {
  X509CsrBuilder builder = CreateMinimalCsrBuilder();
  builder.subject = absl::nullopt;
  EXPECT_THAT(builder.SignAndBuild(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(X509CertificateTest, X509CsrBuilderSignAndBuildSucceeds) {
  X509CsrBuilder builder = CreateMinimalCsrBuilder();
  CertificateSigningRequest csr;
  csr.set_format(CertificateSigningRequest::PKCS10_PEM);
  ASYLO_ASSERT_OK_AND_ASSIGN(*csr.mutable_data(), builder.SignAndBuild());
  bssl::UniquePtr<X509_REQ> req;
  ASYLO_ASSERT_OK_AND_ASSIGN(req, CertificateSigningRequestToX509Req(csr));
  bssl::UniquePtr<EVP_PKEY> pkey(X509_REQ_get_pubkey(req.get()));
  EXPECT_EQ(X509_REQ_verify(req.get(), pkey.get()), 1);
}

}  // namespace
}  // namespace asylo
