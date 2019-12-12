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

#include "asylo/crypto/certificate_util.h"

#include <memory>
#include <vector>

#include <google/protobuf/text_format.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/memory/memory.h"
#include "absl/types/optional.h"
#include "absl/types/span.h"
#include "asylo/crypto/certificate.pb.h"
#include "asylo/crypto/certificate_interface.h"
#include "asylo/crypto/fake_certificate.h"
#include "asylo/crypto/fake_certificate.pb.h"
#include "asylo/test/util/proto_matchers.h"
#include "asylo/test/util/status_matchers.h"

namespace asylo {
namespace {

constexpr char kRootKey[] = "f00d";
constexpr char kIntermediateKey[] = "c0ff33";
constexpr char kExtraIntermediateKey[] = "c0c0a";
constexpr char kEndUserKey[] = "fun";

// Data for a malformed FakeCertificate;
constexpr char kMalformedCertData[] = "food food food food";

// Test data of a valid X.509 PEM-encoded certificate.
constexpr char kPemCert[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIEgTCCBCegAwIBAgIVAJ1mxDIzAXa+ixcUKKaUmyYxoyJlMAoGCCqGSM49BAMC\n"
    "MHExIzAhBgNVBAMMGkludGVsIFNHWCBQQ0sgUHJvY2Vzc29yIENBMRowGAYDVQQK\n"
    "DBFJbnRlbCBDb3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNV\n"
    "BAgMAkNBMQswCQYDVQQGEwJVUzAeFw0xOTA0MDMyMTE2MzFaFw0yNjA0MDMyMTE2\n"
    "MzFaMHAxIjAgBgNVBAMMGUludGVsIFNHWCBQQ0sgQ2VydGlmaWNhdGUxGjAYBgNV\n"
    "BAoMEUludGVsIENvcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkG\n"
    "A1UECAwCQ0ExCzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n"
    "F7aCJQzGR7R/oeDkuyiFhknVXV4mKl72QUCD+02CS+a0AUnJtKz37EmAyd5afJ38\n"
    "dFswPFL1upLY7yrEco993qOCApswggKXMB8GA1UdIwQYMBaAFNDoqtp11/kuSReY\n"
    "PHsUZdDV8llNMF8GA1UdHwRYMFYwVKBSoFCGTmh0dHBzOi8vYXBpLnRydXN0ZWRz\n"
    "ZXJ2aWNlcy5pbnRlbC5jb20vc2d4L2NlcnRpZmljYXRpb24vdjEvcGNrY3JsP2Nh\n"
    "PXByb2Nlc3NvcjAdBgNVHQ4EFgQUFBTkM8dooH85tY3YGlV1MtZs1zEwDgYDVR0P\n"
    "AQH/BAQDAgbAMAwGA1UdEwEB/wQCMAAwggHUBgkqhkiG+E0BDQEEggHFMIIBwTAe\n"
    "BgoqhkiG+E0BDQEBBBB7l753xi1CRsYD0PTxGzG7MIIBZAYKKoZIhvhNAQ0BAjCC\n"
    "AVQwEAYLKoZIhvhNAQ0BAgECAQUwEAYLKoZIhvhNAQ0BAgICAQUwEAYLKoZIhvhN\n"
    "AQ0BAgMCAQIwEAYLKoZIhvhNAQ0BAgQCAQQwEAYLKoZIhvhNAQ0BAgUCAQEwEQYL\n"
    "KoZIhvhNAQ0BAgYCAgCAMBAGCyqGSIb4TQENAQIHAgEAMBAGCyqGSIb4TQENAQII\n"
    "AgEAMBAGCyqGSIb4TQENAQIJAgEAMBAGCyqGSIb4TQENAQIKAgEAMBAGCyqGSIb4\n"
    "TQENAQILAgEAMBAGCyqGSIb4TQENAQIMAgEAMBAGCyqGSIb4TQENAQINAgEAMBAG\n"
    "CyqGSIb4TQENAQIOAgEAMBAGCyqGSIb4TQENAQIPAgEAMBAGCyqGSIb4TQENAQIQ\n"
    "AgEAMBAGCyqGSIb4TQENAQIRAgEHMB8GCyqGSIb4TQENAQISBBAFBQIEAYAAAAAA\n"
    "AAAAAAAAMBAGCiqGSIb4TQENAQMEAgAAMBQGCiqGSIb4TQENAQQEBgCQbqEAADAP\n"
    "BgoqhkiG+E0BDQEFCgEAMAoGCCqGSM49BAMCA0gAMEUCIQCumiqM0xbNkSovgoDP\n"
    "ZlMLpLOGlQZKIiYdOCqJhD4vYgIged7Ldm1CUVBPEfBElbn9QMS2aSNsElIAtDlT\n"
    "Z0FeT5U=\n"
    "-----END CERTIFICATE-----\n";

// Test data of a Certificate proto parsed from an X.509 PEM-encoded cert
// string.
constexpr char kProtoPemCert[] = R"proto(
  format: X509_PEM
  data: "-----BEGIN CERTIFICATE-----\n"
        "MIIEgTCCBCegAwIBAgIVAJ1mxDIzAXa+ixcUKKaUmyYxoyJlMAoGCCqGSM49BAMC\n"
        "MHExIzAhBgNVBAMMGkludGVsIFNHWCBQQ0sgUHJvY2Vzc29yIENBMRowGAYDVQQK\n"
        "DBFJbnRlbCBDb3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNV\n"
        "BAgMAkNBMQswCQYDVQQGEwJVUzAeFw0xOTA0MDMyMTE2MzFaFw0yNjA0MDMyMTE2\n"
        "MzFaMHAxIjAgBgNVBAMMGUludGVsIFNHWCBQQ0sgQ2VydGlmaWNhdGUxGjAYBgNV\n"
        "BAoMEUludGVsIENvcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkG\n"
        "A1UECAwCQ0ExCzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n"
        "F7aCJQzGR7R/oeDkuyiFhknVXV4mKl72QUCD+02CS+a0AUnJtKz37EmAyd5afJ38\n"
        "dFswPFL1upLY7yrEco993qOCApswggKXMB8GA1UdIwQYMBaAFNDoqtp11/kuSReY\n"
        "PHsUZdDV8llNMF8GA1UdHwRYMFYwVKBSoFCGTmh0dHBzOi8vYXBpLnRydXN0ZWRz\n"
        "ZXJ2aWNlcy5pbnRlbC5jb20vc2d4L2NlcnRpZmljYXRpb24vdjEvcGNrY3JsP2Nh\n"
        "PXByb2Nlc3NvcjAdBgNVHQ4EFgQUFBTkM8dooH85tY3YGlV1MtZs1zEwDgYDVR0P\n"
        "AQH/BAQDAgbAMAwGA1UdEwEB/wQCMAAwggHUBgkqhkiG+E0BDQEEggHFMIIBwTAe\n"
        "BgoqhkiG+E0BDQEBBBB7l753xi1CRsYD0PTxGzG7MIIBZAYKKoZIhvhNAQ0BAjCC\n"
        "AVQwEAYLKoZIhvhNAQ0BAgECAQUwEAYLKoZIhvhNAQ0BAgICAQUwEAYLKoZIhvhN\n"
        "AQ0BAgMCAQIwEAYLKoZIhvhNAQ0BAgQCAQQwEAYLKoZIhvhNAQ0BAgUCAQEwEQYL\n"
        "KoZIhvhNAQ0BAgYCAgCAMBAGCyqGSIb4TQENAQIHAgEAMBAGCyqGSIb4TQENAQII\n"
        "AgEAMBAGCyqGSIb4TQENAQIJAgEAMBAGCyqGSIb4TQENAQIKAgEAMBAGCyqGSIb4\n"
        "TQENAQILAgEAMBAGCyqGSIb4TQENAQIMAgEAMBAGCyqGSIb4TQENAQINAgEAMBAG\n"
        "CyqGSIb4TQENAQIOAgEAMBAGCyqGSIb4TQENAQIPAgEAMBAGCyqGSIb4TQENAQIQ\n"
        "AgEAMBAGCyqGSIb4TQENAQIRAgEHMB8GCyqGSIb4TQENAQISBBAFBQIEAYAAAAAA\n"
        "AAAAAAAAMBAGCiqGSIb4TQENAQMEAgAAMBQGCiqGSIb4TQENAQQEBgCQbqEAADAP\n"
        "BgoqhkiG+E0BDQEFCgEAMAoGCCqGSM49BAMCA0gAMEUCIQCumiqM0xbNkSovgoDP\n"
        "ZlMLpLOGlQZKIiYdOCqJhD4vYgIged7Ldm1CUVBPEfBElbn9QMS2aSNsElIAtDlT\n"
        "Z0FeT5U=\n"
        "-----END CERTIFICATE-----\n"
)proto";

// Test data of a certificate chain composed of concatenation of X.509
// PEM-encoded certificates.
constexpr char kPemCertChain[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIClzCCAj6gAwIBAgIVANDoqtp11/kuSReYPHsUZdDV8llNMAoGCCqGSM49BAMC\n"
    "MGgxGjAYBgNVBAMMEUludGVsIFNHWCBSb290IENBMRowGAYDVQQKDBFJbnRlbCBD\n"
    "b3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNBMQsw\n"
    "CQYDVQQGEwJVUzAeFw0xODA1MjExMDQ1MDhaFw0zMzA1MjExMDQ1MDhaMHExIzAh\n"
    "BgNVBAMMGkludGVsIFNHWCBQQ0sgUHJvY2Vzc29yIENBMRowGAYDVQQKDBFJbnRl\n"
    "bCBDb3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNB\n"
    "MQswCQYDVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABL9q+NMp2IOg\n"
    "tdl1bk/uWZ5+TGQm8aCi8z78fs+fKCQ3d+uDzXnVTAT2ZhDCifyIuJwvN3wNBp9i\n"
    "HBSSMJMJrBOjgbswgbgwHwYDVR0jBBgwFoAUImUM1lqdNInzg7SVUr9QGzknBqww\n"
    "UgYDVR0fBEswSTBHoEWgQ4ZBaHR0cHM6Ly9jZXJ0aWZpY2F0ZXMudHJ1c3RlZHNl\n"
    "cnZpY2VzLmludGVsLmNvbS9JbnRlbFNHWFJvb3RDQS5jcmwwHQYDVR0OBBYEFNDo\n"
    "qtp11/kuSReYPHsUZdDV8llNMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAG\n"
    "AQH/AgEAMAoGCCqGSM49BAMCA0cAMEQCIC/9j+84T+HztVO/sOQBWJbSd+/2uexK\n"
    "4+aA0jcFBLcpAiA3dhMrF5cD52t6FqMvAIpj8XdGmy2beeljLJK+pzpcRA==\n"
    "-----END CERTIFICATE-----\n"
    "-----BEGIN CERTIFICATE-----\n"
    "MIICjjCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw\n"
    "aDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv\n"
    "cnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ\n"
    "BgNVBAYTAlVTMB4XDTE4MDUyMTEwNDExMVoXDTMzMDUyMTEwNDExMFowaDEaMBgG\n"
    "A1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0\n"
    "aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT\n"
    "AlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi7\n"
    "1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB\n"
    "uzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ\n"
    "MEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50\n"
    "ZWwuY29tL0ludGVsU0dYUm9vdENBLmNybDAdBgNVHQ4EFgQUImUM1lqdNInzg7SV\n"
    "Ur9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYI\n"
    "KoZIzj0EAwIDSAAwRQIgQQs/08rycdPauCFk8UPQXCMAlsloBe7NwaQGTcdpa0EC\n"
    "IQCUt8SGvxKmjpcM/z0WP9Dvo8h2k5du1iWDdBkAn+0iiA==\n"
    "-----END CERTIFICATE-----\n";

// Test data of a CertificateChain proto parsed from a string of concatenated
// X.509 PEM-encoded certificates.
constexpr char kProtoPemCertChain[] = R"proto(
  certificates {
    format: X509_PEM
    data: "-----BEGIN CERTIFICATE-----\n"
          "MIIClzCCAj6gAwIBAgIVANDoqtp11/kuSReYPHsUZdDV8llNMAoGCCqGSM49BAMC\n"
          "MGgxGjAYBgNVBAMMEUludGVsIFNHWCBSb290IENBMRowGAYDVQQKDBFJbnRlbCBD\n"
          "b3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNBMQsw\n"
          "CQYDVQQGEwJVUzAeFw0xODA1MjExMDQ1MDhaFw0zMzA1MjExMDQ1MDhaMHExIzAh\n"
          "BgNVBAMMGkludGVsIFNHWCBQQ0sgUHJvY2Vzc29yIENBMRowGAYDVQQKDBFJbnRl\n"
          "bCBDb3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNB\n"
          "MQswCQYDVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABL9q+NMp2IOg\n"
          "tdl1bk/uWZ5+TGQm8aCi8z78fs+fKCQ3d+uDzXnVTAT2ZhDCifyIuJwvN3wNBp9i\n"
          "HBSSMJMJrBOjgbswgbgwHwYDVR0jBBgwFoAUImUM1lqdNInzg7SVUr9QGzknBqww\n"
          "UgYDVR0fBEswSTBHoEWgQ4ZBaHR0cHM6Ly9jZXJ0aWZpY2F0ZXMudHJ1c3RlZHNl\n"
          "cnZpY2VzLmludGVsLmNvbS9JbnRlbFNHWFJvb3RDQS5jcmwwHQYDVR0OBBYEFNDo\n"
          "qtp11/kuSReYPHsUZdDV8llNMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAG\n"
          "AQH/AgEAMAoGCCqGSM49BAMCA0cAMEQCIC/9j+84T+HztVO/sOQBWJbSd+/2uexK\n"
          "4+aA0jcFBLcpAiA3dhMrF5cD52t6FqMvAIpj8XdGmy2beeljLJK+pzpcRA==\n"
          "-----END CERTIFICATE-----\n"
  }
  certificates {
    format: X509_PEM
    data: "-----BEGIN CERTIFICATE-----\n"
          "MIICjjCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw\n"
          "aDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv\n"
          "cnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ\n"
          "BgNVBAYTAlVTMB4XDTE4MDUyMTEwNDExMVoXDTMzMDUyMTEwNDExMFowaDEaMBgG\n"
          "A1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0\n"
          "aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT\n"
          "AlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi7\n"
          "1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB\n"
          "uzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ\n"
          "MEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50\n"
          "ZWwuY29tL0ludGVsU0dYUm9vdENBLmNybDAdBgNVHQ4EFgQUImUM1lqdNInzg7SV\n"
          "Ur9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYI\n"
          "KoZIzj0EAwIDSAAwRQIgQQs/08rycdPauCFk8UPQXCMAlsloBe7NwaQGTcdpa0EC\n"
          "IQCUt8SGvxKmjpcM/z0WP9Dvo8h2k5du1iWDdBkAn+0iiA==\n"
          "-----END CERTIFICATE-----\n"
  }
)proto";

// Test data of a certificate chain composed of X.509 PEM-encoded certificates
// and extra padding.
constexpr char kPemCertChainWithExtraPadding[] =
    "Heading bytes"
    "-----BEGIN CERTIFICATE-----\n"
    "MIIClzCCAj6gAwIBAgIVANDoqtp11/kuSReYPHsUZdDV8llNMAoGCCqGSM49BAMC\n"
    "MGgxGjAYBgNVBAMMEUludGVsIFNHWCBSb290IENBMRowGAYDVQQKDBFJbnRlbCBD\n"
    "b3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNBMQsw\n"
    "CQYDVQQGEwJVUzAeFw0xODA1MjExMDQ1MDhaFw0zMzA1MjExMDQ1MDhaMHExIzAh\n"
    "BgNVBAMMGkludGVsIFNHWCBQQ0sgUHJvY2Vzc29yIENBMRowGAYDVQQKDBFJbnRl\n"
    "bCBDb3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNB\n"
    "MQswCQYDVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABL9q+NMp2IOg\n"
    "tdl1bk/uWZ5+TGQm8aCi8z78fs+fKCQ3d+uDzXnVTAT2ZhDCifyIuJwvN3wNBp9i\n"
    "HBSSMJMJrBOjgbswgbgwHwYDVR0jBBgwFoAUImUM1lqdNInzg7SVUr9QGzknBqww\n"
    "UgYDVR0fBEswSTBHoEWgQ4ZBaHR0cHM6Ly9jZXJ0aWZpY2F0ZXMudHJ1c3RlZHNl\n"
    "cnZpY2VzLmludGVsLmNvbS9JbnRlbFNHWFJvb3RDQS5jcmwwHQYDVR0OBBYEFNDo\n"
    "qtp11/kuSReYPHsUZdDV8llNMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAG\n"
    "AQH/AgEAMAoGCCqGSM49BAMCA0cAMEQCIC/9j+84T+HztVO/sOQBWJbSd+/2uexK\n"
    "4+aA0jcFBLcpAiA3dhMrF5cD52t6FqMvAIpj8XdGmy2beeljLJK+pzpcRA==\n"
    "-----END CERTIFICATE-----\n"
    "Padding bytes"
    "-----BEGIN CERTIFICATE-----\n"
    "MIICjjCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw\n"
    "aDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv\n"
    "cnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ\n"
    "BgNVBAYTAlVTMB4XDTE4MDUyMTEwNDExMVoXDTMzMDUyMTEwNDExMFowaDEaMBgG\n"
    "A1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0\n"
    "aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT\n"
    "AlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi7\n"
    "1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB\n"
    "uzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ\n"
    "MEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50\n"
    "ZWwuY29tL0ludGVsU0dYUm9vdENBLmNybDAdBgNVHQ4EFgQUImUM1lqdNInzg7SV\n"
    "Ur9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYI\n"
    "KoZIzj0EAwIDSAAwRQIgQQs/08rycdPauCFk8UPQXCMAlsloBe7NwaQGTcdpa0EC\n"
    "IQCUt8SGvxKmjpcM/z0WP9Dvo8h2k5du1iWDdBkAn+0iiA==\n"
    "-----END CERTIFICATE-----\n"
    "trailing bytes";

// Test data of a certificate chain composed of one valid and one invalid X.509
// PEM-encoded certificates.
constexpr char kPemCertChainWithOneInvalidCert[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIClzCCAj6gAwIBAgIVANDoqtp11/kuSReYPHsUZdDV8llNMAoGCCqGSM49BAMC\n"
    "MGgxGjAYBgNVBAMMEUludGVsIFNHWCBSb290IENBMRowGAYDVQQKDBFJbnRlbCBD\n"
    "b3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNBMQsw\n"
    "CQYDVQQGEwJVUzAeFw0xODA1MjExMDQ1MDhaFw0zMzA1MjExMDQ1MDhaMHExIzAh\n"
    "BgNVBAMMGkludGVsIFNHWCBQQ0sgUHJvY2Vzc29yIENBMRowGAYDVQQKDBFJbnRl\n"
    "bCBDb3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNB\n"
    "MQswCQYDVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABL9q+NMp2IOg\n"
    "tdl1bk/uWZ5+TGQm8aCi8z78fs+fKCQ3d+uDzXnVTAT2ZhDCifyIuJwvN3wNBp9i\n"
    "HBSSMJMJrBOjgbswgbgwHwYDVR0jBBgwFoAUImUM1lqdNInzg7SVUr9QGzknBqww\n"
    "UgYDVR0fBEswSTBHoEWgQ4ZBaHR0cHM6Ly9jZXJ0aWZpY2F0ZXMudHJ1c3RlZHNl\n"
    "cnZpY2VzLmludGVsLmNvbS9JbnRlbFNHWFJvb3RDQS5jcmwwHQYDVR0OBBYEFNDo\n"
    "qtp11/kuSReYPHsUZdDV8llNMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAG\n"
    "AQH/AgEAMAoGCCqGSM49BAMCA0cAMEQCIC/9j+84T+HztVO/sOQBWJbSd+/2uexK\n"
    "4+aA0jcFBLcpAiA3dhMrF5cD52t6FqMvAIpj8XdGmy2beeljLJK+pzpcRA==\n"
    "-----END CERTIFICATE-----\n"
    "-----BEGIN CERTIFICATE-----\n"
    "Not a valid cert"
    "-----END CERTIFICATE-----\n";

// Test data of a valid Certificate Revocation List (CRL) that is X.509 PEM
// encoded.
constexpr char kPemCrl[] =
    "-----BEGIN X509 CRL-----\n"
    "MIIBKTCB0QIBATAKBggqhkjOPQQDAjBxMSMwIQYDVQQDDBpJbnRlbCBTR1ggUENLIFByb2\n"
    "Nlc3NvciBDQTEaMBgGA1UECgwRSW50ZWwgQ29ycG9yYXRpb24xFDASBgNVBAcMC1NhbnRh\n"
    "IENsYXJhMQswCQYDVQQIDAJDQTELMAkGA1UEBhMCVVMXDTE5MDYxMjE0MjM0N1oXDTE5MD\n"
    "cxMjE0MjM0N1qgLzAtMAoGA1UdFAQDAgEBMB8GA1UdIwQYMBaAFNDoqtp11/kuSReYPHsU\n"
    "ZdDV8llNMAoGCCqGSM49BAMCA0cAMEQCIF+xkFb6+0dhH7KaUVWyLWGsvVCu9ikcYa46Ue\n"
    "nA7pdmAiAiGfZm4dRz7CzIPGXxigN/zrvaggra8k3q2C3QMjH5ig==\n"
    "-----END X509 CRL-----\n";

// Test data of a CertificateRevocationList proto that is parsed from a X.509
// PEM-encoded string.
constexpr char kProtoPemCrl[] = R"proto(
  format: X509_PEM
  data: "-----BEGIN X509 CRL-----\n"
        "MIIBKTCB0QIBATAKBggqhkjOPQQDAjBxMSMwIQYDVQQDDBpJbnRlbCBTR1ggUENLIFByb2"
        "\nNlc3NvciBDQTEaMBgGA1UECgwRSW50ZWwgQ29ycG9yYXRpb24xFDASBgNVBAcMC1Nhbn"
        "Rh\nIENsYXJhMQswCQYDVQQIDAJDQTELMAkGA1UEBhMCVVMXDTE5MDYxMjE0MjM0N1oXDT"
        "E5MD\ncxMjE0MjM0N1qgLzAtMAoGA1UdFAQDAgEBMB8GA1UdIwQYMBaAFNDoqtp11/kuSR"
        "eYPHsU\nZdDV8llNMAoGCCqGSM49BAMCA0cAMEQCIF+xkFb6+0dhH7KaUVWyLWGsvVCu9i"
        "kcYa46Ue\nnA7pdmAiAiGfZm4dRz7CzIPGXxigN/zrvaggra8k3q2C3QMjH5ig==\n"
        "-----END X509 CRL-----\n"
)proto";

using ::testing::Eq;
using ::testing::Optional;
using ::testing::SizeIs;

// Returns a valid (according to ValidateCertificateSigningRequest())
// CertificateSigningRequest message.
CertificateSigningRequest CreateValidCertificateSigningRequest() {
  CertificateSigningRequest csr;
  csr.set_format(CertificateSigningRequest::PKCS10_PEM);
  csr.set_data("foobar");
  return csr;
}

// Returns a valid (according to ValidateCertificate()) Certificate message.
Certificate CreateValidCertificate() {
  Certificate certificate;
  certificate.set_format(Certificate::X509_PEM);
  certificate.set_data("foobar");
  return certificate;
}

// Returns a valid (according to ValidateCertificateChain()) CertificateChain
// message containing |length| certificates.
CertificateChain CreateValidCertificateChain(int length) {
  CertificateChain certificate_chain;
  for (int i = 0; i < length; ++i) {
    *certificate_chain.add_certificates() = CreateValidCertificate();
  }
  return certificate_chain;
}

// Returns a valid (according to ValidateCertificateRevocationList())
// CertificateRevocationList message.
CertificateRevocationList CreateValidCertificateRevocationList() {
  CertificateRevocationList crl;
  crl.set_format(CertificateRevocationList::X509_PEM);
  crl.set_data("foobar");
  return crl;
}

TEST(CertificateUtilTest,
     ValidateCertificateSigningRequestReturnsErrorIfNoFormat) {
  CertificateSigningRequest csr = CreateValidCertificateSigningRequest();
  csr.clear_format();
  EXPECT_THAT(ValidateCertificateSigningRequest(csr),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(CertificateUtilTest,
     ValidateCertificateSigningRequestReturnsErrorIfUnknownFormat) {
  CertificateSigningRequest csr = CreateValidCertificateSigningRequest();
  csr.set_format(CertificateSigningRequest::UNKNOWN);
  EXPECT_THAT(ValidateCertificateSigningRequest(csr),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(CertificateUtilTest,
     ValidateCertificateSigningRequestReturnsErrorIfNoData) {
  CertificateSigningRequest csr = CreateValidCertificateSigningRequest();
  csr.clear_data();
  EXPECT_THAT(ValidateCertificateSigningRequest(csr),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(CertificateUtilTest,
     ValidateCertificateSigningRequestSucceedsIfCsrIsValid) {
  ASYLO_EXPECT_OK(ValidateCertificateSigningRequest(
      CreateValidCertificateSigningRequest()));
}

TEST(CertificateUtilTest, ValidateCertificateReturnsErrorIfNoFormat) {
  Certificate certificate = CreateValidCertificate();
  certificate.clear_format();
  EXPECT_THAT(ValidateCertificate(certificate),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(CertificateUtilTest, ValidateCertificateReturnsErrorIfUnknownFormat) {
  Certificate certificate = CreateValidCertificate();
  certificate.set_format(Certificate::UNKNOWN);
  EXPECT_THAT(ValidateCertificate(certificate),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(CertificateUtilTest, ValidateCertificateReturnsErrorIfNoData) {
  Certificate certificate = CreateValidCertificate();
  certificate.clear_data();
  EXPECT_THAT(ValidateCertificate(certificate),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(CertificateUtilTest, ValidateCertificateSucceedsIfCertificateIsValid) {
  ASYLO_EXPECT_OK(ValidateCertificate(CreateValidCertificate()));
}

TEST(CertificateUtilTest,
     ValidateCertificateChainFailsIfAContainedCertificateIsInvalid) {
  CertificateChain certificate_chain = CreateValidCertificateChain(1);
  certificate_chain.mutable_certificates(0)->clear_format();
  EXPECT_THAT(ValidateCertificateChain(certificate_chain),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));

  certificate_chain = CreateValidCertificateChain(5);
  certificate_chain.mutable_certificates(1)->clear_format();
  EXPECT_THAT(ValidateCertificateChain(certificate_chain),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(CertificateUtilTest,
     ValidateCertificateChainSucceedsIfCertificateChainIsValid) {
  ASYLO_EXPECT_OK(ValidateCertificateChain(CreateValidCertificateChain(0)));
  ASYLO_EXPECT_OK(ValidateCertificateChain(CreateValidCertificateChain(1)));
  ASYLO_EXPECT_OK(ValidateCertificateChain(CreateValidCertificateChain(27)));
}

TEST(CertificateUtilTest,
     ValidateCertificateRevocationListReturnsErrorIfNoFormat) {
  CertificateRevocationList crl = CreateValidCertificateRevocationList();
  crl.clear_format();
  EXPECT_THAT(ValidateCertificateRevocationList(crl),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(CertificateUtilTest,
     ValidateCertificateRevocationListReturnsErrorIfUnknownFormat) {
  CertificateRevocationList crl = CreateValidCertificateRevocationList();
  crl.set_format(CertificateRevocationList::UNKNOWN);
  EXPECT_THAT(ValidateCertificateRevocationList(crl),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(CertificateUtilTest,
     ValidateCertificateRevocationListReturnsErrorIfNoData) {
  CertificateRevocationList crl = CreateValidCertificateRevocationList();
  crl.clear_data();
  EXPECT_THAT(ValidateCertificateRevocationList(crl),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(CertificateUtilTest,
     ValidateCertificateRevocationListSucceedsIfCrlIsValid) {
  ASYLO_EXPECT_OK(ValidateCertificateRevocationList(
      CreateValidCertificateRevocationList()));
}

CertificateChain TestCertificateChain() {
  CertificateChain chain;

  FakeCertificateProto end_cert_proto;
  end_cert_proto.set_subject_key(kEndUserKey);
  end_cert_proto.set_issuer_key(kIntermediateKey);

  Certificate end_cert;
  end_cert.set_format(Certificate::X509_PEM);
  end_cert_proto.SerializeToString(end_cert.mutable_data());
  *chain.add_certificates() = end_cert;

  FakeCertificateProto intermediate_cert_proto;
  intermediate_cert_proto.set_subject_key(kIntermediateKey);
  intermediate_cert_proto.set_issuer_key(kRootKey);
  intermediate_cert_proto.set_is_ca(true);
  intermediate_cert_proto.set_pathlength(0);

  Certificate intermediate_cert;
  intermediate_cert.set_format(Certificate::X509_DER);
  intermediate_cert_proto.SerializeToString(intermediate_cert.mutable_data());
  *chain.add_certificates() = intermediate_cert;

  FakeCertificateProto root_cert_proto;
  root_cert_proto.set_subject_key(kRootKey);
  root_cert_proto.set_issuer_key(kRootKey);
  root_cert_proto.set_is_ca(true);
  root_cert_proto.set_pathlength(1);

  Certificate root_cert;
  root_cert.set_format(Certificate::X509_PEM);
  root_cert_proto.SerializeToString(root_cert.mutable_data());
  *chain.add_certificates() = root_cert;

  return chain;
}

CertificateFactoryMap CreateFactoryMap(
    std::vector<Certificate::CertificateFormat> formats) {
  CertificateFactoryMap factory_map;
  for (Certificate::CertificateFormat format : formats) {
    factory_map.emplace(format, FakeCertificate::Create);
  }
  return factory_map;
}

TEST(CertificateUtilTest, VerifyCertificateChainSuccessWithPathLengths) {
  CertificateInterfaceVector chain;
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kEndUserKey, kIntermediateKey, /*is_ca=*/absl::nullopt,
      /*pathlength=*/absl::nullopt));
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kIntermediateKey, kRootKey, /*is_ca=*/absl::nullopt, /*pathlength=*/0));
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kRootKey, kRootKey, /*is_ca=*/absl::nullopt, /*pathlength=*/1));

  VerificationConfig config(/*all_fields=*/true);
  ASYLO_EXPECT_OK(VerifyCertificateChain(absl::MakeConstSpan(chain), config));
}

TEST(CertificateUtilTest, VerifyCertificateChainSuccessWithoutPathLengths) {
  CertificateInterfaceVector chain;
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kEndUserKey, kIntermediateKey, /*is_ca=*/absl::nullopt,
      /*pathlength=*/absl::nullopt));
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kIntermediateKey, kRootKey, /*is_ca=*/true,
      /*pathlength=*/absl::nullopt));
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kRootKey, kRootKey,
      /*is_ca=*/false, /*pathlength=*/absl::nullopt));

  VerificationConfig config(/*all_fields=*/true);
  ASYLO_EXPECT_OK(VerifyCertificateChain(absl::MakeConstSpan(chain), config));
}

TEST(CertificateUtilTest, VerifyCertificateChainVerificationErrorForwarded) {
  CertificateInterfaceVector chain;
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kEndUserKey, kExtraIntermediateKey, /*is_ca=*/absl::nullopt,
      /*pathlength=*/absl::nullopt));
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kIntermediateKey, kRootKey, /*is_ca=*/absl::nullopt, /*pathlength=*/0));
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kRootKey, kRootKey, /*is_ca=*/absl::nullopt, /*pathlength=*/1));

  VerificationConfig config(/*all_fields=*/false);
  EXPECT_THAT(VerifyCertificateChain(absl::MakeConstSpan(chain), config),
              StatusIs(error::GoogleError::UNAUTHENTICATED));
}

TEST(CertificateUtilTest, VerifyCertificateChainBadRootPathlen) {
  CertificateInterfaceVector chain;
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kEndUserKey, kIntermediateKey, /*is_ca=*/absl::nullopt,
      /*pathlength=*/absl::nullopt));
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kIntermediateKey, kRootKey, /*is_ca=*/absl::nullopt, /*pathlength=*/0));
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kRootKey, kRootKey, /*is_ca=*/absl::nullopt, /*pathlength=*/0));

  VerificationConfig config(/*all_fields=*/true);
  EXPECT_THAT(VerifyCertificateChain(absl::MakeConstSpan(chain), config),
              StatusIs(error::GoogleError::UNAUTHENTICATED));
}

TEST(CertificateUtilTest, VerifyCertificateChainBadIntermediatePathlen) {
  CertificateInterfaceVector chain;
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kEndUserKey, kExtraIntermediateKey, /*is_ca=*/absl::nullopt,
      /*pathlength=*/absl::nullopt));
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kExtraIntermediateKey, kIntermediateKey, /*is_ca=*/absl::nullopt,
      /*pathlength=*/0));
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kIntermediateKey, kRootKey, /*is_ca=*/absl::nullopt, /*pathlength=*/0));
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kRootKey, kRootKey, /*is_ca=*/absl::nullopt, /*pathlength=*/2));

  VerificationConfig config(/*all_fields=*/true);
  EXPECT_THAT(VerifyCertificateChain(absl::MakeConstSpan(chain), config),
              StatusIs(error::GoogleError::UNAUTHENTICATED));
}

TEST(CertificateUtilTest, VerifyCertificateChainBadPathlenNoCheck) {
  CertificateInterfaceVector chain;
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kEndUserKey, kIntermediateKey, /*is_ca=*/absl::nullopt,
      /*pathlength=*/absl::nullopt));
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kIntermediateKey, kRootKey, /*is_ca=*/absl::nullopt, /*pathlength=*/0));
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kRootKey, kRootKey, /*is_ca=*/absl::nullopt, /*pathlength=*/0));

  VerificationConfig config(/*all_fields=*/false);
  ASYLO_EXPECT_OK(VerifyCertificateChain(absl::MakeConstSpan(chain), config));
}

TEST(CertificateUtilTest, VerifyCertificateChainCaValuesSet) {
  CertificateInterfaceVector chain;
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kEndUserKey, kExtraIntermediateKey, /*is_ca=*/false,
      /*pathlength=*/absl::nullopt));
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kExtraIntermediateKey, kIntermediateKey, /*is_ca=*/false,
      /*pathlength=*/absl::nullopt));
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kIntermediateKey, kRootKey, /*is_ca=*/true, /*pathlength=*/0));
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kRootKey, kRootKey, /*is_ca=*/true, /*pathlength=*/1));

  VerificationConfig config(/*all_fields=*/true);
  ASYLO_EXPECT_OK(VerifyCertificateChain(absl::MakeConstSpan(chain), config));
}

TEST(CertificateUtilTest, CreateCertificateInterfaceMissingFormat) {
  FakeCertificateProto cert_proto;
  cert_proto.set_subject_key(kRootKey);
  cert_proto.set_issuer_key(kRootKey);

  Certificate cert;
  cert.set_format(Certificate::X509_PEM);
  cert_proto.SerializeToString(cert.mutable_data());

  CertificateFactoryMap factory_map = CreateFactoryMap({Certificate::X509_DER});

  EXPECT_THAT(CreateCertificateInterface(factory_map, cert),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(CertificateUtilTest, CreateCertificateInterfaceMalformedCertificate) {
  Certificate cert;
  cert.set_format(Certificate::X509_PEM);
  cert.set_data(kMalformedCertData);

  CertificateFactoryMap factory_map = CreateFactoryMap({Certificate::X509_DER});

  EXPECT_THAT(CreateCertificateInterface(factory_map, cert),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(CertificateUtilTest, CreateCertificateInterfaceSuccess) {
  FakeCertificate expected_cert(kRootKey, kRootKey, /*is_ca=*/absl::nullopt,
                                /*pathlength=*/absl::nullopt);

  FakeCertificateProto cert_proto;
  cert_proto.set_subject_key(kRootKey);
  cert_proto.set_issuer_key(kRootKey);

  Certificate cert;
  cert.set_format(Certificate::X509_PEM);
  cert_proto.SerializeToString(cert.mutable_data());

  CertificateFactoryMap factory_map = CreateFactoryMap({Certificate::X509_PEM});

  std::unique_ptr<CertificateInterface> certificate_interface;
  ASYLO_ASSERT_OK_AND_ASSIGN(certificate_interface,
                             CreateCertificateInterface(factory_map, cert));
  EXPECT_EQ(*certificate_interface, expected_cert);
}

TEST(CertificateUtilTest, CreateCertificateChainMissingFormat) {
  CertificateFactoryMap factory_map = CreateFactoryMap({Certificate::X509_PEM});
  EXPECT_THAT(CreateCertificateChain(factory_map, TestCertificateChain()),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(CertificateUtilTest, CreateCertificateChainMalformedCertificate) {
  CertificateFactoryMap factory_map = CreateFactoryMap({Certificate::X509_PEM});
  CertificateChain chain;
  Certificate *malformed_cert = chain.add_certificates();
  malformed_cert->set_format(Certificate::X509_PEM);
  malformed_cert->set_data(kMalformedCertData);

  EXPECT_THAT(CreateCertificateChain(factory_map, chain),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(CertificateUtilTest, CreateCertificateChainSuccess) {
  CertificateFactoryMap factory_map =
      CreateFactoryMap({Certificate::X509_PEM, Certificate::X509_DER});

  CertificateInterfaceVector chain;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      chain, CreateCertificateChain(factory_map, TestCertificateChain()));
  ASSERT_THAT(chain, SizeIs(3));

  EXPECT_THAT(chain[2]->SubjectKeyDer(), IsOkAndHolds(kRootKey));
  EXPECT_THAT(chain[2]->CertPathLength(), Optional(1));
  EXPECT_THAT(chain[2]->IsCa(), Optional(true));
  EXPECT_THAT(chain[1]->SubjectKeyDer(), IsOkAndHolds(kIntermediateKey));
  EXPECT_THAT(chain[1]->CertPathLength(), Optional(0));
  EXPECT_THAT(chain[1]->IsCa(), Optional(true));
  EXPECT_THAT(chain[0]->SubjectKeyDer(), IsOkAndHolds(kEndUserKey));
  EXPECT_THAT(chain[0]->CertPathLength(), Eq(absl::nullopt));
  EXPECT_THAT(chain[0]->IsCa(), Eq(absl::nullopt));
}

TEST(CertificateUtilTest, GetCertificateFromPem_Success) {
  Certificate cert;
  ASYLO_ASSERT_OK_AND_ASSIGN(cert, GetCertificateFromPem(kPemCert));
  Certificate expected_cert;
  ASSERT_TRUE(
      google::protobuf::TextFormat::ParseFromString(kProtoPemCert, &expected_cert));
  EXPECT_THAT(cert, EqualsProto(expected_cert));
}

TEST(GetCertFromPemTest, GetCertificateFromPem_NonPemCertFailsToParse) {
  EXPECT_THAT(GetCertificateFromPem("Not a PEM cert"),
              StatusIs(error::GoogleError::INTERNAL));
}

TEST(CertificateUtilTest, GetCertificateChain_Success) {
  CertificateChain cert_chain;
  ASYLO_ASSERT_OK_AND_ASSIGN(cert_chain,
                             GetCertificateChainFromPem(kPemCertChain));
  CertificateChain expected_cert_chain;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(kProtoPemCertChain,
                                                  &expected_cert_chain));
  EXPECT_THAT(cert_chain, EqualsProto(expected_cert_chain));
}

TEST(CertificateUtilTest,
     GetCertificateChain_CertChainWithExtraPaddingParsesSuccessfully) {
  CertificateChain cert_chain;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      cert_chain, GetCertificateChainFromPem(kPemCertChainWithExtraPadding));
  CertificateChain expected_cert_chain;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(kProtoPemCertChain,
                                                  &expected_cert_chain));
  EXPECT_THAT(cert_chain, EqualsProto(expected_cert_chain));
}

TEST(CertificateUtilTest,
     GetCertificateChainFromPem_NonPemCertChainFailsToParse) {
  EXPECT_THAT(GetCertificateChainFromPem("Not a PEM cert chain"),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(CertificateUtilTest,
     GetCertificateChainFromPem_CertChainWithOneInvalidCertFailsToParse) {
  EXPECT_THAT(GetCertificateChainFromPem(kPemCertChainWithOneInvalidCert),
              StatusIs(error::GoogleError::INTERNAL));
}

TEST(CertificateUtilTest, GetCrlFromPemTest_Success) {
  asylo::CertificateRevocationList crl;
  ASYLO_ASSERT_OK_AND_ASSIGN(crl, GetCrlFromPem(kPemCrl));
  asylo::CertificateRevocationList expected_crl;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(kProtoPemCrl, &expected_crl));
  EXPECT_THAT(crl, EqualsProto(expected_crl));
}

}  // namespace
}  // namespace asylo
