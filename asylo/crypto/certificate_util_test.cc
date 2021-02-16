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
#include "absl/status/status.h"
#include "absl/types/optional.h"
#include "absl/types/span.h"
#include "asylo/crypto/certificate.pb.h"
#include "asylo/crypto/certificate_interface.h"
#include "asylo/crypto/fake_certificate.h"
#include "asylo/crypto/fake_certificate.pb.h"
#include "asylo/test/util/proto_matchers.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/proto_parse_util.h"

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

constexpr char kDerCert[] =
    "\x30\x82\x04\x81\x30\x82\x04\x27\xa0\x03\x02\x01\x02\x02\x15\x00\x9d\x66"
    "\xc4\x32\x33\x01\x76\xbe\x8b\x17\x14\x28\xa6\x94\x9b\x26\x31\xa3\x22\x65"
    "\x30\x0a\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02\x30\x71\x31\x23\x30\x21"
    "\x06\x03\x55\x04\x03\x0c\x1a\x49\x6e\x74\x65\x6c\x20\x53\x47\x58\x20\x50"
    "\x43\x4b\x20\x50\x72\x6f\x63\x65\x73\x73\x6f\x72\x20\x43\x41\x31\x1a\x30"
    "\x18\x06\x03\x55\x04\x0a\x0c\x11\x49\x6e\x74\x65\x6c\x20\x43\x6f\x72\x70"
    "\x6f\x72\x61\x74\x69\x6f\x6e\x31\x14\x30\x12\x06\x03\x55\x04\x07\x0c\x0b"
    "\x53\x61\x6e\x74\x61\x20\x43\x6c\x61\x72\x61\x31\x0b\x30\x09\x06\x03\x55"
    "\x04\x08\x0c\x02\x43\x41\x31\x0b\x30\x09\x06\x03\x55\x04\x06\x13\x02\x55"
    "\x53\x30\x1e\x17\x0d\x31\x39\x30\x34\x30\x33\x32\x31\x31\x36\x33\x31\x5a"
    "\x17\x0d\x32\x36\x30\x34\x30\x33\x32\x31\x31\x36\x33\x31\x5a\x30\x70\x31"
    "\x22\x30\x20\x06\x03\x55\x04\x03\x0c\x19\x49\x6e\x74\x65\x6c\x20\x53\x47"
    "\x58\x20\x50\x43\x4b\x20\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x31"
    "\x1a\x30\x18\x06\x03\x55\x04\x0a\x0c\x11\x49\x6e\x74\x65\x6c\x20\x43\x6f"
    "\x72\x70\x6f\x72\x61\x74\x69\x6f\x6e\x31\x14\x30\x12\x06\x03\x55\x04\x07"
    "\x0c\x0b\x53\x61\x6e\x74\x61\x20\x43\x6c\x61\x72\x61\x31\x0b\x30\x09\x06"
    "\x03\x55\x04\x08\x0c\x02\x43\x41\x31\x0b\x30\x09\x06\x03\x55\x04\x06\x13"
    "\x02\x55\x53\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08"
    "\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00\x04\x17\xb6\x82\x25\x0c\xc6"
    "\x47\xb4\x7f\xa1\xe0\xe4\xbb\x28\x85\x86\x49\xd5\x5d\x5e\x26\x2a\x5e\xf6"
    "\x41\x40\x83\xfb\x4d\x82\x4b\xe6\xb4\x01\x49\xc9\xb4\xac\xf7\xec\x49\x80"
    "\xc9\xde\x5a\x7c\x9d\xfc\x74\x5b\x30\x3c\x52\xf5\xba\x92\xd8\xef\x2a\xc4"
    "\x72\x8f\x7d\xde\xa3\x82\x02\x9b\x30\x82\x02\x97\x30\x1f\x06\x03\x55\x1d"
    "\x23\x04\x18\x30\x16\x80\x14\xd0\xe8\xaa\xda\x75\xd7\xf9\x2e\x49\x17\x98"
    "\x3c\x7b\x14\x65\xd0\xd5\xf2\x59\x4d\x30\x5f\x06\x03\x55\x1d\x1f\x04\x58"
    "\x30\x56\x30\x54\xa0\x52\xa0\x50\x86\x4e\x68\x74\x74\x70\x73\x3a\x2f\x2f"
    "\x61\x70\x69\x2e\x74\x72\x75\x73\x74\x65\x64\x73\x65\x72\x76\x69\x63\x65"
    "\x73\x2e\x69\x6e\x74\x65\x6c\x2e\x63\x6f\x6d\x2f\x73\x67\x78\x2f\x63\x65"
    "\x72\x74\x69\x66\x69\x63\x61\x74\x69\x6f\x6e\x2f\x76\x31\x2f\x70\x63\x6b"
    "\x63\x72\x6c\x3f\x63\x61\x3d\x70\x72\x6f\x63\x65\x73\x73\x6f\x72\x30\x1d"
    "\x06\x03\x55\x1d\x0e\x04\x16\x04\x14\x14\x14\xe4\x33\xc7\x68\xa0\x7f\x39"
    "\xb5\x8d\xd8\x1a\x55\x75\x32\xd6\x6c\xd7\x31\x30\x0e\x06\x03\x55\x1d\x0f"
    "\x01\x01\xff\x04\x04\x03\x02\x06\xc0\x30\x0c\x06\x03\x55\x1d\x13\x01\x01"
    "\xff\x04\x02\x30\x00\x30\x82\x01\xd4\x06\x09\x2a\x86\x48\x86\xf8\x4d\x01"
    "\x0d\x01\x04\x82\x01\xc5\x30\x82\x01\xc1\x30\x1e\x06\x0a\x2a\x86\x48\x86"
    "\xf8\x4d\x01\x0d\x01\x01\x04\x10\x7b\x97\xbe\x77\xc6\x2d\x42\x46\xc6\x03"
    "\xd0\xf4\xf1\x1b\x31\xbb\x30\x82\x01\x64\x06\x0a\x2a\x86\x48\x86\xf8\x4d"
    "\x01\x0d\x01\x02\x30\x82\x01\x54\x30\x10\x06\x0b\x2a\x86\x48\x86\xf8\x4d"
    "\x01\x0d\x01\x02\x01\x02\x01\x05\x30\x10\x06\x0b\x2a\x86\x48\x86\xf8\x4d"
    "\x01\x0d\x01\x02\x02\x02\x01\x05\x30\x10\x06\x0b\x2a\x86\x48\x86\xf8\x4d"
    "\x01\x0d\x01\x02\x03\x02\x01\x02\x30\x10\x06\x0b\x2a\x86\x48\x86\xf8\x4d"
    "\x01\x0d\x01\x02\x04\x02\x01\x04\x30\x10\x06\x0b\x2a\x86\x48\x86\xf8\x4d"
    "\x01\x0d\x01\x02\x05\x02\x01\x01\x30\x11\x06\x0b\x2a\x86\x48\x86\xf8\x4d"
    "\x01\x0d\x01\x02\x06\x02\x02\x00\x80\x30\x10\x06\x0b\x2a\x86\x48\x86\xf8"
    "\x4d\x01\x0d\x01\x02\x07\x02\x01\x00\x30\x10\x06\x0b\x2a\x86\x48\x86\xf8"
    "\x4d\x01\x0d\x01\x02\x08\x02\x01\x00\x30\x10\x06\x0b\x2a\x86\x48\x86\xf8"
    "\x4d\x01\x0d\x01\x02\x09\x02\x01\x00\x30\x10\x06\x0b\x2a\x86\x48\x86\xf8"
    "\x4d\x01\x0d\x01\x02\x0a\x02\x01\x00\x30\x10\x06\x0b\x2a\x86\x48\x86\xf8"
    "\x4d\x01\x0d\x01\x02\x0b\x02\x01\x00\x30\x10\x06\x0b\x2a\x86\x48\x86\xf8"
    "\x4d\x01\x0d\x01\x02\x0c\x02\x01\x00\x30\x10\x06\x0b\x2a\x86\x48\x86\xf8"
    "\x4d\x01\x0d\x01\x02\x0d\x02\x01\x00\x30\x10\x06\x0b\x2a\x86\x48\x86\xf8"
    "\x4d\x01\x0d\x01\x02\x0e\x02\x01\x00\x30\x10\x06\x0b\x2a\x86\x48\x86\xf8"
    "\x4d\x01\x0d\x01\x02\x0f\x02\x01\x00\x30\x10\x06\x0b\x2a\x86\x48\x86\xf8"
    "\x4d\x01\x0d\x01\x02\x10\x02\x01\x00\x30\x10\x06\x0b\x2a\x86\x48\x86\xf8"
    "\x4d\x01\x0d\x01\x02\x11\x02\x01\x07\x30\x1f\x06\x0b\x2a\x86\x48\x86\xf8"
    "\x4d\x01\x0d\x01\x02\x12\x04\x10\x05\x05\x02\x04\x01\x80\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x30\x10\x06\x0a\x2a\x86\x48\x86\xf8\x4d\x01\x0d"
    "\x01\x03\x04\x02\x00\x00\x30\x14\x06\x0a\x2a\x86\x48\x86\xf8\x4d\x01\x0d"
    "\x01\x04\x04\x06\x00\x90\x6e\xa1\x00\x00\x30\x0f\x06\x0a\x2a\x86\x48\x86"
    "\xf8\x4d\x01\x0d\x01\x05\x0a\x01\x00\x30\x0a\x06\x08\x2a\x86\x48\xce\x3d"
    "\x04\x03\x02\x03\x48\x00\x30\x45\x02\x21\x00\xae\x9a\x2a\x8c\xd3\x16\xcd"
    "\x91\x2a\x2f\x82\x80\xcf\x66\x53\x0b\xa4\xb3\x86\x95\x06\x4a\x22\x26\x1d"
    "\x38\x2a\x89\x84\x3e\x2f\x62\x02\x20\x79\xde\xcb\x76\x6d\x42\x51\x50\x4f"
    "\x11\xf0\x44\x95\xb9\xfd\x40\xc4\xb6\x69\x23\x6c\x12\x52\x00\xb4\x39\x53"
    "\x67\x41\x5e\x4f\x95";

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

constexpr char kProtoAttestationKeyCert[] = R"proto(
  format: SGX_ATTESTATION_KEY_CERTIFICATE
  data: "\n\263\003\n\260\003\000\000\000\000\000\000\000\000\000\000\000\000"
        "\000\000\000\000\001\000\000\000\000\000\000\000\000\000\000\000\000"
        "\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000"
        "\000\000\'\000\000\000\000\000\000\000\'\000\000\000\000\000\000\000"
        "\260\365\210%\302mRw\302\n\252\357;4\223\252\374\357p\363iW\263\331"
        "\007\022\356,\226\263\366R\000\000\000\000\000\000\000\000\000\000\000"
        "\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000"
        "\000\000\000\000\275\361\343\231\220Q\014\371B\237\256_\246Kl\323\232g"
        "\311\231X\240\020;\251\276yH\252\347\336\014\000\000\000\000\000\000"
        "\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000"
        "\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000"
        "\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000"
        "\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000"
        "\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000"
        "\000\000\000\000\000\036,8\234\000\000\000\000\000\000\000\000\000\000"
        "\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000"
        "\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000"
        "\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\026M"
        "\304IJ\026L0\257\257\263?K\273\357wPle\261\324\217\344\244w)YJ\206\342"
        "\257\372\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000"
        "\000ASYLO SIGNREPORT\000\000\000\000\000\000\000\000\000\000\000\000"
        "\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000"
        "\000\000\000\342T=\274\262\307j\023\000\036\n\232\240rRi\022\335\001\n"
        "\304\001\nc\010\002\020\001\030\002\"[0Y0\023\006\007*\206H\316=\002"
        "\001\006\010*\206H\316=\003\001\007\003B\000\004\273i\362\351\001\331&"
        "\331\327\347F\235i\001v\371\004\024\213\226\210~\211\016[\261\262\034`"
        "\030\310S3\366U\000\312&\231\324p.\311\211\206\314\014\020\240\377\023"
        "\2567Qz\2569&2\214?\013\202h\0220Assertion Generator Enclave "
        "Attestation Key v0.1\032+Assertion Generator Enclave Attestation Key"
        "\022\024PCE Sign Report v0.1\032H\010\001\022D\n \246\246\343\277W\212"
        "\247\273#k\256L\371\016\262\326\234\347\003\303ST\310`\202o\212\215BM"
        "\233}\022 \263u\356K\241.ah\211\353\260\255GH\234s\307\227\177\240S"
        "\304\004v\302\356\230R\361\'\235Q"
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
  certificate.set_data(kPemCert);
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
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(CertificateUtilTest,
     ValidateCertificateSigningRequestReturnsErrorIfUnknownFormat) {
  CertificateSigningRequest csr = CreateValidCertificateSigningRequest();
  csr.set_format(CertificateSigningRequest::UNKNOWN);
  EXPECT_THAT(ValidateCertificateSigningRequest(csr),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(CertificateUtilTest,
     ValidateCertificateSigningRequestReturnsErrorIfNoData) {
  CertificateSigningRequest csr = CreateValidCertificateSigningRequest();
  csr.clear_data();
  EXPECT_THAT(ValidateCertificateSigningRequest(csr),
              StatusIs(absl::StatusCode::kInvalidArgument));
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
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(FullyValidateCertificate(certificate),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(CertificateUtilTest, ValidateCertificateReturnsErrorIfUnknownFormat) {
  Certificate certificate = CreateValidCertificate();
  certificate.set_format(Certificate::UNKNOWN);
  EXPECT_THAT(ValidateCertificate(certificate),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(FullyValidateCertificate(certificate),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(CertificateUtilTest, ValidateCertificateReturnsErrorIfNoData) {
  Certificate certificate = CreateValidCertificate();
  certificate.clear_data();
  EXPECT_THAT(ValidateCertificate(certificate),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(FullyValidateCertificate(certificate),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(CertificateUtilTest,
     FullyValidateCertificateReturnsErrorIfPemDataIsInvalid) {
  EXPECT_THAT(FullyValidateCertificate(ParseTextProtoOrDie(R"pb(
                format: X509_PEM
                data: "nope, not valid"
              )pb")),
              StatusIs(absl::StatusCode::kInternal));
}

TEST(CertificateUtilTest,
     FullyValidateCertificateReturnsErrorIfDerDataIsInvalid) {
  EXPECT_THAT(FullyValidateCertificate(ParseTextProtoOrDie(R"pb(
                format: X509_DER
                data: "junk data"
              )pb")),
              StatusIs(absl::StatusCode::kInternal));
}

TEST(CertificateUtilTest,
     FullyValidateCertificateReturnsErrorIfSgxAttestationKeyCertIsInvalid) {
  EXPECT_THAT(FullyValidateCertificate(ParseTextProtoOrDie(R"pb(
                format: SGX_ATTESTATION_KEY_CERTIFICATE
                data: "totally bogus"
              )pb")),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(CertificateUtilTest, FullyValidateCertificateSucceedsWithValidPem) {
  Certificate certificate;
  certificate.set_format(Certificate::X509_PEM);
  certificate.set_data(kPemCert);
  ASYLO_EXPECT_OK(FullyValidateCertificate(certificate));
}

TEST(CertificateUtilTest, FullyValidateCertificateSucceedsWithValidDer) {
  Certificate certificate;
  certificate.set_format(Certificate::X509_DER);
  certificate.set_data(kDerCert, sizeof(kDerCert) - 1);
  ASYLO_EXPECT_OK(FullyValidateCertificate(certificate));
}

TEST(CertificateUtilTest,
     FullyValidateCertificateSucceedsWithValidAttestionKeyCertificate) {
  ASYLO_EXPECT_OK(
      FullyValidateCertificate(ParseTextProtoOrDie(kProtoAttestationKeyCert)));
}

TEST(CertificateUtilTest,
     ValidateCertificateChainFailsIfAContainedCertificateIsInvalid) {
  CertificateChain certificate_chain = CreateValidCertificateChain(1);
  certificate_chain.mutable_certificates(0)->clear_format();
  EXPECT_THAT(ValidateCertificateChain(certificate_chain),
              StatusIs(absl::StatusCode::kInvalidArgument));

  certificate_chain = CreateValidCertificateChain(5);
  certificate_chain.mutable_certificates(1)->clear_format();
  EXPECT_THAT(ValidateCertificateChain(certificate_chain),
              StatusIs(absl::StatusCode::kInvalidArgument));
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
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(CertificateUtilTest,
     ValidateCertificateRevocationListReturnsErrorIfUnknownFormat) {
  CertificateRevocationList crl = CreateValidCertificateRevocationList();
  crl.set_format(CertificateRevocationList::UNKNOWN);
  EXPECT_THAT(ValidateCertificateRevocationList(crl),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(CertificateUtilTest,
     ValidateCertificateRevocationListReturnsErrorIfNoData) {
  CertificateRevocationList crl = CreateValidCertificateRevocationList();
  crl.clear_data();
  EXPECT_THAT(ValidateCertificateRevocationList(crl),
              StatusIs(absl::StatusCode::kInvalidArgument));
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
      /*pathlength=*/absl::nullopt, /*subject_name=*/absl::nullopt));
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kIntermediateKey, kRootKey, /*is_ca=*/absl::nullopt, /*pathlength=*/0,
      /*subject_name=*/absl::nullopt));
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kRootKey, kRootKey, /*is_ca=*/absl::nullopt, /*pathlength=*/1,
      /*subject_name=*/absl::nullopt));

  VerificationConfig config(/*all_fields=*/true);
  ASYLO_EXPECT_OK(VerifyCertificateChain(absl::MakeConstSpan(chain), config));
}

TEST(CertificateUtilTest, VerifyCertificateChainSuccessWithoutPathLengths) {
  CertificateInterfaceVector chain;
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kEndUserKey, kIntermediateKey, /*is_ca=*/absl::nullopt,
      /*pathlength=*/absl::nullopt, /*subject_name=*/absl::nullopt));
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kIntermediateKey, kRootKey, /*is_ca=*/true,
      /*pathlength=*/absl::nullopt, /*subject_name=*/absl::nullopt));
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kRootKey, kRootKey,
      /*is_ca=*/false, /*pathlength=*/absl::nullopt,
      /*subject_name=*/absl::nullopt));

  VerificationConfig config(/*all_fields=*/true);
  ASYLO_EXPECT_OK(VerifyCertificateChain(absl::MakeConstSpan(chain), config));
}

TEST(CertificateUtilTest, VerifyCertificateChainVerificationErrorForwarded) {
  CertificateInterfaceVector chain;
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kEndUserKey, kExtraIntermediateKey, /*is_ca=*/absl::nullopt,
      /*pathlength=*/absl::nullopt, /*subject_name=*/absl::nullopt));
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kIntermediateKey, kRootKey, /*is_ca=*/absl::nullopt, /*pathlength=*/0,
      /*subject_name=*/absl::nullopt));
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kRootKey, kRootKey, /*is_ca=*/absl::nullopt, /*pathlength=*/1,
      /*subject_name=*/absl::nullopt));

  VerificationConfig config(/*all_fields=*/false);
  EXPECT_THAT(VerifyCertificateChain(absl::MakeConstSpan(chain), config),
              StatusIs(absl::StatusCode::kUnauthenticated));
}

TEST(CertificateUtilTest, VerifyCertificateChainBadRootPathlen) {
  CertificateInterfaceVector chain;
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kEndUserKey, kIntermediateKey, /*is_ca=*/absl::nullopt,
      /*pathlength=*/absl::nullopt, /*subject_name=*/absl::nullopt));
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kIntermediateKey, kRootKey, /*is_ca=*/absl::nullopt, /*pathlength=*/0,
      /*subject_name=*/absl::nullopt));
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kRootKey, kRootKey, /*is_ca=*/absl::nullopt, /*pathlength=*/0,
      /*subject_name=*/absl::nullopt));

  VerificationConfig config(/*all_fields=*/true);
  EXPECT_THAT(VerifyCertificateChain(absl::MakeConstSpan(chain), config),
              StatusIs(absl::StatusCode::kUnauthenticated));
}

TEST(CertificateUtilTest, VerifyCertificateChainBadIntermediatePathlen) {
  CertificateInterfaceVector chain;
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kEndUserKey, kExtraIntermediateKey, /*is_ca=*/absl::nullopt,
      /*pathlength=*/absl::nullopt, /*subject_name=*/absl::nullopt));
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kExtraIntermediateKey, kIntermediateKey, /*is_ca=*/absl::nullopt,
      /*pathlength=*/0, /*subject_name=*/absl::nullopt));
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kIntermediateKey, kRootKey, /*is_ca=*/absl::nullopt, /*pathlength=*/0,
      /*subject_name=*/absl::nullopt));
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kRootKey, kRootKey, /*is_ca=*/absl::nullopt, /*pathlength=*/2,
      /*subject_name=*/absl::nullopt));

  VerificationConfig config(/*all_fields=*/true);
  EXPECT_THAT(VerifyCertificateChain(absl::MakeConstSpan(chain), config),
              StatusIs(absl::StatusCode::kUnauthenticated));
}

TEST(CertificateUtilTest, VerifyCertificateChainBadPathlenNoCheck) {
  CertificateInterfaceVector chain;
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kEndUserKey, kIntermediateKey, /*is_ca=*/absl::nullopt,
      /*pathlength=*/absl::nullopt, /*subject_name=*/absl::nullopt));
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kIntermediateKey, kRootKey, /*is_ca=*/absl::nullopt, /*pathlength=*/0,
      /*subject_name=*/absl::nullopt));
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kRootKey, kRootKey, /*is_ca=*/absl::nullopt, /*pathlength=*/0,
      /*subject_name=*/absl::nullopt));

  VerificationConfig config(/*all_fields=*/false);
  ASYLO_EXPECT_OK(VerifyCertificateChain(absl::MakeConstSpan(chain), config));
}

TEST(CertificateUtilTest, VerifyCertificateChainCaValuesSet) {
  CertificateInterfaceVector chain;
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kEndUserKey, kExtraIntermediateKey, /*is_ca=*/false,
      /*pathlength=*/absl::nullopt, /*subject_name=*/absl::nullopt));
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kExtraIntermediateKey, kIntermediateKey, /*is_ca=*/false,
      /*pathlength=*/absl::nullopt, /*subject_name=*/absl::nullopt));
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kIntermediateKey, kRootKey, /*is_ca=*/true, /*pathlength=*/0,
      /*subject_name=*/absl::nullopt));
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kRootKey, kRootKey, /*is_ca=*/true, /*pathlength=*/1,
      /*subject_name=*/absl::nullopt));

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
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(CertificateUtilTest, CreateCertificateInterfaceMalformedCertificate) {
  Certificate cert;
  cert.set_format(Certificate::X509_PEM);
  cert.set_data(kMalformedCertData);

  CertificateFactoryMap factory_map = CreateFactoryMap({Certificate::X509_DER});

  EXPECT_THAT(CreateCertificateInterface(factory_map, cert),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(CertificateUtilTest, CreateCertificateInterfaceSuccess) {
  FakeCertificate expected_cert(kRootKey, kRootKey, /*is_ca=*/absl::nullopt,
                                /*pathlength=*/absl::nullopt,
                                /*subject_name=*/absl::nullopt);

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
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(CertificateUtilTest, CreateCertificateChainMalformedCertificate) {
  CertificateFactoryMap factory_map = CreateFactoryMap({Certificate::X509_PEM});
  CertificateChain chain;
  Certificate *malformed_cert = chain.add_certificates();
  malformed_cert->set_format(Certificate::X509_PEM);
  malformed_cert->set_data(kMalformedCertData);

  EXPECT_THAT(CreateCertificateChain(factory_map, chain),
              StatusIs(absl::StatusCode::kInvalidArgument));
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
              StatusIs(absl::StatusCode::kInternal));
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
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(CertificateUtilTest,
     GetCertificateChainFromPem_CertChainWithOneInvalidCertFailsToParse) {
  EXPECT_THAT(GetCertificateChainFromPem(kPemCertChainWithOneInvalidCert),
              StatusIs(absl::StatusCode::kInternal));
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
