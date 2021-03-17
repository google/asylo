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

#include "asylo/identity/provisioning/sgx/internal/sgx_pcs_client_impl.h"

#include <algorithm>
#include <memory>
#include <vector>

#include <google/protobuf/text_format.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/identity/platform/sgx/machine_configuration.pb.h"
#include "asylo/identity/provisioning/sgx/internal/platform_provisioning.pb.h"
#include "asylo/identity/provisioning/sgx/internal/sgx_pcs_client.h"
#include "asylo/identity/provisioning/sgx/internal/sgx_pcs_client.pb.h"
#include "asylo/test/util/proto_matchers.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/error_codes.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace sgx {
namespace {

using ::google::protobuf::TextFormat;
using ::testing::DoAll;
using ::testing::ElementsAreArray;
using ::testing::Eq;
using ::testing::IsEmpty;
using ::testing::NotNull;
using ::testing::Return;
using ::testing::SetArgPointee;
using ::testing::StrictMock;
using ::testing::ValuesIn;
using ::testing::WithParamInterface;

// HTTP header name for the API key.
const char kHttpHeaderApiKey[] = "Ocp-Apim-Subscription-Key";

// The testing Intel PCS API key.
constexpr char kApiKey[] = "deadbeefdeadd00ddeadbeefdeadd00d";

// The expected URL sent by GetPckCertificate.
constexpr char kGetPckCertExpectedUrl[] =
    "https://api.trustedservices.intel.com/sgx/certification/v1/pckcert?enc"
    "rypted_ppid=5caa75aefb87f56c18b377eed358d9f9084a54f435de6292a20cd16d63"
    "34dbf81eee3602c40ceaca5ec702dc5cfc4b740489885781b263566f2152f4b88f0a11"
    "4cdb0ab969d858e9576e17c72a0ed8f1916a25231ecca8e0543509f7996378dcd9ae8e"
    "85d6b340d71389a71c7edaffd5ebfd44d8ff8e16091263bff7b0ea7f0dea6297d38240"
    "50501411f7c9045c4060eceb1587103e9d99d604264f6a856b38e5918b22eb22171f91"
    "f512d731451c56febdeba7290949195b71dd75b915803ea5daec4af7c05b01e0103b6b"
    "843120acf8337b9fe1325366b6f298ced41f0093b05ae14f26e1d2b4fe9f871ce104a9"
    "798f176ee1f4a01199e3d8054bac62f72941f90de0f202e5cc958ec2fec8f66250702d"
    "71685605f5c32d56272fc887aea5a45e4e4bd9c412972cb0f6a83275736e0cec7164b5"
    "44122ec5b81be53d99163b1ee8105d8cf7bba1ab35bd4bf82f6e8d1bb91c0066a80f7e"
    "6ec2a704156d6e28209c06087faabbbe76588aadd9c5c65092c49b001c7ff2cdb8ac65"
    "faa5038b94&cpusvn=05050204018000000000000000000000&pcesvn=0700&pceid=0"
    "000";

// The HTTP header key for the PCK certificate issuer cert chain.
constexpr char kGetPckCertHttpResponseHeaderIssuerCertChainKey[] =
    "SGX-PCK-Certificate-Issuer-Chain";

// The HTTP header value for the PCK certificate issuer cert chain.
constexpr char kGetPckCertHttpResponseHeaderIssuerCertChainValue[] =
    "-----BEGIN%20CERTIFICATE-----%0AMIIClzCCAj6gAwIBAgIVANDoqtp11%2FkuSReY"
    "PHsUZdDV8llNMAoGCCqGSM49BAMC%0AMGgxGjAYBgNVBAMMEUludGVsIFNHWCBSb290IEN"
    "BMRowGAYDVQQKDBFJbnRlbCBD%0Ab3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcm"
    "ExCzAJBgNVBAgMAkNBMQsw%0ACQYDVQQGEwJVUzAeFw0xODA1MjExMDQ1MDhaFw0zMzA1M"
    "jExMDQ1MDhaMHExIzAh%0ABgNVBAMMGkludGVsIFNHWCBQQ0sgUHJvY2Vzc29yIENBMRow"
    "GAYDVQQKDBFJbnRl%0AbCBDb3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzA"
    "JBgNVBAgMAkNB%0AMQswCQYDVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABL"
    "9q%2BNMp2IOg%0Atdl1bk%2FuWZ5%2BTGQm8aCi8z78fs%2BfKCQ3d%2BuDzXnVTAT2ZhD"
    "CifyIuJwvN3wNBp9i%0AHBSSMJMJrBOjgbswgbgwHwYDVR0jBBgwFoAUImUM1lqdNInzg7"
    "SVUr9QGzknBqww%0AUgYDVR0fBEswSTBHoEWgQ4ZBaHR0cHM6Ly9jZXJ0aWZpY2F0ZXMud"
    "HJ1c3RlZHNl%0AcnZpY2VzLmludGVsLmNvbS9JbnRlbFNHWFJvb3RDQS5jcmwwHQYDVR0O"
    "BBYEFNDo%0Aqtp11%2FkuSReYPHsUZdDV8llNMA4GA1UdDwEB%2FwQEAwIBBjASBgNVHRM"
    "BAf8ECDAG%0AAQH%2FAgEAMAoGCCqGSM49BAMCA0cAMEQCIC%2F9j%2B84T%2BHztVO%2F"
    "sOQBWJbSd%2B%2F2uexK%0A4%2BaA0jcFBLcpAiA3dhMrF5cD52t6FqMvAIpj8XdGmy2be"
    "eljLJK%2BpzpcRA%3D%3D%0A-----END%20CERTIFICATE-----%0A-----BEGIN%20CER"
    "TIFICATE-----%0AMIICjjCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKo"
    "ZIzj0EAwIw%0AaDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUlud"
    "GVsIENv%0AcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0Ex"
    "CzAJ%0ABgNVBAYTAlVTMB4XDTE4MDUyMTEwNDExMVoXDTMzMDUyMTEwNDExMFowaDEaMBg"
    "G%0AA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0%0"
    "AaW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT%0AAl"
    "VTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj%2FiPWsCzaEKi7%0A1Oi"
    "OSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB%0AuzCBuD"
    "AfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ%0AMEegRaBDh"
    "kFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50%0AZWwuY29tL0lu"
    "dGVsU0dYUm9vdENBLmNybDAdBgNVHQ4EFgQUImUM1lqdNInzg7SV%0AUr9QGzknBqwwDgY"
    "DVR0PAQH%2FBAQDAgEGMBIGA1UdEwEB%2FwQIMAYBAf8CAQEwCgYI%0AKoZIzj0EAwIDSA"
    "AwRQIgQQs%2F08rycdPauCFk8UPQXCMAlsloBe7NwaQGTcdpa0EC%0AIQCUt8SGvxKmjpc"
    "M%2Fz0WP9Dvo8h2k5du1iWDdBkAn%2B0iiA%3D%3D%0A-----END%20CERTIFICATE----"
    "-%0A";

// The HTTP header key for Tcbm in the HTTP response for GetPckCertificate.
constexpr char kGetPckCertHttpResponseHeaderTcbmKey[] = "SGX-TCBm";

// The HTTP header value for Tcbm in the HTTP response for GetPckCertificate.
constexpr char kGetPckCertHttpResponseHeaderTcbmValue[] =
    "050502040180000000000000000000000700";

// The body of the HTTP response for GetPckCertificate.
constexpr char kGetPckCertHttpResponseBody[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIEgDCCBCegAwIBAgIVAJ1mxDIzAXa+ixcUKKaUmyYxoyJlMAoGCCqGSM49BAMCMHExIz"
    "AhBgNV\nBAMMGkludGVsIFNHWCBQQ0sgUHJvY2Vzc29yIENBMRowGAYDVQQKDBFJbnRlbC"
    "BDb3Jwb3JhdGlv\nbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNBMQswCQ"
    "YDVQQGEwJVUzAeFw0xOTA5\nMjMxNTIwMjBaFw0yNjA5MjMxNTIwMjBaMHAxIjAgBgNVBA"
    "MMGUludGVsIFNHWCBQQ0sgQ2VydGlm\naWNhdGUxGjAYBgNVBAoMEUludGVsIENvcnBvcm"
    "F0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTEL\nMAkGA1UECAwCQ0ExCzAJBgNVBAYTAl"
    "VTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEF7aCJQzG\nR7R/oeDkuyiFhknVXV4mKl"
    "72QUCD+02CS+a0AUnJtKz37EmAyd5afJ38dFswPFL1upLY7yrEco99\n3qOCApswggKXMB"
    "8GA1UdIwQYMBaAFNDoqtp11/kuSReYPHsUZdDV8llNMF8GA1UdHwRYMFYwVKBS\noFCGTm"
    "h0dHBzOi8vYXBpLnRydXN0ZWRzZXJ2aWNlcy5pbnRlbC5jb20vc2d4L2NlcnRpZmljYXRp"
    "\nb24vdjEvcGNrY3JsP2NhPXByb2Nlc3NvcjAdBgNVHQ4EFgQUFBTkM8dooH85tY3YGlV1"
    "MtZs1zEw\nDgYDVR0PAQH/BAQDAgbAMAwGA1UdEwEB/wQCMAAwggHUBgkqhkiG+E0BDQEE"
    "ggHFMIIBwTAeBgoq\nhkiG+E0BDQEBBBB7l753xi1CRsYD0PTxGzG7MIIBZAYKKoZIhvhN"
    "AQ0BAjCCAVQwEAYLKoZIhvhN\nAQ0BAgECAQUwEAYLKoZIhvhNAQ0BAgICAQUwEAYLKoZI"
    "hvhNAQ0BAgMCAQIwEAYLKoZIhvhNAQ0B\nAgQCAQQwEAYLKoZIhvhNAQ0BAgUCAQEwEQYL"
    "KoZIhvhNAQ0BAgYCAgCAMBAGCyqGSIb4TQENAQIH\nAgEAMBAGCyqGSIb4TQENAQIIAgEA"
    "MBAGCyqGSIb4TQENAQIJAgEAMBAGCyqGSIb4TQENAQIKAgEA\nMBAGCyqGSIb4TQENAQIL"
    "AgEAMBAGCyqGSIb4TQENAQIMAgEAMBAGCyqGSIb4TQENAQINAgEAMBAG\nCyqGSIb4TQEN"
    "AQIOAgEAMBAGCyqGSIb4TQENAQIPAgEAMBAGCyqGSIb4TQENAQIQAgEAMBAGCyqG\nSIb4"
    "TQENAQIRAgEHMB8GCyqGSIb4TQENAQISBBAFBQIEAYAAAAAAAAAAAAAAMBAGCiqGSIb4TQ"
    "EN\nAQMEAgAAMBQGCiqGSIb4TQENAQQEBgCQbqEAADAPBgoqhkiG+E0BDQEFCgEAMAoGCC"
    "qGSM49BAMC\nA0cAMEQCIGlbXmxddyurwfUUWdRU4/8lYt7ajZobpwh6LvcK8pBrAiAp+L"
    "6I1+eyfKtu/Lfvk/xu\nqUglPPXuljMTdM9FWBIczQ==\n"
    "-----END CERTIFICATE-----\n";

// The expected parsed PCK certificate.
constexpr char kExpectedPckCertTextProto[] = R"proto(
  format: X509_PEM
  data: "-----BEGIN CERTIFICATE-----\nMIIEgDCCBCegAwIBAgIVAJ1mxDIzAXa+ixcUKKa"
        "UmyYxoyJlMAoGCCqGSM49BAMC\nMHExIzAhBgNVBAMMGkludGVsIFNHWCBQQ0sgUHJvY"
        "2Vzc29yIENBMRowGAYDVQQK\nDBFJbnRlbCBDb3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2F"
        "udGEgQ2xhcmExCzAJBgNV\nBAgMAkNBMQswCQYDVQQGEwJVUzAeFw0xOTA5MjMxNTIwM"
        "jBaFw0yNjA5MjMxNTIw\nMjBaMHAxIjAgBgNVBAMMGUludGVsIFNHWCBQQ0sgQ2VydGl"
        "maWNhdGUxGjAYBgNV\nBAoMEUludGVsIENvcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50Y"
        "SBDbGFyYTELMAkG\nA1UECAwCQ0ExCzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZ"
        "Izj0DAQcDQgAE\nF7aCJQzGR7R/oeDkuyiFhknVXV4mKl72QUCD+02CS+a0AUnJtKz37"
        "EmAyd5afJ38\ndFswPFL1upLY7yrEco993qOCApswggKXMB8GA1UdIwQYMBaAFNDoqtp"
        "11/kuSReY\nPHsUZdDV8llNMF8GA1UdHwRYMFYwVKBSoFCGTmh0dHBzOi8vYXBpLnRyd"
        "XN0ZWRz\nZXJ2aWNlcy5pbnRlbC5jb20vc2d4L2NlcnRpZmljYXRpb24vdjEvcGNrY3J"
        "sP2Nh\nPXByb2Nlc3NvcjAdBgNVHQ4EFgQUFBTkM8dooH85tY3YGlV1MtZs1zEwDgYDV"
        "R0P\nAQH/BAQDAgbAMAwGA1UdEwEB/wQCMAAwggHUBgkqhkiG+E0BDQEEggHFMIIBwTA"
        "e\nBgoqhkiG+E0BDQEBBBB7l753xi1CRsYD0PTxGzG7MIIBZAYKKoZIhvhNAQ0BAjCC"
        "\nAVQwEAYLKoZIhvhNAQ0BAgECAQUwEAYLKoZIhvhNAQ0BAgICAQUwEAYLKoZIhvhN\n"
        "AQ0BAgMCAQIwEAYLKoZIhvhNAQ0BAgQCAQQwEAYLKoZIhvhNAQ0BAgUCAQEwEQYL\nKo"
        "ZIhvhNAQ0BAgYCAgCAMBAGCyqGSIb4TQENAQIHAgEAMBAGCyqGSIb4TQENAQII\nAgEA"
        "MBAGCyqGSIb4TQENAQIJAgEAMBAGCyqGSIb4TQENAQIKAgEAMBAGCyqGSIb4\nTQENAQ"
        "ILAgEAMBAGCyqGSIb4TQENAQIMAgEAMBAGCyqGSIb4TQENAQINAgEAMBAG\nCyqGSIb4"
        "TQENAQIOAgEAMBAGCyqGSIb4TQENAQIPAgEAMBAGCyqGSIb4TQENAQIQ\nAgEAMBAGCy"
        "qGSIb4TQENAQIRAgEHMB8GCyqGSIb4TQENAQISBBAFBQIEAYAAAAAA\nAAAAAAAAMBAG"
        "CiqGSIb4TQENAQMEAgAAMBQGCiqGSIb4TQENAQQEBgCQbqEAADAP\nBgoqhkiG+E0BDQ"
        "EFCgEAMAoGCCqGSM49BAMCA0cAMEQCIGlbXmxddyurwfUUWdRU\n4/8lYt7ajZobpwh6"
        "LvcK8pBrAiAp+L6I1+eyfKtu/Lfvk/xuqUglPPXuljMTdM9F\nWBIczQ==\n-----END"
        " CERTIFICATE-----\n"
)proto";

// The expected parsed PCK certificate issuer cert chain.
constexpr char kExpectedPckIssuerCertChainTextProto[] = R"proto(
  certificates {
    format: X509_PEM
    data: "-----BEGIN CERTIFICATE-----\nMIIClzCCAj6gAwIBAgIVANDoqtp11/kuSReYP"
          "HsUZdDV8llNMAoGCCqGSM49BAMC\nMGgxGjAYBgNVBAMMEUludGVsIFNHWCBSb290I"
          "ENBMRowGAYDVQQKDBFJbnRlbCBD\nb3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ"
          "2xhcmExCzAJBgNVBAgMAkNBMQsw\nCQYDVQQGEwJVUzAeFw0xODA1MjExMDQ1MDhaF"
          "w0zMzA1MjExMDQ1MDhaMHExIzAh\nBgNVBAMMGkludGVsIFNHWCBQQ0sgUHJvY2Vzc"
          "29yIENBMRowGAYDVQQKDBFJbnRl\nbCBDb3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2Fud"
          "GEgQ2xhcmExCzAJBgNVBAgMAkNB\nMQswCQYDVQQGEwJVUzBZMBMGByqGSM49AgEGC"
          "CqGSM49AwEHA0IABL9q+NMp2IOg\ntdl1bk/uWZ5+TGQm8aCi8z78fs+fKCQ3d+uDz"
          "XnVTAT2ZhDCifyIuJwvN3wNBp9i\nHBSSMJMJrBOjgbswgbgwHwYDVR0jBBgwFoAUI"
          "mUM1lqdNInzg7SVUr9QGzknBqww\nUgYDVR0fBEswSTBHoEWgQ4ZBaHR0cHM6Ly9jZ"
          "XJ0aWZpY2F0ZXMudHJ1c3RlZHNl\ncnZpY2VzLmludGVsLmNvbS9JbnRlbFNHWFJvb"
          "3RDQS5jcmwwHQYDVR0OBBYEFNDo\nqtp11/kuSReYPHsUZdDV8llNMA4GA1UdDwEB/"
          "wQEAwIBBjASBgNVHRMBAf8ECDAG\nAQH/AgEAMAoGCCqGSM49BAMCA0cAMEQCIC/9j"
          "+84T+HztVO/sOQBWJbSd+/2uexK\n4+aA0jcFBLcpAiA3dhMrF5cD52t6FqMvAIpj8"
          "XdGmy2beeljLJK+pzpcRA==\n-----END CERTIFICATE-----\n"
  }
  certificates {
    format: X509_PEM
    data: "-----BEGIN CERTIFICATE-----\nMIICjjCCAjSgAwIBAgIUImUM1lqdNInzg7SVU"
          "r9QGzknBqwwCgYIKoZIzj0EAwIw\naDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ"
          "0ExGjAYBgNVBAoMEUludGVsIENv\ncnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDb"
          "GFyYTELMAkGA1UECAwCQ0ExCzAJ\nBgNVBAYTAlVTMB4XDTE4MDUyMTEwNDExMVoXD"
          "TMzMDUyMTEwNDExMFowaDEaMBgG\nA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYB"
          "gNVBAoMEUludGVsIENvcnBvcmF0\naW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELM"
          "AkGA1UECAwCQ0ExCzAJBgNVBAYT\nAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQ"
          "gAEC6nEwMDIYZOj/iPWsCzaEKi7\n1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4"
          "mqsyYjlBalTVYxFP2sJBK5zlKOB\nuzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODt"
          "JVSv1AbOScGrDBSBgNVHR8ESzBJ\nMEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlc"
          "y50cnVzdGVkc2VydmljZXMuaW50\nZWwuY29tL0ludGVsU0dYUm9vdENBLmNybDAdB"
          "gNVHQ4EFgQUImUM1lqdNInzg7SV\nUr9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA"
          "1UdEwEB/wQIMAYBAf8CAQEwCgYI\nKoZIzj0EAwIDSAAwRQIgQQs/08rycdPauCFk8"
          "UPQXCMAlsloBe7NwaQGTcdpa0EC\nIQCUt8SGvxKmjpcM/z0WP9Dvo8h2k5du1iWDd"
          "BkAn+0iiA==\n-----END CERTIFICATE-----\n"
  }
)proto";

// The expected parsed Tcbm.
constexpr char kExpectedTcbmTextProto[] = R"proto(
  cpu_svn {
    value: "\005\005\002\004\001\200\000\000\000\000\000\000\000\000\000\000"
  }
  pce_svn { value: 7 }
)proto";

// The expected URL sent by GetPckCertificates.
constexpr char kGetPckCertsExpectedUrl[] =
    "https://api.trustedservices.intel.com/sgx/certification/v1/pckcerts?encryp"
    "ted_ppid=5caa75aefb87f56c18b377eed358d9f9084a54f435de6292a20cd16d6334dbf81"
    "eee3602c40ceaca5ec702dc5cfc4b740489885781b263566f2152f4b88f0a114cdb0ab969d"
    "858e9576e17c72a0ed8f1916a25231ecca8e0543509f7996378dcd9ae8e85d6b340d71389a"
    "71c7edaffd5ebfd44d8ff8e16091263bff7b0ea7f0dea6297d3824050501411f7c9045c406"
    "0eceb1587103e9d99d604264f6a856b38e5918b22eb22171f91f512d731451c56febdeba72"
    "90949195b71dd75b915803ea5daec4af7c05b01e0103b6b843120acf8337b9fe1325366b6f"
    "298ced41f0093b05ae14f26e1d2b4fe9f871ce104a9798f176ee1f4a01199e3d8054bac62f"
    "72941f90de0f202e5cc958ec2fec8f66250702d71685605f5c32d56272fc887aea5a45e4e4"
    "bd9c412972cb0f6a83275736e0cec7164b544122ec5b81be53d99163b1ee8105d8cf7bba1a"
    "b35bd4bf82f6e8d1bb91c0066a80f7e6ec2a704156d6e28209c06087faabbbe76588aadd9c"
    "5c65092c49b001c7ff2cdb8ac65faa5038b94&pceid=0000";

// The body of the HTTP response for GetPckCertificates.
constexpr char kGetPckCertsHttpResponseBody[] =
    "[{\"tcb\":{\"sgxtcbcomp01svn\":6,\"sgxtcbcomp02svn\":6,\"sgxtcbcomp03svn\""
    ":2,\"sgxtcbcomp04svn\":4,\"sgxtcbcomp05svn\":1,\"sgxtcbcomp06svn\":128,\"s"
    "gxtcbcomp07svn\":1,\"sgxtcbcomp08svn\":0,\"sgxtcbcomp09svn\":0,\"sgxtcbcom"
    "p10svn\":0,\"sgxtcbcomp11svn\":0,\"sgxtcbcomp12svn\":0,\"sgxtcbcomp13svn\""
    ":0,\"sgxtcbcomp14svn\":0,\"sgxtcbcomp15svn\":0,\"sgxtcbcomp16svn\":0,\"pce"
    "svn\":7},\"tcbm\":\"060602040180010000000000000000000700\",\"cert\":\"----"
    "-BEGIN%20CERTIFICATE-----%0AMIIEgDCCBCagAwIBAgIUVEUOECXhHHTveY0hS2kbngAuXo"
    "wwCgYIKoZIzj0EAwIwcTEjMCEGA1UE%0AAwwaSW50ZWwgU0dYIFBDSyBQcm9jZXNzb3IgQ0ExG"
    "jAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9u%0AMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkG"
    "A1UECAwCQ0ExCzAJBgNVBAYTAlVTMB4XDTE5MDky%0AMzE4NDA0OVoXDTI2MDkyMzE4NDA0OVo"
    "wcDEiMCAGA1UEAwwZSW50ZWwgU0dYIFBDSyBDZXJ0aWZp%0AY2F0ZTEaMBgGA1UECgwRSW50ZW"
    "wgQ29ycG9yYXRpb24xFDASBgNVBAcMC1NhbnRhIENsYXJhMQsw%0ACQYDVQQIDAJDQTELMAkGA"
    "1UEBhMCVVMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ06CXTMK6h%0A%2FBR2sRaSssWO8M"
    "qEdbccOGWzyLjwiRx1zfyrreCqgAN2LOkGAKFlomquV%2FCZ369yTSm7li4APNfC%0Ao4ICmzC"
    "CApcwHwYDVR0jBBgwFoAU0Oiq2nXX%2BS5JF5g8exRl0NXyWU0wXwYDVR0fBFgwVjBUoFKg%0A"
    "UIZOaHR0cHM6Ly9hcGkudHJ1c3RlZHNlcnZpY2VzLmludGVsLmNvbS9zZ3gvY2VydGlmaWNhdG"
    "lv%0Abi92MS9wY2tjcmw%2FY2E9cHJvY2Vzc29yMB0GA1UdDgQWBBRBM37ZBg6NUUSIMXn4sRc"
    "RjFN%2FPDAO%0ABgNVHQ8BAf8EBAMCBsAwDAYDVR0TAQH%2FBAIwADCCAdQGCSqGSIb4TQENAQ"
    "SCAcUwggHBMB4GCiqG%0ASIb4TQENAQEEEHuXvnfGLUJGxgPQ9PEbMbswggFkBgoqhkiG%2BE0"
    "BDQECMIIBVDAQBgsqhkiG%2BE0B%0ADQECAQIBBjAQBgsqhkiG%2BE0BDQECAgIBBjAQBgsqhk"
    "iG%2BE0BDQECAwIBAjAQBgsqhkiG%2BE0BDQEC%0ABAIBBDAQBgsqhkiG%2BE0BDQECBQIBATA"
    "RBgsqhkiG%2BE0BDQECBgICAIAwEAYLKoZIhvhNAQ0BAgcC%0AAQEwEAYLKoZIhvhNAQ0BAggC"
    "AQAwEAYLKoZIhvhNAQ0BAgkCAQAwEAYLKoZIhvhNAQ0BAgoCAQAw%0AEAYLKoZIhvhNAQ0BAgs"
    "CAQAwEAYLKoZIhvhNAQ0BAgwCAQAwEAYLKoZIhvhNAQ0BAg0CAQAwEAYL%0AKoZIhvhNAQ0BAg"
    "4CAQAwEAYLKoZIhvhNAQ0BAg8CAQAwEAYLKoZIhvhNAQ0BAhACAQAwEAYLKoZI%0AhvhNAQ0BA"
    "hECAQcwHwYLKoZIhvhNAQ0BAhIEEAYGAgQBgAEAAAAAAAAAAAAwEAYKKoZIhvhNAQ0B%0AAwQC"
    "AAAwFAYKKoZIhvhNAQ0BBAQGAJBuoQAAMA8GCiqGSIb4TQENAQUKAQAwCgYIKoZIzj0EAwID%0"
    "ASAAwRQIhAJ1Pb3uhDcrzExLFQ9lW5Bd%2BvFopsISpxMBGt%2F53V0BjAiAr0hD0DolN3%2Bf"
    "H3KCNydyf%0AKY5naS4Hf7PiUSznsrNi8w%3D%3D%0A-----END%20CERTIFICATE-----\"},"
    "{\"tcb\":{\"sgxtcbcomp01svn\":6,\"sgxtcbcomp02svn\":6,\"sgxtcbcomp03svn\":"
    "2,\"sgxtcbcomp04svn\":4,\"sgxtcbcomp05svn\":1,\"sgxtcbcomp06svn\":128,\"sg"
    "xtcbcomp07svn\":0,\"sgxtcbcomp08svn\":0,\"sgxtcbcomp09svn\":0,\"sgxtcbcomp"
    "10svn\":0,\"sgxtcbcomp11svn\":0,\"sgxtcbcomp12svn\":0,\"sgxtcbcomp13svn\":"
    "0,\"sgxtcbcomp14svn\":0,\"sgxtcbcomp15svn\":0,\"sgxtcbcomp16svn\":0,\"pces"
    "vn\":7},\"tcbm\":\"060602040180000000000000000000000700\",\"cert\":\"-----"
    "BEGIN%20CERTIFICATE-----%0AMIIEgTCCBCegAwIBAgIVAKOnJWy71ZwjgzZ%2BdQ4kQtwDZ"
    "85nMAoGCCqGSM49BAMCMHExIzAhBgNV%0ABAMMGkludGVsIFNHWCBQQ0sgUHJvY2Vzc29yIENB"
    "MRowGAYDVQQKDBFJbnRlbCBDb3Jwb3JhdGlv%0AbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzA"
    "JBgNVBAgMAkNBMQswCQYDVQQGEwJVUzAeFw0xOTA5%0AMjMxODQwNDlaFw0yNjA5MjMxODQwND"
    "laMHAxIjAgBgNVBAMMGUludGVsIFNHWCBQQ0sgQ2VydGlm%0AaWNhdGUxGjAYBgNVBAoMEUlud"
    "GVsIENvcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTEL%0AMAkGA1UECAwCQ0ExCzAJ"
    "BgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKq9bOB5%2B%0Al5%2BD8Jy6m4N"
    "3fEfG143k4fBEIUHTI11TwGA6nXYPy3otv6ggl6d9mUsDt%2Bt1tOjvgNCaVudrhUbP%0Aq6OC"
    "ApswggKXMB8GA1UdIwQYMBaAFNDoqtp11%2FkuSReYPHsUZdDV8llNMF8GA1UdHwRYMFYwVKBS"
    "%0AoFCGTmh0dHBzOi8vYXBpLnRydXN0ZWRzZXJ2aWNlcy5pbnRlbC5jb20vc2d4L2NlcnRpZml"
    "jYXRp%0Ab24vdjEvcGNrY3JsP2NhPXByb2Nlc3NvcjAdBgNVHQ4EFgQU%2BfN53shxLxPvhXbl"
    "SobC21HrvmIw%0ADgYDVR0PAQH%2FBAQDAgbAMAwGA1UdEwEB%2FwQCMAAwggHUBgkqhkiG%2B"
    "E0BDQEEggHFMIIBwTAeBgoq%0AhkiG%2BE0BDQEBBBB7l753xi1CRsYD0PTxGzG7MIIBZAYKKo"
    "ZIhvhNAQ0BAjCCAVQwEAYLKoZIhvhN%0AAQ0BAgECAQYwEAYLKoZIhvhNAQ0BAgICAQYwEAYLK"
    "oZIhvhNAQ0BAgMCAQIwEAYLKoZIhvhNAQ0B%0AAgQCAQQwEAYLKoZIhvhNAQ0BAgUCAQEwEQYL"
    "KoZIhvhNAQ0BAgYCAgCAMBAGCyqGSIb4TQENAQIH%0AAgEAMBAGCyqGSIb4TQENAQIIAgEAMBA"
    "GCyqGSIb4TQENAQIJAgEAMBAGCyqGSIb4TQENAQIKAgEA%0AMBAGCyqGSIb4TQENAQILAgEAMB"
    "AGCyqGSIb4TQENAQIMAgEAMBAGCyqGSIb4TQENAQINAgEAMBAG%0ACyqGSIb4TQENAQIOAgEAM"
    "BAGCyqGSIb4TQENAQIPAgEAMBAGCyqGSIb4TQENAQIQAgEAMBAGCyqG%0ASIb4TQENAQIRAgEH"
    "MB8GCyqGSIb4TQENAQISBBAGBgIEAYAAAAAAAAAAAAAAMBAGCiqGSIb4TQEN%0AAQMEAgAAMBQ"
    "GCiqGSIb4TQENAQQEBgCQbqEAADAPBgoqhkiG%2BE0BDQEFCgEAMAoGCCqGSM49BAMC%0AA0gA"
    "MEUCIQCi70nmz%2FNLTtF9OTIxbyz%2BqN42%2BMt6mbw1rGiXqHPRXwIgWklRaR0wKtoB7OlK"
    "Cp19%0Ab3Ti13jRup8WTFJnoyoPKSI%3D%0A-----END%20CERTIFICATE-----\"},{\"tcb"
    "\":{\"sgxtcbcomp01svn\":5,\"sgxtcbcomp02svn\":5,\"sgxtcbcomp03svn\":2,\"sg"
    "xtcbcomp04svn\":4,\"sgxtcbcomp05svn\":1,\"sgxtcbcomp06svn\":128,\"sgxtcbco"
    "mp07svn\":1,\"sgxtcbcomp08svn\":0,\"sgxtcbcomp09svn\":0,\"sgxtcbcomp10svn"
    "\":0,\"sgxtcbcomp11svn\":0,\"sgxtcbcomp12svn\":0,\"sgxtcbcomp13svn\":0,\"s"
    "gxtcbcomp14svn\":0,\"sgxtcbcomp15svn\":0,\"sgxtcbcomp16svn\":0,\"pcesvn\":"
    "7},\"tcbm\":\"050502040180010000000000000000000700\",\"cert\":\"-----BEGIN"
    "%20CERTIFICATE-----%0AMIIEgTCCBCegAwIBAgIVAIudIsG0zFrcVwWCJpnF%2FoJ%2FAv3U"
    "MAoGCCqGSM49BAMCMHExIzAhBgNV%0ABAMMGkludGVsIFNHWCBQQ0sgUHJvY2Vzc29yIENBMRo"
    "wGAYDVQQKDBFJbnRlbCBDb3Jwb3JhdGlv%0AbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBg"
    "NVBAgMAkNBMQswCQYDVQQGEwJVUzAeFw0xOTA5%0AMjMxODQwNDlaFw0yNjA5MjMxODQwNDlaM"
    "HAxIjAgBgNVBAMMGUludGVsIFNHWCBQQ0sgQ2VydGlm%0AaWNhdGUxGjAYBgNVBAoMEUludGVs"
    "IENvcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTEL%0AMAkGA1UECAwCQ0ExCzAJBgN"
    "VBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEvZb0pkVJ%0ALhna4zUXQy1jp%2FSM"
    "IkIE2ufJjSVCNU4g5ymzO0RKS%2B%2BXpSwDOJHNxCpIyCkpWeYNbj9m6HDd0zWs%0AHaOCAps"
    "wggKXMB8GA1UdIwQYMBaAFNDoqtp11%2FkuSReYPHsUZdDV8llNMF8GA1UdHwRYMFYwVKBS%0A"
    "oFCGTmh0dHBzOi8vYXBpLnRydXN0ZWRzZXJ2aWNlcy5pbnRlbC5jb20vc2d4L2NlcnRpZmljYX"
    "Rp%0Ab24vdjEvcGNrY3JsP2NhPXByb2Nlc3NvcjAdBgNVHQ4EFgQUiyOA3JWI9LZWgvm%2FZZB"
    "MdTCRMt0w%0ADgYDVR0PAQH%2FBAQDAgbAMAwGA1UdEwEB%2FwQCMAAwggHUBgkqhkiG%2BE0B"
    "DQEEggHFMIIBwTAeBgoq%0AhkiG%2BE0BDQEBBBB7l753xi1CRsYD0PTxGzG7MIIBZAYKKoZIh"
    "vhNAQ0BAjCCAVQwEAYLKoZIhvhN%0AAQ0BAgECAQUwEAYLKoZIhvhNAQ0BAgICAQUwEAYLKoZI"
    "hvhNAQ0BAgMCAQIwEAYLKoZIhvhNAQ0B%0AAgQCAQQwEAYLKoZIhvhNAQ0BAgUCAQEwEQYLKoZ"
    "IhvhNAQ0BAgYCAgCAMBAGCyqGSIb4TQENAQIH%0AAgEBMBAGCyqGSIb4TQENAQIIAgEAMBAGCy"
    "qGSIb4TQENAQIJAgEAMBAGCyqGSIb4TQENAQIKAgEA%0AMBAGCyqGSIb4TQENAQILAgEAMBAGC"
    "yqGSIb4TQENAQIMAgEAMBAGCyqGSIb4TQENAQINAgEAMBAG%0ACyqGSIb4TQENAQIOAgEAMBAG"
    "CyqGSIb4TQENAQIPAgEAMBAGCyqGSIb4TQENAQIQAgEAMBAGCyqG%0ASIb4TQENAQIRAgEHMB8"
    "GCyqGSIb4TQENAQISBBAFBQIEAYABAAAAAAAAAAAAMBAGCiqGSIb4TQEN%0AAQMEAgAAMBQGCi"
    "qGSIb4TQENAQQEBgCQbqEAADAPBgoqhkiG%2BE0BDQEFCgEAMAoGCCqGSM49BAMC%0AA0gAMEU"
    "CICIqBeXLJfcOBzjagRDcsRP8x3o2Ahbo1shacB1KuAUBAiEAtcVX5IxxUb1Df9E%2BAqbG%0A"
    "HZgulkqloYpIUegK7VWCS48%3D%0A-----END%20CERTIFICATE-----\"}]";

// The expected parsed PCK certificates.
constexpr char kExpectedPckCertsTextProto[] = R"proto(
  certs {
    tcb_level {
      components: "\006\006\002\004\001\200\001\000\000\000\000\000\000\000"
                  "\000\000"
      pce_svn { value: 7 }
    }
    tcbm {
      cpu_svn {
        value: "\006\006\002\004\001\200\001\000\000\000\000\000\000\000\000"
               "\000"
      }
      pce_svn { value: 7 }
    }
    cert {
      format: X509_PEM
      data: "-----BEGIN CERTIFICATE-----\nMIIEgDCCBCagAwIBAgIUVEUOECXhHHTve"
            "Y0hS2kbngAuXowwCgYIKoZIzj0EAwIw\ncTEjMCEGA1UEAwwaSW50ZWwgU0dYI"
            "FBDSyBQcm9jZXNzb3IgQ0ExGjAYBgNVBAoM\nEUludGVsIENvcnBvcmF0aW9uM"
            "RQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UE\nCAwCQ0ExCzAJBgNVBAYTA"
            "lVTMB4XDTE5MDkyMzE4NDA0OVoXDTI2MDkyMzE4NDA0\nOVowcDEiMCAGA1UEA"
            "wwZSW50ZWwgU0dYIFBDSyBDZXJ0aWZpY2F0ZTEaMBgGA1UE\nCgwRSW50ZWwgQ"
            "29ycG9yYXRpb24xFDASBgNVBAcMC1NhbnRhIENsYXJhMQswCQYD\nVQQIDAJDQ"
            "TELMAkGA1UEBhMCVVMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ0\n6CXTM"
            "K6h/BR2sRaSssWO8MqEdbccOGWzyLjwiRx1zfyrreCqgAN2LOkGAKFlomqu\nV"
            "/CZ369yTSm7li4APNfCo4ICmzCCApcwHwYDVR0jBBgwFoAU0Oiq2nXX+S5JF5g"
            "8\nexRl0NXyWU0wXwYDVR0fBFgwVjBUoFKgUIZOaHR0cHM6Ly9hcGkudHJ1c3R"
            "lZHNl\ncnZpY2VzLmludGVsLmNvbS9zZ3gvY2VydGlmaWNhdGlvbi92MS9wY2t"
            "jcmw/Y2E9\ncHJvY2Vzc29yMB0GA1UdDgQWBBRBM37ZBg6NUUSIMXn4sRcRjFN"
            "/PDAOBgNVHQ8B\nAf8EBAMCBsAwDAYDVR0TAQH/BAIwADCCAdQGCSqGSIb4TQE"
            "NAQSCAcUwggHBMB4G\nCiqGSIb4TQENAQEEEHuXvnfGLUJGxgPQ9PEbMbswggF"
            "kBgoqhkiG+E0BDQECMIIB\nVDAQBgsqhkiG+E0BDQECAQIBBjAQBgsqhkiG+E0"
            "BDQECAgIBBjAQBgsqhkiG+E0B\nDQECAwIBAjAQBgsqhkiG+E0BDQECBAIBBDA"
            "QBgsqhkiG+E0BDQECBQIBATARBgsq\nhkiG+E0BDQECBgICAIAwEAYLKoZIhvh"
            "NAQ0BAgcCAQEwEAYLKoZIhvhNAQ0BAggC\nAQAwEAYLKoZIhvhNAQ0BAgkCAQA"
            "wEAYLKoZIhvhNAQ0BAgoCAQAwEAYLKoZIhvhN\nAQ0BAgsCAQAwEAYLKoZIhvh"
            "NAQ0BAgwCAQAwEAYLKoZIhvhNAQ0BAg0CAQAwEAYL\nKoZIhvhNAQ0BAg4CAQA"
            "wEAYLKoZIhvhNAQ0BAg8CAQAwEAYLKoZIhvhNAQ0BAhAC\nAQAwEAYLKoZIhvh"
            "NAQ0BAhECAQcwHwYLKoZIhvhNAQ0BAhIEEAYGAgQBgAEAAAAA\nAAAAAAAwEAY"
            "KKoZIhvhNAQ0BAwQCAAAwFAYKKoZIhvhNAQ0BBAQGAJBuoQAAMA8G\nCiqGSIb"
            "4TQENAQUKAQAwCgYIKoZIzj0EAwIDSAAwRQIhAJ1Pb3uhDcrzExLFQ9lW\n5Bd"
            "+vFopsISpxMBGt/53V0BjAiAr0hD0DolN3+fH3KCNydyfKY5naS4Hf7PiUSzn"
            "\nsrNi8w==\n-----END CERTIFICATE-----\n"
    }
  }
  certs {
    tcb_level {
      components: "\006\006\002\004\001\200\000\000\000\000\000\000\000\000"
                  "\000\000"
      pce_svn { value: 7 }
    }
    tcbm {
      cpu_svn {
        value: "\006\006\002\004\001\200\000\000\000\000\000\000\000\000\000"
               "\000"
      }
      pce_svn { value: 7 }
    }
    cert {
      format: X509_PEM
      data: "-----BEGIN CERTIFICATE-----\nMIIEgTCCBCegAwIBAgIVAKOnJWy71Zwj"
            "gzZ+dQ4kQtwDZ85nMAoGCCqGSM49BAMC\nMHExIzAhBgNVBAMMGkludGVsIFNH"
            "WCBQQ0sgUHJvY2Vzc29yIENBMRowGAYDVQQK\nDBFJbnRlbCBDb3Jwb3JhdGlv"
            "bjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNV\nBAgMAkNBMQswCQYDVQQG"
            "EwJVUzAeFw0xOTA5MjMxODQwNDlaFw0yNjA5MjMxODQw\nNDlaMHAxIjAgBgNV"
            "BAMMGUludGVsIFNHWCBQQ0sgQ2VydGlmaWNhdGUxGjAYBgNV\nBAoMEUludGVs"
            "IENvcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkG\nA1UECAwC"
            "Q0ExCzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\nKq9b"
            "OB5+l5+D8Jy6m4N3fEfG143k4fBEIUHTI11TwGA6nXYPy3otv6ggl6d9mUsD\n"
            "t+t1tOjvgNCaVudrhUbPq6OCApswggKXMB8GA1UdIwQYMBaAFNDoqtp11/kuSR"
            "eY\nPHsUZdDV8llNMF8GA1UdHwRYMFYwVKBSoFCGTmh0dHBzOi8vYXBpLnRydX"
            "N0ZWRz\nZXJ2aWNlcy5pbnRlbC5jb20vc2d4L2NlcnRpZmljYXRpb24vdjEvcG"
            "NrY3JsP2Nh\nPXByb2Nlc3NvcjAdBgNVHQ4EFgQU+fN53shxLxPvhXblSobC21"
            "HrvmIwDgYDVR0P\nAQH/BAQDAgbAMAwGA1UdEwEB/wQCMAAwggHUBgkqhkiG+E"
            "0BDQEEggHFMIIBwTAe\nBgoqhkiG+E0BDQEBBBB7l753xi1CRsYD0PTxGzG7MI"
            "IBZAYKKoZIhvhNAQ0BAjCC\nAVQwEAYLKoZIhvhNAQ0BAgECAQYwEAYLKoZIhv"
            "hNAQ0BAgICAQYwEAYLKoZIhvhN\nAQ0BAgMCAQIwEAYLKoZIhvhNAQ0BAgQCAQ"
            "QwEAYLKoZIhvhNAQ0BAgUCAQEwEQYL\nKoZIhvhNAQ0BAgYCAgCAMBAGCyqGSI"
            "b4TQENAQIHAgEAMBAGCyqGSIb4TQENAQII\nAgEAMBAGCyqGSIb4TQENAQIJAg"
            "EAMBAGCyqGSIb4TQENAQIKAgEAMBAGCyqGSIb4\nTQENAQILAgEAMBAGCyqGSI"
            "b4TQENAQIMAgEAMBAGCyqGSIb4TQENAQINAgEAMBAG\nCyqGSIb4TQENAQIOAg"
            "EAMBAGCyqGSIb4TQENAQIPAgEAMBAGCyqGSIb4TQENAQIQ\nAgEAMBAGCyqGSI"
            "b4TQENAQIRAgEHMB8GCyqGSIb4TQENAQISBBAGBgIEAYAAAAAA\nAAAAAAAAMB"
            "AGCiqGSIb4TQENAQMEAgAAMBQGCiqGSIb4TQENAQQEBgCQbqEAADAP\nBgoqhk"
            "iG+E0BDQEFCgEAMAoGCCqGSM49BAMCA0gAMEUCIQCi70nmz/NLTtF9OTIx\nby"
            "z+qN42+Mt6mbw1rGiXqHPRXwIgWklRaR0wKtoB7OlKCp19b3Ti13jRup8WTFJn"
            "\noyoPKSI=\n-----END CERTIFICATE-----\n"
    }
  }
  certs {
    tcb_level {
      components: "\005\005\002\004\001\200\001\000\000\000\000\000\000\000"
                  "\000\000"
      pce_svn { value: 7 }
    }
    tcbm {
      cpu_svn {
        value: "\005\005\002\004\001\200\001\000\000\000\000\000\000\000\000"
               "\000"
      }
      pce_svn { value: 7 }
    }
    cert {
      format: X509_PEM
      data: "-----BEGIN CERTIFICATE-----\nMIIEgTCCBCegAwIBAgIVAIudIsG0zFrcV"
            "wWCJpnF/oJ/Av3UMAoGCCqGSM49BAMC\nMHExIzAhBgNVBAMMGkludGVsIFNHW"
            "CBQQ0sgUHJvY2Vzc29yIENBMRowGAYDVQQK\nDBFJbnRlbCBDb3Jwb3JhdGlvb"
            "jEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNV\nBAgMAkNBMQswCQYDVQQGE"
            "wJVUzAeFw0xOTA5MjMxODQwNDlaFw0yNjA5MjMxODQw\nNDlaMHAxIjAgBgNVB"
            "AMMGUludGVsIFNHWCBQQ0sgQ2VydGlmaWNhdGUxGjAYBgNV\nBAoMEUludGVsI"
            "ENvcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkG\nA1UECAwCQ"
            "0ExCzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\nvZb0p"
            "kVJLhna4zUXQy1jp/SMIkIE2ufJjSVCNU4g5ymzO0RKS++XpSwDOJHNxCpI\ny"
            "CkpWeYNbj9m6HDd0zWsHaOCApswggKXMB8GA1UdIwQYMBaAFNDoqtp11/kuSRe"
            "Y\nPHsUZdDV8llNMF8GA1UdHwRYMFYwVKBSoFCGTmh0dHBzOi8vYXBpLnRydXN"
            "0ZWRz\nZXJ2aWNlcy5pbnRlbC5jb20vc2d4L2NlcnRpZmljYXRpb24vdjEvcGN"
            "rY3JsP2Nh\nPXByb2Nlc3NvcjAdBgNVHQ4EFgQUiyOA3JWI9LZWgvm/ZZBMdTC"
            "RMt0wDgYDVR0P\nAQH/BAQDAgbAMAwGA1UdEwEB/wQCMAAwggHUBgkqhkiG+E0"
            "BDQEEggHFMIIBwTAe\nBgoqhkiG+E0BDQEBBBB7l753xi1CRsYD0PTxGzG7MII"
            "BZAYKKoZIhvhNAQ0BAjCC\nAVQwEAYLKoZIhvhNAQ0BAgECAQUwEAYLKoZIhvh"
            "NAQ0BAgICAQUwEAYLKoZIhvhN\nAQ0BAgMCAQIwEAYLKoZIhvhNAQ0BAgQCAQQ"
            "wEAYLKoZIhvhNAQ0BAgUCAQEwEQYL\nKoZIhvhNAQ0BAgYCAgCAMBAGCyqGSIb"
            "4TQENAQIHAgEBMBAGCyqGSIb4TQENAQII\nAgEAMBAGCyqGSIb4TQENAQIJAgE"
            "AMBAGCyqGSIb4TQENAQIKAgEAMBAGCyqGSIb4\nTQENAQILAgEAMBAGCyqGSIb"
            "4TQENAQIMAgEAMBAGCyqGSIb4TQENAQINAgEAMBAG\nCyqGSIb4TQENAQIOAgE"
            "AMBAGCyqGSIb4TQENAQIPAgEAMBAGCyqGSIb4TQENAQIQ\nAgEAMBAGCyqGSIb"
            "4TQENAQIRAgEHMB8GCyqGSIb4TQENAQISBBAFBQIEAYABAAAA\nAAAAAAAAMBA"
            "GCiqGSIb4TQENAQMEAgAAMBQGCiqGSIb4TQENAQQEBgCQbqEAADAP\nBgoqhki"
            "G+E0BDQEFCgEAMAoGCCqGSM49BAMCA0gAMEUCICIqBeXLJfcOBzjagRDc\nsRP"
            "8x3o2Ahbo1shacB1KuAUBAiEAtcVX5IxxUb1Df9E+AqbGHZgulkqloYpIUegK"
            "\n7VWCS48=\n-----END CERTIFICATE-----\n"
    }
  }
)proto";

// The expected URL sent by GetCrl.
constexpr char kGetCrlExpectedUrl[] =
    "https://api.trustedservices.intel.com/sgx/certification/v1/pckcrl?ca=proce"
    "ssor";

// The HTTP header key for the CRL issuer cert chain.
constexpr char kGetCrlHttpResponseHeaderIssuerCertChainKey[] =
    "SGX-PCK-CRL-Issuer-Chain";

// The HTTP header value for the CRL issuer cert chain.
constexpr char kGetCrlHttpResponseHeaderIssuerCertChainValue[] =
    "-----BEGIN%20CERTIFICATE-----%0AMIIClzCCAj6gAwIBAgIVANDoqtp11%2FkuSReYPHsU"
    "ZdDV8llNMAoGCCqGSM49BAMC%0AMGgxGjAYBgNVBAMMEUludGVsIFNHWCBSb290IENBMRowGAY"
    "DVQQKDBFJbnRlbCBD%0Ab3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBA"
    "gMAkNBMQsw%0ACQYDVQQGEwJVUzAeFw0xODA1MjExMDQ1MDhaFw0zMzA1MjExMDQ1MDhaMHExI"
    "zAh%0ABgNVBAMMGkludGVsIFNHWCBQQ0sgUHJvY2Vzc29yIENBMRowGAYDVQQKDBFJbnRl%0Ab"
    "CBDb3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNB%0AMQswCQYD"
    "VQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABL9q%2BNMp2IOg%0Atdl1bk%2FuWZ5"
    "%2BTGQm8aCi8z78fs%2BfKCQ3d%2BuDzXnVTAT2ZhDCifyIuJwvN3wNBp9i%0AHBSSMJMJrBOj"
    "gbswgbgwHwYDVR0jBBgwFoAUImUM1lqdNInzg7SVUr9QGzknBqww%0AUgYDVR0fBEswSTBHoEW"
    "gQ4ZBaHR0cHM6Ly9jZXJ0aWZpY2F0ZXMudHJ1c3RlZHNl%0AcnZpY2VzLmludGVsLmNvbS9Jbn"
    "RlbFNHWFJvb3RDQS5jcmwwHQYDVR0OBBYEFNDo%0Aqtp11%2FkuSReYPHsUZdDV8llNMA4GA1U"
    "dDwEB%2FwQEAwIBBjASBgNVHRMBAf8ECDAG%0AAQH%2FAgEAMAoGCCqGSM49BAMCA0cAMEQCIC"
    "%2F9j%2B84T%2BHztVO%2FsOQBWJbSd%2B%2F2uexK%0A4%2BaA0jcFBLcpAiA3dhMrF5cD52t"
    "6FqMvAIpj8XdGmy2beeljLJK%2BpzpcRA%3D%3D%0A-----END%20CERTIFICATE-----%0A--"
    "---BEGIN%20CERTIFICATE-----%0AMIICjjCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzkn"
    "BqwwCgYIKoZIzj0EAwIw%0AaDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAo"
    "MEUludGVsIENv%0AcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0"
    "ExCzAJ%0ABgNVBAYTAlVTMB4XDTE4MDUyMTEwNDExMVoXDTMzMDUyMTEwNDExMFowaDEaMBgG%"
    "0AA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0%0AaW9uM"
    "RQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT%0AAlVTMFkwEwYH"
    "KoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj%2FiPWsCzaEKi7%0A1OiOSLRFhWGjbnBVJ"
    "fVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB%0AuzCBuDAfBgNVHSMEGDAWgBQi"
    "ZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ%0AMEegRaBDhkFodHRwczovL2NlcnRpZml"
    "jYXRlcy50cnVzdGVkc2VydmljZXMuaW50%0AZWwuY29tL0ludGVsU0dYUm9vdENBLmNybDAdBg"
    "NVHQ4EFgQUImUM1lqdNInzg7SV%0AUr9QGzknBqwwDgYDVR0PAQH%2FBAQDAgEGMBIGA1UdEwE"
    "B%2FwQIMAYBAf8CAQEwCgYI%0AKoZIzj0EAwIDSAAwRQIgQQs%2F08rycdPauCFk8UPQXCMAls"
    "loBe7NwaQGTcdpa0EC%0AIQCUt8SGvxKmjpcM%2Fz0WP9Dvo8h2k5du1iWDdBkAn%2B0iiA%3D"
    "%3D%0A-----END%20CERTIFICATE-----%0A";

// The body of the HTTP response for GetCrl.
constexpr char kGetCrlHttpResponseBody[] =
    "-----BEGIN X509 CRL-----\n"
    "MIIBKjCB0QIBATAKBggqhkjOPQQDAjBxMSMwIQYDVQQDDBpJbnRlbCBTR1ggUENLIFByb2Nlc3"
    "Nv\nciBDQTEaMBgGA1UECgwRSW50ZWwgQ29ycG9yYXRpb24xFDASBgNVBAcMC1NhbnRhIENsYX"
    "JhMQsw\nCQYDVQQIDAJDQTELMAkGA1UEBhMCVVMXDTE5MDkyMzE5MzkyM1oXDTE5MTAyMzE5Mz"
    "kyM1qgLzAt\nMAoGA1UdFAQDAgEBMB8GA1UdIwQYMBaAFNDoqtp11/kuSReYPHsUZdDV8llNMA"
    "oGCCqGSM49BAMC\nA0gAMEUCICOCtmDnHjkL22nitHxWVBrCkxubRx+eKMzOk0SQBiTrAiEAsC"
    "JQEgZuJ6eFS7J/b2AP\n44xKZbvx9IqgBn9YoomMRbw=\n"
    "-----END X509 CRL-----\n";

// The expected parsed CRL.
constexpr char kExpectedCrlTextProto[] = R"proto(
  format: X509_PEM
  data: "-----BEGIN X509 CRL-----\nMIIBKjCB0QIBATAKBggqhkjOPQQDAjBxMSMwIQYDVQ"
        "QDDBpJbnRlbCBTR1ggUENLIFByb2Nlc3Nv\nciBDQTEaMBgGA1UECgwRSW50ZWwgQ29y"
        "cG9yYXRpb24xFDASBgNVBAcMC1NhbnRhIENsYXJhMQsw\nCQYDVQQIDAJDQTELMAkGA1"
        "UEBhMCVVMXDTE5MDkyMzE5MzkyM1oXDTE5MTAyMzE5MzkyM1qgLzAt\nMAoGA1UdFAQD"
        "AgEBMB8GA1UdIwQYMBaAFNDoqtp11/kuSReYPHsUZdDV8llNMAoGCCqGSM49BAMC\nA0"
        "gAMEUCICOCtmDnHjkL22nitHxWVBrCkxubRx+eKMzOk0SQBiTrAiEAsCJQEgZuJ6eFS7"
        "J/b2AP\n44xKZbvx9IqgBn9YoomMRbw=\n-----END X509 CRL-----\n"
)proto";

// The expected parsed CRL issuer cert chain.
constexpr char kExpectedCrlIssuerCertChainTextProto[] = R"proto(
  certificates {
    format: X509_PEM
    data: "-----BEGIN CERTIFICATE-----\nMIIClzCCAj6gAwIBAgIVANDoqtp11/kuSReYP"
          "HsUZdDV8llNMAoGCCqGSM49BAMC\nMGgxGjAYBgNVBAMMEUludGVsIFNHWCBSb290I"
          "ENBMRowGAYDVQQKDBFJbnRlbCBD\nb3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ"
          "2xhcmExCzAJBgNVBAgMAkNBMQsw\nCQYDVQQGEwJVUzAeFw0xODA1MjExMDQ1MDhaF"
          "w0zMzA1MjExMDQ1MDhaMHExIzAh\nBgNVBAMMGkludGVsIFNHWCBQQ0sgUHJvY2Vzc"
          "29yIENBMRowGAYDVQQKDBFJbnRl\nbCBDb3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2Fud"
          "GEgQ2xhcmExCzAJBgNVBAgMAkNB\nMQswCQYDVQQGEwJVUzBZMBMGByqGSM49AgEGC"
          "CqGSM49AwEHA0IABL9q+NMp2IOg\ntdl1bk/uWZ5+TGQm8aCi8z78fs+fKCQ3d+uDz"
          "XnVTAT2ZhDCifyIuJwvN3wNBp9i\nHBSSMJMJrBOjgbswgbgwHwYDVR0jBBgwFoAUI"
          "mUM1lqdNInzg7SVUr9QGzknBqww\nUgYDVR0fBEswSTBHoEWgQ4ZBaHR0cHM6Ly9jZ"
          "XJ0aWZpY2F0ZXMudHJ1c3RlZHNl\ncnZpY2VzLmludGVsLmNvbS9JbnRlbFNHWFJvb"
          "3RDQS5jcmwwHQYDVR0OBBYEFNDo\nqtp11/kuSReYPHsUZdDV8llNMA4GA1UdDwEB/"
          "wQEAwIBBjASBgNVHRMBAf8ECDAG\nAQH/AgEAMAoGCCqGSM49BAMCA0cAMEQCIC/9j"
          "+84T+HztVO/sOQBWJbSd+/2uexK\n4+aA0jcFBLcpAiA3dhMrF5cD52t6FqMvAIpj8"
          "XdGmy2beeljLJK+pzpcRA==\n-----END CERTIFICATE-----\n"
  }
  certificates {
    format: X509_PEM
    data: "-----BEGIN CERTIFICATE-----\nMIICjjCCAjSgAwIBAgIUImUM1lqdNInzg7SVU"
          "r9QGzknBqwwCgYIKoZIzj0EAwIw\naDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ"
          "0ExGjAYBgNVBAoMEUludGVsIENv\ncnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDb"
          "GFyYTELMAkGA1UECAwCQ0ExCzAJ\nBgNVBAYTAlVTMB4XDTE4MDUyMTEwNDExMVoXD"
          "TMzMDUyMTEwNDExMFowaDEaMBgG\nA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYB"
          "gNVBAoMEUludGVsIENvcnBvcmF0\naW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELM"
          "AkGA1UECAwCQ0ExCzAJBgNVBAYT\nAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQ"
          "gAEC6nEwMDIYZOj/iPWsCzaEKi7\n1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4"
          "mqsyYjlBalTVYxFP2sJBK5zlKOB\nuzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODt"
          "JVSv1AbOScGrDBSBgNVHR8ESzBJ\nMEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlc"
          "y50cnVzdGVkc2VydmljZXMuaW50\nZWwuY29tL0ludGVsU0dYUm9vdENBLmNybDAdB"
          "gNVHQ4EFgQUImUM1lqdNInzg7SV\nUr9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA"
          "1UdEwEB/wQIMAYBAf8CAQEwCgYI\nKoZIzj0EAwIDSAAwRQIgQQs/08rycdPauCFk8"
          "UPQXCMAlsloBe7NwaQGTcdpa0EC\nIQCUt8SGvxKmjpcM/z0WP9Dvo8h2k5du1iWDd"
          "BkAn+0iiA==\n-----END CERTIFICATE-----\n"
  }
)proto";

// The expected URL sent by GetPckCertificate.
constexpr char kGetTcbInfoExpectedUrl[] =
    "https://api.trustedservices.intel.com/sgx/certification/v1/tcb?fmspc=00906"
    "ea10000";

// The HTTP header key for the TCB info issuer cert chain.
constexpr char kGetTcbInfoHttpResponseHeaderIssuerCertChainKey[] =
    "SGX-TCB-Info-Issuer-Chain";

// The HTTP header value for the TCB info issuer cert chain.
constexpr char kGetTcbInfoHttpResponseHeaderIssuerCertChainValue[] =
    "-----BEGIN%20CERTIFICATE-----%0AMIICjDCCAjKgAwIBAgIUfjiC1ftVKUpASY5FhAPpFJ"
    "G99FUwCgYIKoZIzj0EAwIw%0AaDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVB"
    "AoMEUludGVsIENv%0AcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwC"
    "Q0ExCzAJ%0ABgNVBAYTAlVTMB4XDTE4MDUyMTEwNDc1MVoXDTMzMDUyMTEwNDc1MVowbDEeMBw"
    "G%0AA1UEAwwVSW50ZWwgU0dYIFRDQiBTaWduaW5nMRowGAYDVQQKDBFJbnRlbCBDb3Jw%0Ab3J"
    "hdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNBMQswCQYD%0AVQQGEwJVUz"
    "BZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABENFG8xzydWRfK92bmGv%0AP%2BmAh91PEyV7Jh6"
    "FGJd5ndE9aBH7R3E4A7ubrlh%2FzN3C4xvpoouGlirMba%2BW2lju%0AypajgbUwgbIwHwYDVR"
    "0jBBgwFoAUImUM1lqdNInzg7SVUr9QGzknBqwwUgYDVR0f%0ABEswSTBHoEWgQ4ZBaHR0cHM6L"
    "y9jZXJ0aWZpY2F0ZXMudHJ1c3RlZHNlcnZpY2Vz%0ALmludGVsLmNvbS9JbnRlbFNHWFJvb3RD"
    "QS5jcmwwHQYDVR0OBBYEFH44gtX7VSlK%0AQEmORYQD6RSRvfRVMA4GA1UdDwEB%2FwQEAwIGw"
    "DAMBgNVHRMBAf8EAjAAMAoGCCqG%0ASM49BAMCA0gAMEUCIBZZKhCZkaY8Db3MNDbrJdB6l1R9"
    "nrgUZicB9k3gQrChAiEA%0AkUsVfIqjzK0lVWu8U5%2B8rL1xG57CJ7aPxTgl0kfFWuw%3D%0A"
    "-----END%20CERTIFICATE-----%0A-----BEGIN%20CERTIFICATE-----%0AMIICjjCCAjSg"
    "AwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw%0AaDEaMBgGA1UEAwwRSW5"
    "0ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv%0AcnBvcmF0aW9uMRQwEgYDVQQHDA"
    "tTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ%0ABgNVBAYTAlVTMB4XDTE4MDUyMTEwNDExM"
    "VoXDTMzMDUyMTEwNDExMFowaDEaMBgG%0AA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNV"
    "BAoMEUludGVsIENvcnBvcmF0%0AaW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAw"
    "CQ0ExCzAJBgNVBAYT%0AAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj%2"
    "FiPWsCzaEKi7%0A1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5"
    "zlKOB%0AuzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ%0"
    "AMEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50%0AZWwuY2"
    "9tL0ludGVsU0dYUm9vdENBLmNybDAdBgNVHQ4EFgQUImUM1lqdNInzg7SV%0AUr9QGzknBqwwD"
    "gYDVR0PAQH%2FBAQDAgEGMBIGA1UdEwEB%2FwQIMAYBAf8CAQEwCgYI%0AKoZIzj0EAwIDSAAw"
    "RQIgQQs%2F08rycdPauCFk8UPQXCMAlsloBe7NwaQGTcdpa0EC%0AIQCUt8SGvxKmjpcM%2Fz0"
    "WP9Dvo8h2k5du1iWDdBkAn%2B0iiA%3D%3D%0A-----END%20CERTIFICATE-----%0A";

// The body of the HTTP response for GetTcbInfo.
constexpr char kGetTcbInfoHttpResponseBody[] =
    "{\"tcbInfo\":{\"version\":1,\"issueDate\":\"2019-09-23T20:27:46Z\",\"nextU"
    "pdate\":\"2019-10-23T20:27:46Z\",\"fmspc\":\"00906ea10000\",\"pceId\":\"00"
    "00\",\"tcbLevels\":[{\"tcb\":{\"sgxtcbcomp01svn\":6,\"sgxtcbcomp02svn\":6,"
    "\"sgxtcbcomp03svn\":2,\"sgxtcbcomp04svn\":4,\"sgxtcbcomp05svn\":1,\"sgxtcb"
    "comp06svn\":128,\"sgxtcbcomp07svn\":1,\"sgxtcbcomp08svn\":0,\"sgxtcbcomp09"
    "svn\":0,\"sgxtcbcomp10svn\":0,\"sgxtcbcomp11svn\":0,\"sgxtcbcomp12svn\":0,"
    "\"sgxtcbcomp13svn\":0,\"sgxtcbcomp14svn\":0,\"sgxtcbcomp15svn\":0,\"sgxtcb"
    "comp16svn\":0,\"pcesvn\":7},\"status\":\"UpToDate\"},{\"tcb\":{\"sgxtcbcom"
    "p01svn\":6,\"sgxtcbcomp02svn\":6,\"sgxtcbcomp03svn\":2,\"sgxtcbcomp04svn\""
    ":4,\"sgxtcbcomp05svn\":1,\"sgxtcbcomp06svn\":128,\"sgxtcbcomp07svn\":0,\"s"
    "gxtcbcomp08svn\":0,\"sgxtcbcomp09svn\":0,\"sgxtcbcomp10svn\":0,\"sgxtcbcom"
    "p11svn\":0,\"sgxtcbcomp12svn\":0,\"sgxtcbcomp13svn\":0,\"sgxtcbcomp14svn\""
    ":0,\"sgxtcbcomp15svn\":0,\"sgxtcbcomp16svn\":0,\"pcesvn\":7},\"status\":\""
    "ConfigurationNeeded\"},{\"tcb\":{\"sgxtcbcomp01svn\":5,\"sgxtcbcomp02svn\""
    ":5,\"sgxtcbcomp03svn\":2,\"sgxtcbcomp04svn\":4,\"sgxtcbcomp05svn\":1,\"sgx"
    "tcbcomp06svn\":128,\"sgxtcbcomp07svn\":1,\"sgxtcbcomp08svn\":0,\"sgxtcbcom"
    "p09svn\":0,\"sgxtcbcomp10svn\":0,\"sgxtcbcomp11svn\":0,\"sgxtcbcomp12svn\""
    ":0,\"sgxtcbcomp13svn\":0,\"sgxtcbcomp14svn\":0,\"sgxtcbcomp15svn\":0,\"sgx"
    "tcbcomp16svn\":0,\"pcesvn\":7},\"status\":\"OutOfDate\"},{\"tcb\":{\"sgxtc"
    "bcomp01svn\":5,\"sgxtcbcomp02svn\":5,\"sgxtcbcomp03svn\":2,\"sgxtcbcomp04s"
    "vn\":4,\"sgxtcbcomp05svn\":1,\"sgxtcbcomp06svn\":128,\"sgxtcbcomp07svn\":1"
    ",\"sgxtcbcomp08svn\":0,\"sgxtcbcomp09svn\":0,\"sgxtcbcomp10svn\":0,\"sgxtc"
    "bcomp11svn\":0,\"sgxtcbcomp12svn\":0,\"sgxtcbcomp13svn\":0,\"sgxtcbcomp14s"
    "vn\":0,\"sgxtcbcomp15svn\":0,\"sgxtcbcomp16svn\":0,\"pcesvn\":6},\"status"
    "\":\"OutOfDate\"},{\"tcb\":{\"sgxtcbcomp01svn\":5,\"sgxtcbcomp02svn\":5,\""
    "sgxtcbcomp03svn\":2,\"sgxtcbcomp04svn\":4,\"sgxtcbcomp05svn\":1,\"sgxtcbco"
    "mp06svn\":128,\"sgxtcbcomp07svn\":0,\"sgxtcbcomp08svn\":0,\"sgxtcbcomp09sv"
    "n\":0,\"sgxtcbcomp10svn\":0,\"sgxtcbcomp11svn\":0,\"sgxtcbcomp12svn\":0,\""
    "sgxtcbcomp13svn\":0,\"sgxtcbcomp14svn\":0,\"sgxtcbcomp15svn\":0,\"sgxtcbco"
    "mp16svn\":0,\"pcesvn\":7},\"status\":\"OutOfDate\"},{\"tcb\":{\"sgxtcbcomp"
    "01svn\":5,\"sgxtcbcomp02svn\":5,\"sgxtcbcomp03svn\":2,\"sgxtcbcomp04svn\":"
    "4,\"sgxtcbcomp05svn\":1,\"sgxtcbcomp06svn\":128,\"sgxtcbcomp07svn\":0,\"sg"
    "xtcbcomp08svn\":0,\"sgxtcbcomp09svn\":0,\"sgxtcbcomp10svn\":0,\"sgxtcbcomp"
    "11svn\":0,\"sgxtcbcomp12svn\":0,\"sgxtcbcomp13svn\":0,\"sgxtcbcomp14svn\":"
    "0,\"sgxtcbcomp15svn\":0,\"sgxtcbcomp16svn\":0,\"pcesvn\":6},\"status\":\"O"
    "utOfDate\"},{\"tcb\":{\"sgxtcbcomp01svn\":4,\"sgxtcbcomp02svn\":4,\"sgxtcb"
    "comp03svn\":2,\"sgxtcbcomp04svn\":4,\"sgxtcbcomp05svn\":1,\"sgxtcbcomp06sv"
    "n\":128,\"sgxtcbcomp07svn\":0,\"sgxtcbcomp08svn\":0,\"sgxtcbcomp09svn\":0,"
    "\"sgxtcbcomp10svn\":0,\"sgxtcbcomp11svn\":0,\"sgxtcbcomp12svn\":0,\"sgxtcb"
    "comp13svn\":0,\"sgxtcbcomp14svn\":0,\"sgxtcbcomp15svn\":0,\"sgxtcbcomp16sv"
    "n\":0,\"pcesvn\":5},\"status\":\"OutOfDate\"},{\"tcb\":{\"sgxtcbcomp01svn"
    "\":2,\"sgxtcbcomp02svn\":2,\"sgxtcbcomp03svn\":2,\"sgxtcbcomp04svn\":4,\"s"
    "gxtcbcomp05svn\":1,\"sgxtcbcomp06svn\":128,\"sgxtcbcomp07svn\":0,\"sgxtcbc"
    "omp08svn\":0,\"sgxtcbcomp09svn\":0,\"sgxtcbcomp10svn\":0,\"sgxtcbcomp11svn"
    "\":0,\"sgxtcbcomp12svn\":0,\"sgxtcbcomp13svn\":0,\"sgxtcbcomp14svn\":0,\"s"
    "gxtcbcomp15svn\":0,\"sgxtcbcomp16svn\":0,\"pcesvn\":4},\"status\":\"OutOfD"
    "ate\"}]},\"signature\":\"42fd456ac34539b448e7dfe136cb914c3f3971618a8b403a3"
    "70305b2ea42605e4b57d1d5de183d7f2bbbbdc7265f40e4e6e063a034eb0d5e84ceb76bc58"
    "a03eb\"}";

// The expected parsed signed TCB info.
constexpr char kExpectedSignedTcbInfoTextProto[] = R"proto(
  tcb_info_json: "{\"version\":1,\"issueDate\":\"2019-09-23T20:27:46Z\",\"ne"
                 "xtUpdate\":\"2019-10-23T20:27:46Z\",\"fmspc\":\"00906ea100"
                 "00\",\"pceId\":\"0000\",\"tcbLevels\":[{\"tcb\":{\"sgxtcbc"
                 "omp01svn\":6,\"sgxtcbcomp02svn\":6,\"sgxtcbcomp03svn\":2,"
                 "\"sgxtcbcomp04svn\":4,\"sgxtcbcomp05svn\":1,\"sgxtcbcomp06"
                 "svn\":128,\"sgxtcbcomp07svn\":1,\"sgxtcbcomp08svn\":0,\"sg"
                 "xtcbcomp09svn\":0,\"sgxtcbcomp10svn\":0,\"sgxtcbcomp11svn"
                 "\":0,\"sgxtcbcomp12svn\":0,\"sgxtcbcomp13svn\":0,\"sgxtcbc"
                 "omp14svn\":0,\"sgxtcbcomp15svn\":0,\"sgxtcbcomp16svn\":0,"
                 "\"pcesvn\":7},\"status\":\"UpToDate\"},{\"tcb\":{\"sgxtcbc"
                 "omp01svn\":6,\"sgxtcbcomp02svn\":6,\"sgxtcbcomp03svn\":2,"
                 "\"sgxtcbcomp04svn\":4,\"sgxtcbcomp05svn\":1,\"sgxtcbcomp06"
                 "svn\":128,\"sgxtcbcomp07svn\":0,\"sgxtcbcomp08svn\":0,\"sg"
                 "xtcbcomp09svn\":0,\"sgxtcbcomp10svn\":0,\"sgxtcbcomp11svn"
                 "\":0,\"sgxtcbcomp12svn\":0,\"sgxtcbcomp13svn\":0,\"sgxtcbc"
                 "omp14svn\":0,\"sgxtcbcomp15svn\":0,\"sgxtcbcomp16svn\":0,"
                 "\"pcesvn\":7},\"status\":\"ConfigurationNeeded\"},{\"tcb\""
                 ":{\"sgxtcbcomp01svn\":5,\"sgxtcbcomp02svn\":5,\"sgxtcbcomp"
                 "03svn\":2,\"sgxtcbcomp04svn\":4,\"sgxtcbcomp05svn\":1,\"sg"
                 "xtcbcomp06svn\":128,\"sgxtcbcomp07svn\":1,\"sgxtcbcomp08sv"
                 "n\":0,\"sgxtcbcomp09svn\":0,\"sgxtcbcomp10svn\":0,\"sgxtcb"
                 "comp11svn\":0,\"sgxtcbcomp12svn\":0,\"sgxtcbcomp13svn\":0,"
                 "\"sgxtcbcomp14svn\":0,\"sgxtcbcomp15svn\":0,\"sgxtcbcomp16"
                 "svn\":0,\"pcesvn\":7},\"status\":\"OutOfDate\"},{\"tcb\":{"
                 "\"sgxtcbcomp01svn\":5,\"sgxtcbcomp02svn\":5,\"sgxtcbcomp03"
                 "svn\":2,\"sgxtcbcomp04svn\":4,\"sgxtcbcomp05svn\":1,\"sgxt"
                 "cbcomp06svn\":128,\"sgxtcbcomp07svn\":1,\"sgxtcbcomp08svn"
                 "\":0,\"sgxtcbcomp09svn\":0,\"sgxtcbcomp10svn\":0,\"sgxtcbc"
                 "omp11svn\":0,\"sgxtcbcomp12svn\":0,\"sgxtcbcomp13svn\":0,"
                 "\"sgxtcbcomp14svn\":0,\"sgxtcbcomp15svn\":0,\"sgxtcbcomp16"
                 "svn\":0,\"pcesvn\":6},\"status\":\"OutOfDate\"},{\"tcb\":{"
                 "\"sgxtcbcomp01svn\":5,\"sgxtcbcomp02svn\":5,\"sgxtcbcomp03"
                 "svn\":2,\"sgxtcbcomp04svn\":4,\"sgxtcbcomp05svn\":1,\"sgxt"
                 "cbcomp06svn\":128,\"sgxtcbcomp07svn\":0,\"sgxtcbcomp08svn"
                 "\":0,\"sgxtcbcomp09svn\":0,\"sgxtcbcomp10svn\":0,\"sgxtcbc"
                 "omp11svn\":0,\"sgxtcbcomp12svn\":0,\"sgxtcbcomp13svn\":0,"
                 "\"sgxtcbcomp14svn\":0,\"sgxtcbcomp15svn\":0,\"sgxtcbcomp16"
                 "svn\":0,\"pcesvn\":7},\"status\":\"OutOfDate\"},{\"tcb\":{"
                 "\"sgxtcbcomp01svn\":5,\"sgxtcbcomp02svn\":5,\"sgxtcbcomp03"
                 "svn\":2,\"sgxtcbcomp04svn\":4,\"sgxtcbcomp05svn\":1,\"sgxt"
                 "cbcomp06svn\":128,\"sgxtcbcomp07svn\":0,\"sgxtcbcomp08svn"
                 "\":0,\"sgxtcbcomp09svn\":0,\"sgxtcbcomp10svn\":0,\"sgxtcbc"
                 "omp11svn\":0,\"sgxtcbcomp12svn\":0,\"sgxtcbcomp13svn\":0,"
                 "\"sgxtcbcomp14svn\":0,\"sgxtcbcomp15svn\":0,\"sgxtcbcomp16"
                 "svn\":0,\"pcesvn\":6},\"status\":\"OutOfDate\"},{\"tcb\":{"
                 "\"sgxtcbcomp01svn\":4,\"sgxtcbcomp02svn\":4,\"sgxtcbcomp03"
                 "svn\":2,\"sgxtcbcomp04svn\":4,\"sgxtcbcomp05svn\":1,\"sgxt"
                 "cbcomp06svn\":128,\"sgxtcbcomp07svn\":0,\"sgxtcbcomp08svn"
                 "\":0,\"sgxtcbcomp09svn\":0,\"sgxtcbcomp10svn\":0,\"sgxtcbc"
                 "omp11svn\":0,\"sgxtcbcomp12svn\":0,\"sgxtcbcomp13svn\":0,"
                 "\"sgxtcbcomp14svn\":0,\"sgxtcbcomp15svn\":0,\"sgxtcbcomp16"
                 "svn\":0,\"pcesvn\":5},\"status\":\"OutOfDate\"},{\"tcb\":{"
                 "\"sgxtcbcomp01svn\":2,\"sgxtcbcomp02svn\":2,\"sgxtcbcomp03"
                 "svn\":2,\"sgxtcbcomp04svn\":4,\"sgxtcbcomp05svn\":1,\"sgxt"
                 "cbcomp06svn\":128,\"sgxtcbcomp07svn\":0,\"sgxtcbcomp08svn"
                 "\":0,\"sgxtcbcomp09svn\":0,\"sgxtcbcomp10svn\":0,\"sgxtcbc"
                 "omp11svn\":0,\"sgxtcbcomp12svn\":0,\"sgxtcbcomp13svn\":0,"
                 "\"sgxtcbcomp14svn\":0,\"sgxtcbcomp15svn\":0,\"sgxtcbcomp16"
                 "svn\":0,\"pcesvn\":4},\"status\":\"OutOfDate\"}]}"
  signature: "B\375Ej\303E9\264H\347\337\3416\313\221L?9qa\212\213@:7\003"
             "\005\262\352B`^KW\321\325\336\030=\177+\273\275\307&_@\344"
             "\346\340c\2404\353\r^\204\316\267k\305\212\003\353"
)proto";

// The expected parsed TCB info issuer cert chain.
constexpr char kExpectedTcbInfoIssuerCertChainTextProto[] = R"proto(
  certificates {
    format: X509_PEM
    data: "-----BEGIN CERTIFICATE-----\nMIICjDCCAjKgAwIBAgIUfjiC1ftVKUpASY5Fh"
          "APpFJG99FUwCgYIKoZIzj0EAwIw\naDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ"
          "0ExGjAYBgNVBAoMEUludGVsIENv\ncnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDb"
          "GFyYTELMAkGA1UECAwCQ0ExCzAJ\nBgNVBAYTAlVTMB4XDTE4MDUyMTEwNDc1MVoXD"
          "TMzMDUyMTEwNDc1MVowbDEeMBwG\nA1UEAwwVSW50ZWwgU0dYIFRDQiBTaWduaW5nM"
          "RowGAYDVQQKDBFJbnRlbCBDb3Jw\nb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhc"
          "mExCzAJBgNVBAgMAkNBMQswCQYD\nVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49A"
          "wEHA0IABENFG8xzydWRfK92bmGv\nP+mAh91PEyV7Jh6FGJd5ndE9aBH7R3E4A7ubr"
          "lh/zN3C4xvpoouGlirMba+W2lju\nypajgbUwgbIwHwYDVR0jBBgwFoAUImUM1lqdN"
          "Inzg7SVUr9QGzknBqwwUgYDVR0f\nBEswSTBHoEWgQ4ZBaHR0cHM6Ly9jZXJ0aWZpY"
          "2F0ZXMudHJ1c3RlZHNlcnZpY2Vz\nLmludGVsLmNvbS9JbnRlbFNHWFJvb3RDQS5jc"
          "mwwHQYDVR0OBBYEFH44gtX7VSlK\nQEmORYQD6RSRvfRVMA4GA1UdDwEB/wQEAwIGw"
          "DAMBgNVHRMBAf8EAjAAMAoGCCqG\nSM49BAMCA0gAMEUCIBZZKhCZkaY8Db3MNDbrJ"
          "dB6l1R9nrgUZicB9k3gQrChAiEA\nkUsVfIqjzK0lVWu8U5+8rL1xG57CJ7aPxTgl0"
          "kfFWuw=\n-----END CERTIFICATE-----\n"
  }
  certificates {
    format: X509_PEM
    data: "-----BEGIN CERTIFICATE-----\nMIICjjCCAjSgAwIBAgIUImUM1lqdNInzg7SVU"
          "r9QGzknBqwwCgYIKoZIzj0EAwIw\naDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ"
          "0ExGjAYBgNVBAoMEUludGVsIENv\ncnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDb"
          "GFyYTELMAkGA1UECAwCQ0ExCzAJ\nBgNVBAYTAlVTMB4XDTE4MDUyMTEwNDExMVoXD"
          "TMzMDUyMTEwNDExMFowaDEaMBgG\nA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYB"
          "gNVBAoMEUludGVsIENvcnBvcmF0\naW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELM"
          "AkGA1UECAwCQ0ExCzAJBgNVBAYT\nAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQ"
          "gAEC6nEwMDIYZOj/iPWsCzaEKi7\n1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4"
          "mqsyYjlBalTVYxFP2sJBK5zlKOB\nuzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODt"
          "JVSv1AbOScGrDBSBgNVHR8ESzBJ\nMEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlc"
          "y50cnVzdGVkc2VydmljZXMuaW50\nZWwuY29tL0ludGVsU0dYUm9vdENBLmNybDAdB"
          "gNVHQ4EFgQUImUM1lqdNInzg7SV\nUr9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA"
          "1UdEwEB/wQIMAYBAf8CAQEwCgYI\nKoZIzj0EAwIDSAAwRQIgQQs/08rycdPauCFk8"
          "UPQXCMAlsloBe7NwaQGTcdpa0EC\nIQCUt8SGvxKmjpcM/z0WP9Dvo8h2k5du1iWDd"
          "BkAn+0iiA==\n-----END CERTIFICATE-----\n"
  }
)proto";

Ppid GetValidPpid() {
  Ppid ppid;
  ppid.set_value(
      "\x7b\x97\xbe\x77\xc6\x2d\x42\x46"
      "\xc6\x03\xd0\xf4\xf1\x1b\x31\xbb",
      16);
  return ppid;
}

std::vector<uint8_t> GetValidEncryptedPpid() {
  // Hex-encoded fake encrypted Ppid.
  constexpr char kEncryptedPpidHexString[] =
      "5caa75aefb87f56c18b377eed358d9f9084a54f435de6292a20cd16d6334dbf81eee36"
      "02c40ceaca5ec702dc5cfc4b740489885781b263566f2152f4b88f0a114cdb0ab969d8"
      "58e9576e17c72a0ed8f1916a25231ecca8e0543509f7996378dcd9ae8e85d6b340d713"
      "89a71c7edaffd5ebfd44d8ff8e16091263bff7b0ea7f0dea6297d3824050501411f7c9"
      "045c4060eceb1587103e9d99d604264f6a856b38e5918b22eb22171f91f512d731451c"
      "56febdeba7290949195b71dd75b915803ea5daec4af7c05b01e0103b6b843120acf833"
      "7b9fe1325366b6f298ced41f0093b05ae14f26e1d2b4fe9f871ce104a9798f176ee1f4"
      "a01199e3d8054bac62f72941f90de0f202e5cc958ec2fec8f66250702d71685605f5c3"
      "2d56272fc887aea5a45e4e4bd9c412972cb0f6a83275736e0cec7164b544122ec5b81b"
      "e53d99163b1ee8105d8cf7bba1ab35bd4bf82f6e8d1bb91c0066a80f7e6ec2a704156d"
      "6e28209c06087faabbbe76588aadd9c5c65092c49b001c7ff2cdb8ac65faa5038b94";
  std::string ppid_encrypted = absl::HexStringToBytes(kEncryptedPpidHexString);
  std::vector<uint8_t> ppid_encrypted_vec(std::begin(ppid_encrypted),
                                          std::end(ppid_encrypted));
  return ppid_encrypted_vec;
}

CpuSvn GetValidCpuSvn() {
  CpuSvn cpu_svn;
  cpu_svn.set_value(
      "\x05\x05\x02\x04\x01\x80\x00\x00"
      "\x00\x00\x00\x00\x00\x00\x00\x00",
      16);
  return cpu_svn;
}

PceSvn GetValidPceSvn() {
  PceSvn pce_svn;
  pce_svn.set_value(7);
  return pce_svn;
}

PceId GetValidPceId() {
  PceId pce_id;
  pce_id.set_value(0);
  return pce_id;
}

Fmspc GetValidFmspc() {
  Fmspc fmspc;
  fmspc.set_value("\x00\x90\x6e\xa1\x00\x00", 6);
  return fmspc;
}

class MockHttpFetcher : public HttpFetcher {
 public:
  MOCK_METHOD(StatusOr<HttpFetcher::HttpResponse>, Get,
              (absl::string_view, const std::vector<HttpHeaderField> &),
              (override));
};

class MockAsymmetricEncryptionKey : public AsymmetricEncryptionKey {
 public:
  MOCK_METHOD(AsymmetricEncryptionScheme, GetEncryptionScheme, (),
              (const, override));
  MOCK_METHOD(StatusOr<std::string>, SerializeToDer, (), (const, override));
  MOCK_METHOD(Status, Encrypt, (ByteContainerView, std::vector<uint8_t> *),
              (const, override));
};

TEST(SgxPcsClientNoFixtureTest, CreateClient_Fails) {
  auto key = absl::make_unique<MockAsymmetricEncryptionKey>();
  EXPECT_CALL(*key, GetEncryptionScheme())
      .WillOnce(Return(AsymmetricEncryptionScheme::RSA2048_OAEP));
  ASSERT_THAT(SgxPcsClientImpl::Create(absl::make_unique<MockHttpFetcher>(),
                                       std::move(key), kApiKey),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(SgxPcsClientNoFixtureTest, PpidMethodsFailIfNoEncryptionKey) {
  std::unique_ptr<SgxPcsClient> client;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      client, SgxPcsClientImpl::CreateWithoutPpidEncryptionKey(
                  absl::make_unique<MockHttpFetcher>(), kApiKey));

  const Ppid ppid = GetValidPpid();
  const CpuSvn cpu_svn = GetValidCpuSvn();
  const PceSvn pce_svn = GetValidPceSvn();
  const PceId pce_id = GetValidPceId();
  EXPECT_THAT(client->GetPckCertificate(ppid, cpu_svn, pce_svn, pce_id),
              StatusIs(absl::StatusCode::kFailedPrecondition));
  EXPECT_THAT(client->GetPckCertificates(ppid, pce_id),
              StatusIs(absl::StatusCode::kFailedPrecondition));
}

class SgxPcsClientTest : public testing::Test {
 protected:
  void SetUp() override {
    auto fetcher = absl::make_unique<StrictMock<MockHttpFetcher>>();
    fetcher_mock_ = fetcher.get();
    auto ppid_enc_key =
        absl::make_unique<StrictMock<MockAsymmetricEncryptionKey>>();
    ppid_enc_key_mock_ = ppid_enc_key.get();
    EXPECT_CALL(*ppid_enc_key_mock_, GetEncryptionScheme())
        .WillOnce(Return(AsymmetricEncryptionScheme::RSA3072_OAEP));
    ASYLO_ASSERT_OK_AND_ASSIGN(
        pcs_client_, SgxPcsClientImpl::Create(
                         std::move(fetcher), std::move(ppid_enc_key), kApiKey));
  }

  MockHttpFetcher *fetcher_mock_;
  const MockAsymmetricEncryptionKey *ppid_enc_key_mock_;
  std::unique_ptr<SgxPcsClient> pcs_client_;
};

TEST_F(SgxPcsClientTest, GetPckCertificate_Success) {
  const Ppid ppid = GetValidPpid();
  const CpuSvn cpu_svn = GetValidCpuSvn();
  const PceSvn pce_svn = GetValidPceSvn();
  const PceId pce_id = GetValidPceId();
  const std::vector<uint8_t> ppid_encrypted = GetValidEncryptedPpid();
  EXPECT_CALL(*ppid_enc_key_mock_, Encrypt(Eq(ppid.value()), NotNull()))
      .Times(1)
      .WillOnce(
          DoAll(SetArgPointee<1>(ppid_encrypted), Return(absl::OkStatus())));
  std::vector<HttpFetcher::HttpHeaderField> expected_custom_headers;
  expected_custom_headers.push_back(std::make_pair(kHttpHeaderApiKey, kApiKey));
  HttpFetcher::HttpResponse response;
  response.status_code = 200;
  response.header = {{kGetPckCertHttpResponseHeaderIssuerCertChainKey,
                      kGetPckCertHttpResponseHeaderIssuerCertChainValue},
                     {kGetPckCertHttpResponseHeaderTcbmKey,
                      kGetPckCertHttpResponseHeaderTcbmValue}};
  response.body = kGetPckCertHttpResponseBody;
  EXPECT_CALL(*fetcher_mock_, Get(Eq(kGetPckCertExpectedUrl),
                                  ElementsAreArray(expected_custom_headers)))
      .Times(1)
      .WillOnce(Return(response));

  GetPckCertificateResult result;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      result, pcs_client_->GetPckCertificate(ppid, cpu_svn, pce_svn, pce_id));

  Certificate expected_pck_cert;
  ASSERT_TRUE(TextFormat::ParseFromString(kExpectedPckCertTextProto,
                                          &expected_pck_cert));
  CertificateChain expected_issuer_chain;
  ASSERT_TRUE(TextFormat::ParseFromString(kExpectedPckIssuerCertChainTextProto,
                                          &expected_issuer_chain));
  RawTcb expected_tcbm;
  ASSERT_TRUE(
      TextFormat::ParseFromString(kExpectedTcbmTextProto, &expected_tcbm));
  EXPECT_THAT(result.pck_cert, EqualsProto(expected_pck_cert));
  EXPECT_THAT(result.issuer_cert_chain, EqualsProto(expected_issuer_chain));
  EXPECT_THAT(result.tcbm, EqualsProto(expected_tcbm));
}

TEST_F(SgxPcsClientTest, GetPckCertificate_MalformedPpid) {
  const Ppid ppid;
  const CpuSvn cpu_svn = GetValidCpuSvn();
  const PceSvn pce_svn = GetValidPceSvn();
  const PceId pce_id = GetValidPceId();
  EXPECT_THAT(pcs_client_->GetPckCertificate(ppid, cpu_svn, pce_svn, pce_id),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(SgxPcsClientTest, GetPckCertificate_MalformedCpuSvn) {
  const Ppid ppid = GetValidPpid();
  const CpuSvn cpu_svn;
  const PceSvn pce_svn = GetValidPceSvn();
  const PceId pce_id = GetValidPceId();
  EXPECT_THAT(pcs_client_->GetPckCertificate(ppid, cpu_svn, pce_svn, pce_id),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(SgxPcsClientTest, GetPckCertificate_MalformedPceSvn) {
  const Ppid ppid = GetValidPpid();
  const CpuSvn cpu_svn = GetValidCpuSvn();
  const PceSvn pce_svn;
  const PceId pce_id = GetValidPceId();
  EXPECT_THAT(pcs_client_->GetPckCertificate(ppid, cpu_svn, pce_svn, pce_id),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(SgxPcsClientTest, GetPckCertificate_MalformedPceId) {
  const Ppid ppid = GetValidPpid();
  const CpuSvn cpu_svn = GetValidCpuSvn();
  const PceSvn pce_svn = GetValidPceSvn();
  const PceId pce_id;
  EXPECT_THAT(pcs_client_->GetPckCertificate(ppid, cpu_svn, pce_svn, pce_id),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(SgxPcsClientTest, GetPckCertificate_MalformedIssuerCertChain) {
  const Ppid ppid = GetValidPpid();
  const CpuSvn cpu_svn = GetValidCpuSvn();
  const PceSvn pce_svn = GetValidPceSvn();
  const PceId pce_id = GetValidPceId();
  const std::vector<uint8_t> ppid_encrypted = GetValidEncryptedPpid();
  EXPECT_CALL(*ppid_enc_key_mock_, Encrypt(Eq(ppid.value()), NotNull()))
      .Times(1)
      .WillOnce(
          DoAll(SetArgPointee<1>(ppid_encrypted), Return(absl::OkStatus())));
  std::vector<HttpFetcher::HttpHeaderField> expected_custom_headers;
  expected_custom_headers.push_back(std::make_pair(kHttpHeaderApiKey, kApiKey));
  HttpFetcher::HttpResponse response;
  response.status_code = 200;
  response.header = {{kGetPckCertHttpResponseHeaderIssuerCertChainKey,
                      "Not a valid PCK issuer certificate chain"},
                     {kGetPckCertHttpResponseHeaderTcbmKey,
                      kGetPckCertHttpResponseHeaderTcbmValue}};
  response.body = kGetPckCertHttpResponseBody;
  EXPECT_CALL(*fetcher_mock_, Get(Eq(kGetPckCertExpectedUrl),
                                  ElementsAreArray(expected_custom_headers)))
      .Times(1)
      .WillOnce(Return(response));

  EXPECT_THAT(pcs_client_->GetPckCertificate(ppid, cpu_svn, pce_svn, pce_id),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(SgxPcsClientTest, GetPckCertificate_MalformedTcbm) {
  const Ppid ppid = GetValidPpid();
  const CpuSvn cpu_svn = GetValidCpuSvn();
  const PceSvn pce_svn = GetValidPceSvn();
  const PceId pce_id = GetValidPceId();
  const std::vector<uint8_t> ppid_encrypted = GetValidEncryptedPpid();
  EXPECT_CALL(*ppid_enc_key_mock_, Encrypt(Eq(ppid.value()), NotNull()))
      .Times(1)
      .WillOnce(
          DoAll(SetArgPointee<1>(ppid_encrypted), Return(absl::OkStatus())));
  std::vector<HttpFetcher::HttpHeaderField> expected_custom_headers;
  expected_custom_headers.push_back(std::make_pair(kHttpHeaderApiKey, kApiKey));
  HttpFetcher::HttpResponse response;
  response.status_code = 200;
  response.header = {
      {kGetPckCertHttpResponseHeaderIssuerCertChainKey,
       kGetPckCertHttpResponseHeaderIssuerCertChainValue},
      {kGetPckCertHttpResponseHeaderTcbmKey, "Not a valid Tcbm value"}};
  response.body = kGetPckCertHttpResponseBody;
  EXPECT_CALL(*fetcher_mock_, Get(Eq(kGetPckCertExpectedUrl),
                                  ElementsAreArray(expected_custom_headers)))
      .Times(1)
      .WillOnce(Return(response));

  EXPECT_THAT(pcs_client_->GetPckCertificate(ppid, cpu_svn, pce_svn, pce_id),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(SgxPcsClientTest, GetPckCertificate_MalformedPckCertificate) {
  const Ppid ppid = GetValidPpid();
  const CpuSvn cpu_svn = GetValidCpuSvn();
  const PceSvn pce_svn = GetValidPceSvn();
  const PceId pce_id = GetValidPceId();
  const std::vector<uint8_t> ppid_encrypted = GetValidEncryptedPpid();
  EXPECT_CALL(*ppid_enc_key_mock_, Encrypt(Eq(ppid.value()), NotNull()))
      .Times(1)
      .WillOnce(
          DoAll(SetArgPointee<1>(ppid_encrypted), Return(absl::OkStatus())));
  std::vector<HttpFetcher::HttpHeaderField> expected_custom_headers;
  expected_custom_headers.push_back(std::make_pair(kHttpHeaderApiKey, kApiKey));
  HttpFetcher::HttpResponse response;
  response.status_code = 200;
  response.header = {{kGetPckCertHttpResponseHeaderIssuerCertChainKey,
                      kGetPckCertHttpResponseHeaderIssuerCertChainValue},
                     {kGetPckCertHttpResponseHeaderTcbmKey,
                      kGetPckCertHttpResponseHeaderTcbmValue}};
  response.body = "Not a PCK certificate";
  EXPECT_CALL(*fetcher_mock_, Get(Eq(kGetPckCertExpectedUrl),
                                  ElementsAreArray(expected_custom_headers)))
      .Times(1)
      .WillOnce(Return(response));

  EXPECT_THAT(pcs_client_->GetPckCertificate(ppid, cpu_svn, pce_svn, pce_id),
              StatusIs(absl::StatusCode::kInternal));
}

TEST_F(SgxPcsClientTest, GetPckCertificates_Success) {
  const Ppid ppid = GetValidPpid();
  const PceId pce_id = GetValidPceId();
  const std::vector<uint8_t> ppid_encrypted = GetValidEncryptedPpid();
  EXPECT_CALL(*ppid_enc_key_mock_, Encrypt(Eq(ppid.value()), NotNull()))
      .Times(1)
      .WillOnce(
          DoAll(SetArgPointee<1>(ppid_encrypted), Return(absl::OkStatus())));
  std::vector<HttpFetcher::HttpHeaderField> expected_custom_headers;
  expected_custom_headers.push_back(std::make_pair(kHttpHeaderApiKey, kApiKey));
  HttpFetcher::HttpResponse response;
  response.status_code = 200;
  response.header = {{kGetPckCertHttpResponseHeaderIssuerCertChainKey,
                      kGetPckCertHttpResponseHeaderIssuerCertChainValue}};
  response.body = kGetPckCertsHttpResponseBody;
  EXPECT_CALL(*fetcher_mock_, Get(Eq(kGetPckCertsExpectedUrl),
                                  ElementsAreArray(expected_custom_headers)))
      .Times(1)
      .WillOnce(Return(response));

  GetPckCertificatesResult result;
  ASYLO_ASSERT_OK_AND_ASSIGN(result,
                             pcs_client_->GetPckCertificates(ppid, pce_id));

  PckCertificates expected_pck_certs;
  ASSERT_TRUE(TextFormat::ParseFromString(kExpectedPckCertsTextProto,
                                          &expected_pck_certs));
  CertificateChain expected_issuer_chain;
  ASSERT_TRUE(TextFormat::ParseFromString(kExpectedPckIssuerCertChainTextProto,
                                          &expected_issuer_chain));
  EXPECT_THAT(result.pck_certs, EqualsProto(expected_pck_certs));
  EXPECT_THAT(result.issuer_cert_chain, EqualsProto(expected_issuer_chain));
}

TEST_F(SgxPcsClientTest, GetPckCertificates_MalformedPpid) {
  const Ppid ppid;
  const PceId pce_id = GetValidPceId();
  EXPECT_THAT(pcs_client_->GetPckCertificates(ppid, pce_id),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(SgxPcsClientTest, GetPckCertificates_MalformedPceId) {
  const Ppid ppid = GetValidPpid();
  const PceId pce_id;
  EXPECT_THAT(pcs_client_->GetPckCertificates(ppid, pce_id),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(SgxPcsClientTest, GetPckCertificates_MalformedIssuerCertChain) {
  const Ppid ppid = GetValidPpid();
  const PceId pce_id = GetValidPceId();
  const std::vector<uint8_t> ppid_encrypted = GetValidEncryptedPpid();
  EXPECT_CALL(*ppid_enc_key_mock_, Encrypt(Eq(ppid.value()), NotNull()))
      .Times(1)
      .WillOnce(
          DoAll(SetArgPointee<1>(ppid_encrypted), Return(absl::OkStatus())));
  std::vector<HttpFetcher::HttpHeaderField> expected_custom_headers;
  expected_custom_headers.push_back(std::make_pair(kHttpHeaderApiKey, kApiKey));
  HttpFetcher::HttpResponse response;
  response.status_code = 200;
  response.header = {{kGetPckCertHttpResponseHeaderIssuerCertChainKey,
                      "Not a valid PCK certificate issuer cert chain"}};
  response.body = kGetPckCertsHttpResponseBody;
  EXPECT_CALL(*fetcher_mock_, Get(Eq(kGetPckCertsExpectedUrl),
                                  ElementsAreArray(expected_custom_headers)))
      .Times(1)
      .WillOnce(Return(response));

  EXPECT_THAT(pcs_client_->GetPckCertificates(ppid, pce_id),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(SgxPcsClientTest, GetPckCertificates_MalformedPckCertificates) {
  const Ppid ppid = GetValidPpid();
  const PceId pce_id = GetValidPceId();
  const std::vector<uint8_t> ppid_encrypted = GetValidEncryptedPpid();
  EXPECT_CALL(*ppid_enc_key_mock_, Encrypt(Eq(ppid.value()), NotNull()))
      .Times(1)
      .WillOnce(
          DoAll(SetArgPointee<1>(ppid_encrypted), Return(absl::OkStatus())));
  std::vector<HttpFetcher::HttpHeaderField> expected_custom_headers;
  expected_custom_headers.push_back(std::make_pair(kHttpHeaderApiKey, kApiKey));
  HttpFetcher::HttpResponse response;
  response.status_code = 200;
  response.header = {{kGetPckCertHttpResponseHeaderIssuerCertChainKey,
                      kGetPckCertHttpResponseHeaderIssuerCertChainValue}};
  response.body = "Not valid PCK certificates";
  EXPECT_CALL(*fetcher_mock_, Get(Eq(kGetPckCertsExpectedUrl),
                                  ElementsAreArray(expected_custom_headers)))
      .Times(1)
      .WillOnce(Return(response));

  GetPckCertificatesResult result;
  EXPECT_THAT(pcs_client_->GetPckCertificates(ppid, pce_id),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(SgxPcsClientTest, GetCrl_Success) {
  HttpFetcher::HttpResponse response;
  response.status_code = 200;
  response.body = kGetCrlHttpResponseBody;
  response.header = {{kGetCrlHttpResponseHeaderIssuerCertChainKey,
                      kGetCrlHttpResponseHeaderIssuerCertChainValue}};
  EXPECT_CALL(*fetcher_mock_, Get(Eq(kGetCrlExpectedUrl), IsEmpty()))
      .Times(1)
      .WillOnce(Return(response));

  GetCrlResult result;
  ASYLO_ASSERT_OK_AND_ASSIGN(result, pcs_client_->GetCrl(SgxCaType::PROCESSOR));

  CertificateRevocationList expected_pck_crl;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(kExpectedCrlTextProto,
                                                  &expected_pck_crl));
  CertificateChain expected_issuer_cert_chain;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(
      kExpectedCrlIssuerCertChainTextProto, &expected_issuer_cert_chain));
  EXPECT_THAT(result.pck_crl, EqualsProto(expected_pck_crl));
  EXPECT_THAT(result.issuer_cert_chain,
              EqualsProto(expected_issuer_cert_chain));
}

TEST_F(SgxPcsClientTest, GetCrl_MalformedIssuerCertChain) {
  HttpFetcher::HttpResponse response;
  response.status_code = 200;
  response.body = kGetCrlHttpResponseBody;
  response.header = {{kGetCrlHttpResponseHeaderIssuerCertChainKey,
                      "Not a valid issuer cert chain"}};
  EXPECT_CALL(*fetcher_mock_, Get(Eq(kGetCrlExpectedUrl), IsEmpty()))
      .Times(1)
      .WillOnce(Return(response));

  EXPECT_THAT(pcs_client_->GetCrl(SgxCaType::PROCESSOR),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(SgxPcsClientTest, GetTcbInfo_Success) {
  const Fmspc fmspc = GetValidFmspc();
  HttpFetcher::HttpResponse response;
  response.status_code = 200;
  response.body = kGetTcbInfoHttpResponseBody;
  response.header = {{kGetTcbInfoHttpResponseHeaderIssuerCertChainKey,
                      kGetTcbInfoHttpResponseHeaderIssuerCertChainValue}};
  EXPECT_CALL(*fetcher_mock_, Get(Eq(kGetTcbInfoExpectedUrl), IsEmpty()))
      .Times(1)
      .WillOnce(Return(response));

  GetTcbInfoResult result;
  ASYLO_ASSERT_OK_AND_ASSIGN(result, pcs_client_->GetTcbInfo(fmspc));

  SignedTcbInfo signed_tcb_info;
  ASSERT_TRUE(TextFormat::ParseFromString(kExpectedSignedTcbInfoTextProto,
                                          &signed_tcb_info));
  CertificateChain issuer_cert_chain;
  ASSERT_TRUE(TextFormat::ParseFromString(
      kExpectedTcbInfoIssuerCertChainTextProto, &issuer_cert_chain));
  EXPECT_THAT(result.tcb_info, EqualsProto(signed_tcb_info));
  EXPECT_THAT(result.issuer_cert_chain, EqualsProto(issuer_cert_chain));
}

TEST_F(SgxPcsClientTest, GetTcbInfo_MalformedFmspc) {
  Fmspc fmspc;
  fmspc.set_value("\x00\x90\x6e\xa1\x00\x00\00\00", 8);
  EXPECT_THAT(pcs_client_->GetTcbInfo(fmspc),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(SgxPcsClientTest, GetTcbInfo_MalformedIssuerCertChain) {
  const Fmspc fmspc = GetValidFmspc();
  HttpFetcher::HttpResponse response;
  response.status_code = 200;
  response.body = kGetTcbInfoHttpResponseBody;
  response.header = {{kGetTcbInfoHttpResponseHeaderIssuerCertChainKey,
                      "Not a valid issuer cert chain"}};
  EXPECT_CALL(*fetcher_mock_, Get(Eq(kGetTcbInfoExpectedUrl), IsEmpty()))
      .Times(1)
      .WillOnce(Return(response));

  EXPECT_THAT(pcs_client_->GetTcbInfo(fmspc),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(SgxPcsClientTest, GetTcbInfo_MalformedTcbInfo) {
  const Fmspc fmspc = GetValidFmspc();
  HttpFetcher::HttpResponse response;
  response.status_code = 200;
  response.body = "Not a valid signed TCB info";
  response.header = {{kGetTcbInfoHttpResponseHeaderIssuerCertChainKey,
                      kGetTcbInfoHttpResponseHeaderIssuerCertChainValue}};
  EXPECT_CALL(*fetcher_mock_, Get(Eq(kGetTcbInfoExpectedUrl), IsEmpty()))
      .Times(1)
      .WillOnce(Return(response));

  EXPECT_THAT(pcs_client_->GetTcbInfo(fmspc),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

// Represents the error states of the HttpFetcher's response.
struct FetcherResponseErrorState {
  // Status returned by HttpFetcher::Get().
  absl::StatusCode status;
  // HTTP response code set returned through HttpResponse.
  int http_response_code;
};

StatusOr<HttpFetcher::HttpResponse> CreateErrorFetchResponse(
    const FetcherResponseErrorState &error_state) {
  if (error_state.status != absl::StatusCode::kOk) {
    return Status(error_state.status, "");
  }
  HttpFetcher::HttpResponse response;
  response.status_code = error_state.http_response_code;
  return response;
}

// Used to represent the errors and the expected parsing status.
struct FetcherResponseErrorAndParsingResult {
  FetcherResponseErrorState response_error_state;
  absl::StatusCode expected_status_code;
};

// Attaches parameterization to SgxPcsClientTest to test PCS client response
// errors.
class SgxPcsClientErrorTest
    : public SgxPcsClientTest,
      public WithParamInterface<FetcherResponseErrorAndParsingResult> {};

// These tests represents the situation where a fetcher response contains an
// error.
INSTANTIATE_TEST_SUITE_P(
    ClientErrors, SgxPcsClientErrorTest,
    ValuesIn(std::vector<FetcherResponseErrorAndParsingResult>{
        // 400 Bad Request.
        {{absl::StatusCode::kOk, 400}, absl::StatusCode::kInvalidArgument},

        // 401 Unauthorized.
        {{absl::StatusCode::kOk, 401}, absl::StatusCode::kUnauthenticated},

        // 404 Not found.
        {{absl::StatusCode::kOk, 404}, absl::StatusCode::kNotFound},

        // 500 Internal server error.
        {{absl::StatusCode::kOk, 500}, absl::StatusCode::kInternal},

        // 503 service unavailable.
        {{absl::StatusCode::kOk, 503}, absl::StatusCode::kUnavailable},

        // Fetch request is roboted.
        {{absl::StatusCode::kInternal, 0}, absl::StatusCode::kInternal}}));

TEST_P(SgxPcsClientErrorTest, GetPckCertificate) {
  const Ppid ppid = GetValidPpid();
  const CpuSvn cpu_svn = GetValidCpuSvn();
  const PceSvn pce_svn = GetValidPceSvn();
  const PceId pce_id = GetValidPceId();
  const std::vector<uint8_t> ppid_encrypted = GetValidEncryptedPpid();
  EXPECT_CALL(*ppid_enc_key_mock_, Encrypt(Eq(ppid.value()), NotNull()))
      .Times(1)
      .WillOnce(
          DoAll(SetArgPointee<1>(ppid_encrypted), Return(absl::OkStatus())));
  std::vector<HttpFetcher::HttpHeaderField> expected_custom_headers;
  expected_custom_headers.push_back(std::make_pair(kHttpHeaderApiKey, kApiKey));
  const StatusOr<HttpFetcher::HttpResponse> fetch_result =
      CreateErrorFetchResponse(GetParam().response_error_state);
  EXPECT_CALL(*fetcher_mock_, Get(Eq(kGetPckCertExpectedUrl),
                                  ElementsAreArray(expected_custom_headers)))
      .Times(1)
      .WillOnce(Return(fetch_result));

  EXPECT_THAT(pcs_client_->GetPckCertificate(ppid, cpu_svn, pce_svn, pce_id),
              StatusIs(GetParam().expected_status_code));
}

TEST_P(SgxPcsClientErrorTest, GetPckCertificates) {
  const Ppid ppid = GetValidPpid();
  const PceId pce_id = GetValidPceId();
  const std::vector<uint8_t> ppid_encrypted = GetValidEncryptedPpid();
  EXPECT_CALL(*ppid_enc_key_mock_, Encrypt(Eq(ppid.value()), NotNull()))
      .Times(1)
      .WillOnce(
          DoAll(SetArgPointee<1>(ppid_encrypted), Return(absl::OkStatus())));
  std::vector<HttpFetcher::HttpHeaderField> expected_custom_headers;
  expected_custom_headers.push_back(std::make_pair(kHttpHeaderApiKey, kApiKey));
  const StatusOr<HttpFetcher::HttpResponse> fetch_result =
      CreateErrorFetchResponse(GetParam().response_error_state);
  EXPECT_CALL(*fetcher_mock_, Get(Eq(kGetPckCertsExpectedUrl),
                                  ElementsAreArray(expected_custom_headers)))
      .Times(1)
      .WillOnce(Return(fetch_result));

  EXPECT_THAT(pcs_client_->GetPckCertificates(ppid, pce_id),
              StatusIs(GetParam().expected_status_code));
}

TEST_P(SgxPcsClientErrorTest, GetCrl) {
  const StatusOr<HttpFetcher::HttpResponse> fetch_result =
      CreateErrorFetchResponse(GetParam().response_error_state);
  EXPECT_CALL(*fetcher_mock_, Get(Eq(kGetCrlExpectedUrl), IsEmpty()))
      .Times(1)
      .WillOnce(Return(fetch_result));

  EXPECT_THAT(pcs_client_->GetCrl(SgxCaType::PROCESSOR),
              StatusIs(GetParam().expected_status_code));
}

TEST_P(SgxPcsClientErrorTest, GetTcbInfo) {
  const Fmspc fmspc = GetValidFmspc();
  const StatusOr<HttpFetcher::HttpResponse> fetch_result =
      CreateErrorFetchResponse(GetParam().response_error_state);
  EXPECT_CALL(*fetcher_mock_, Get(Eq(kGetTcbInfoExpectedUrl), IsEmpty()))
      .Times(1)
      .WillOnce(Return(fetch_result));

  EXPECT_THAT(pcs_client_->GetTcbInfo(fmspc),
              StatusIs(GetParam().expected_status_code));
}

}  // namespace
}  // namespace sgx
}  // namespace asylo
