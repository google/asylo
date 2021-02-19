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

#include "asylo/identity/provisioning/sgx/internal/pck_certs_from_json.h"

#include <memory>

#include "google/protobuf/struct.pb.h"
#include <google/protobuf/text_format.h>
#include <google/protobuf/util/json_util.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "asylo/identity/provisioning/sgx/internal/pck_certificates.pb.h"
#include "asylo/test/util/output_collector.h"
#include "asylo/test/util/proto_matchers.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/error_codes.h"
#include "asylo/util/status.h"

namespace asylo {
namespace sgx {
namespace {

using ::testing::HasSubstr;

constexpr char kValidPckCertsJson[] =
    "[{\"tcb\":{\"sgxtcbcomp01svn\":6,\"sgxtcbcomp02svn\":6,\"sgxtcbcomp03s"
    "vn\":2,\"sgxtcbcomp04svn\":4,\"sgxtcbcomp05svn\":1,\"sgxtcbcomp06svn\""
    ":128,\"sgxtcbcomp07svn\":1,\"sgxtcbcomp08svn\":0,\"sgxtcbcomp09svn\":0"
    ",\"sgxtcbcomp10svn\":0,\"sgxtcbcomp11svn\":0,\"sgxtcbcomp12svn\":0,\"s"
    "gxtcbcomp13svn\":0,\"sgxtcbcomp14svn\":0,\"sgxtcbcomp15svn\":0,\"sgxtc"
    "bcomp16svn\":0,\"pcesvn\":7},\"tcbm\":\"060602040180010000000000000000"
    "000700\",\"cert\":\"-----BEGIN%20CERTIFICATE-----%0AMIIEgDCCBCagAwIBAg"
    "IUVEUOECXhHHTveY0hS2kbngAuXowwCgYIKoZIzj0EAwIwcTEjMCEGA1UE%0AAwwaSW50Z"
    "WwgU0dYIFBDSyBQcm9jZXNzb3IgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9u%0A"
    "MRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYTAlVTMB4XDT"
    "E5MTAy%0AMjIxMzEwOFoXDTI2MTAyMjIxMzEwOFowcDEiMCAGA1UEAwwZSW50ZWwgU0dYI"
    "FBDSyBDZXJ0aWZp%0AY2F0ZTEaMBgGA1UECgwRSW50ZWwgQ29ycG9yYXRpb24xFDASBgNV"
    "BAcMC1NhbnRhIENsYXJhMQsw%0ACQYDVQQIDAJDQTELMAkGA1UEBhMCVVMwWTATBgcqhkj"
    "OPQIBBggqhkjOPQMBBwNCAAQ06CXTMK6h%0A%2FBR2sRaSssWO8MqEdbccOGWzyLjwiRx1"
    "zfyrreCqgAN2LOkGAKFlomquV%2FCZ369yTSm7li4APNfC%0Ao4ICmzCCApcwHwYDVR0jB"
    "BgwFoAU0Oiq2nXX%2BS5JF5g8exRl0NXyWU0wXwYDVR0fBFgwVjBUoFKg%0AUIZOaHR0cH"
    "M6Ly9hcGkudHJ1c3RlZHNlcnZpY2VzLmludGVsLmNvbS9zZ3gvY2VydGlmaWNhdGlv%0Ab"
    "i92MS9wY2tjcmw%2FY2E9cHJvY2Vzc29yMB0GA1UdDgQWBBRBM37ZBg6NUUSIMXn4sRcRj"
    "FN%2FPDAO%0ABgNVHQ8BAf8EBAMCBsAwDAYDVR0TAQH%2FBAIwADCCAdQGCSqGSIb4TQEN"
    "AQSCAcUwggHBMB4GCiqG%0ASIb4TQENAQEEEHuXvnfGLUJGxgPQ9PEbMbswggFkBgoqhki"
    "G%2BE0BDQECMIIBVDAQBgsqhkiG%2BE0B%0ADQECAQIBBjAQBgsqhkiG%2BE0BDQECAgIB"
    "BjAQBgsqhkiG%2BE0BDQECAwIBAjAQBgsqhkiG%2BE0BDQEC%0ABAIBBDAQBgsqhkiG%2B"
    "E0BDQECBQIBATARBgsqhkiG%2BE0BDQECBgICAIAwEAYLKoZIhvhNAQ0BAgcC%0AAQEwEA"
    "YLKoZIhvhNAQ0BAggCAQAwEAYLKoZIhvhNAQ0BAgkCAQAwEAYLKoZIhvhNAQ0BAgoCAQAw"
    "%0AEAYLKoZIhvhNAQ0BAgsCAQAwEAYLKoZIhvhNAQ0BAgwCAQAwEAYLKoZIhvhNAQ0BAg0"
    "CAQAwEAYL%0AKoZIhvhNAQ0BAg4CAQAwEAYLKoZIhvhNAQ0BAg8CAQAwEAYLKoZIhvhNAQ"
    "0BAhACAQAwEAYLKoZI%0AhvhNAQ0BAhECAQcwHwYLKoZIhvhNAQ0BAhIEEAYGAgQBgAEAA"
    "AAAAAAAAAAwEAYKKoZIhvhNAQ0B%0AAwQCAAAwFAYKKoZIhvhNAQ0BBAQGAJBuoQAAMA8G"
    "CiqGSIb4TQENAQUKAQAwCgYIKoZIzj0EAwID%0ASAAwRQIgOeU15KgeYYEBPLDXF8du1g4"
    "5KOz3Es7fBm9pJ9aXeSACIQC2pdR1J%2BUAhoMmj2MKIaQi%0ABF5z3M27EElsAKtZUXM3"
    "7Q%3D%3D%0A-----END%20CERTIFICATE-----\"},{\"tcb\":{\"sgxtcbcomp01svn"
    "\":6,\"sgxtcbcomp02svn\":6,\"sgxtcbcomp03svn\":2,\"sgxtcbcomp04svn\":4"
    ",\"sgxtcbcomp05svn\":1,\"sgxtcbcomp06svn\":128,\"sgxtcbcomp07svn\":0,"
    "\"sgxtcbcomp08svn\":0,\"sgxtcbcomp09svn\":0,\"sgxtcbcomp10svn\":0,\"sg"
    "xtcbcomp11svn\":0,\"sgxtcbcomp12svn\":0,\"sgxtcbcomp13svn\":0,\"sgxtcb"
    "comp14svn\":0,\"sgxtcbcomp15svn\":0,\"sgxtcbcomp16svn\":0,\"pcesvn\":7"
    "},\"tcbm\":\"060602040180000000000000000000000700\",\"cert\":\"-----BE"
    "GIN%20CERTIFICATE-----%0AMIIEgDCCBCegAwIBAgIVAKOnJWy71ZwjgzZ%2BdQ4kQtw"
    "DZ85nMAoGCCqGSM49BAMCMHExIzAhBgNV%0ABAMMGkludGVsIFNHWCBQQ0sgUHJvY2Vzc2"
    "9yIENBMRowGAYDVQQKDBFJbnRlbCBDb3Jwb3JhdGlv%0AbjEUMBIGA1UEBwwLU2FudGEgQ"
    "2xhcmExCzAJBgNVBAgMAkNBMQswCQYDVQQGEwJVUzAeFw0xOTEw%0AMjIyMTMxMDhaFw0y"
    "NjEwMjIyMTMxMDhaMHAxIjAgBgNVBAMMGUludGVsIFNHWCBQQ0sgQ2VydGlm%0AaWNhdGU"
    "xGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTEL%"
    "0AMAkGA1UECAwCQ0ExCzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE"
    "Kq9bOB5%2B%0Al5%2BD8Jy6m4N3fEfG143k4fBEIUHTI11TwGA6nXYPy3otv6ggl6d9mUs"
    "Dt%2Bt1tOjvgNCaVudrhUbP%0Aq6OCApswggKXMB8GA1UdIwQYMBaAFNDoqtp11%2FkuSR"
    "eYPHsUZdDV8llNMF8GA1UdHwRYMFYwVKBS%0AoFCGTmh0dHBzOi8vYXBpLnRydXN0ZWRzZ"
    "XJ2aWNlcy5pbnRlbC5jb20vc2d4L2NlcnRpZmljYXRp%0Ab24vdjEvcGNrY3JsP2NhPXBy"
    "b2Nlc3NvcjAdBgNVHQ4EFgQU%2BfN53shxLxPvhXblSobC21HrvmIw%0ADgYDVR0PAQH%2"
    "FBAQDAgbAMAwGA1UdEwEB%2FwQCMAAwggHUBgkqhkiG%2BE0BDQEEggHFMIIBwTAeBgoq%"
    "0AhkiG%2BE0BDQEBBBB7l753xi1CRsYD0PTxGzG7MIIBZAYKKoZIhvhNAQ0BAjCCAVQwEA"
    "YLKoZIhvhN%0AAQ0BAgECAQYwEAYLKoZIhvhNAQ0BAgICAQYwEAYLKoZIhvhNAQ0BAgMCA"
    "QIwEAYLKoZIhvhNAQ0B%0AAgQCAQQwEAYLKoZIhvhNAQ0BAgUCAQEwEQYLKoZIhvhNAQ0B"
    "AgYCAgCAMBAGCyqGSIb4TQENAQIH%0AAgEAMBAGCyqGSIb4TQENAQIIAgEAMBAGCyqGSIb"
    "4TQENAQIJAgEAMBAGCyqGSIb4TQENAQIKAgEA%0AMBAGCyqGSIb4TQENAQILAgEAMBAGCy"
    "qGSIb4TQENAQIMAgEAMBAGCyqGSIb4TQENAQINAgEAMBAG%0ACyqGSIb4TQENAQIOAgEAM"
    "BAGCyqGSIb4TQENAQIPAgEAMBAGCyqGSIb4TQENAQIQAgEAMBAGCyqG%0ASIb4TQENAQIR"
    "AgEHMB8GCyqGSIb4TQENAQISBBAGBgIEAYAAAAAAAAAAAAAAMBAGCiqGSIb4TQEN%0AAQM"
    "EAgAAMBQGCiqGSIb4TQENAQQEBgCQbqEAADAPBgoqhkiG%2BE0BDQEFCgEAMAoGCCqGSM4"
    "9BAMC%0AA0cAMEQCIAaNDss%2B0OVptuknGsuD1%2BNrEDUtZxYjt%2Bx4XKZ2yFPRAiBx"
    "S%2F5hETSU3v9EW45YoPip%0AcgnNaIK%2FYu4wjpo4RtWffQ%3D%3D%0A-----END%20C"
    "ERTIFICATE-----\"},{\"tcb\":{\"sgxtcbcomp01svn\":5,\"sgxtcbcomp02svn\""
    ":5,\"sgxtcbcomp03svn\":2,\"sgxtcbcomp04svn\":4,\"sgxtcbcomp05svn\":1,"
    "\"sgxtcbcomp06svn\":128,\"sgxtcbcomp07svn\":1,\"sgxtcbcomp08svn\":0,\""
    "sgxtcbcomp09svn\":0,\"sgxtcbcomp10svn\":0,\"sgxtcbcomp11svn\":0,\"sgxt"
    "cbcomp12svn\":0,\"sgxtcbcomp13svn\":0,\"sgxtcbcomp14svn\":0,\"sgxtcbco"
    "mp15svn\":0,\"sgxtcbcomp16svn\":0,\"pcesvn\":7},\"tcbm\":\"05050204018"
    "0010000000000000000000700\",\"cert\":\"-----BEGIN%20CERTIFICATE-----%0"
    "AMIIEgTCCBCegAwIBAgIVAIudIsG0zFrcVwWCJpnF%2FoJ%2FAv3UMAoGCCqGSM49BAMCM"
    "HExIzAhBgNV%0ABAMMGkludGVsIFNHWCBQQ0sgUHJvY2Vzc29yIENBMRowGAYDVQQKDBFJ"
    "bnRlbCBDb3Jwb3JhdGlv%0AbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkN"
    "BMQswCQYDVQQGEwJVUzAeFw0xOTEw%0AMjIyMTMxMDhaFw0yNjEwMjIyMTMxMDhaMHAxIj"
    "AgBgNVBAMMGUludGVsIFNHWCBQQ0sgQ2VydGlm%0AaWNhdGUxGjAYBgNVBAoMEUludGVsI"
    "ENvcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTEL%0AMAkGA1UECAwCQ0ExCzAJ"
    "BgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEvZb0pkVJ%0ALhna4zUXQy1"
    "jp%2FSMIkIE2ufJjSVCNU4g5ymzO0RKS%2B%2BXpSwDOJHNxCpIyCkpWeYNbj9m6HDd0zW"
    "s%0AHaOCApswggKXMB8GA1UdIwQYMBaAFNDoqtp11%2FkuSReYPHsUZdDV8llNMF8GA1Ud"
    "HwRYMFYwVKBS%0AoFCGTmh0dHBzOi8vYXBpLnRydXN0ZWRzZXJ2aWNlcy5pbnRlbC5jb20"
    "vc2d4L2NlcnRpZmljYXRp%0Ab24vdjEvcGNrY3JsP2NhPXByb2Nlc3NvcjAdBgNVHQ4EFg"
    "QUiyOA3JWI9LZWgvm%2FZZBMdTCRMt0w%0ADgYDVR0PAQH%2FBAQDAgbAMAwGA1UdEwEB%"
    "2FwQCMAAwggHUBgkqhkiG%2BE0BDQEEggHFMIIBwTAeBgoq%0AhkiG%2BE0BDQEBBBB7l7"
    "53xi1CRsYD0PTxGzG7MIIBZAYKKoZIhvhNAQ0BAjCCAVQwEAYLKoZIhvhN%0AAQ0BAgECA"
    "QUwEAYLKoZIhvhNAQ0BAgICAQUwEAYLKoZIhvhNAQ0BAgMCAQIwEAYLKoZIhvhNAQ0B%0A"
    "AgQCAQQwEAYLKoZIhvhNAQ0BAgUCAQEwEQYLKoZIhvhNAQ0BAgYCAgCAMBAGCyqGSIb4TQ"
    "ENAQIH%0AAgEBMBAGCyqGSIb4TQENAQIIAgEAMBAGCyqGSIb4TQENAQIJAgEAMBAGCyqGS"
    "Ib4TQENAQIKAgEA%0AMBAGCyqGSIb4TQENAQILAgEAMBAGCyqGSIb4TQENAQIMAgEAMBAG"
    "CyqGSIb4TQENAQINAgEAMBAG%0ACyqGSIb4TQENAQIOAgEAMBAGCyqGSIb4TQENAQIPAgE"
    "AMBAGCyqGSIb4TQENAQIQAgEAMBAGCyqG%0ASIb4TQENAQIRAgEHMB8GCyqGSIb4TQENAQ"
    "ISBBAFBQIEAYABAAAAAAAAAAAAMBAGCiqGSIb4TQEN%0AAQMEAgAAMBQGCiqGSIb4TQENA"
    "QQEBgCQbqEAADAPBgoqhkiG%2BE0BDQEFCgEAMAoGCCqGSM49BAMC%0AA0gAMEUCIQCQbg"
    "df4D%2BVOGBu8DxSLEEO%2FvwJxWeNR%2B8VyzZd7ETb2QIgSpmaPfkq4%2Fi4urdMi2j%"
    "2F%0AehL58ueUYn9RZCPPjR5rUzs%3D%0A-----END%20CERTIFICATE-----\"},{\"tc"
    "b\":{\"sgxtcbcomp01svn\":5,\"sgxtcbcomp02svn\":5,\"sgxtcbcomp03svn\":2"
    ",\"sgxtcbcomp04svn\":4,\"sgxtcbcomp05svn\":1,\"sgxtcbcomp06svn\":128,"
    "\"sgxtcbcomp07svn\":1,\"sgxtcbcomp08svn\":0,\"sgxtcbcomp09svn\":0,\"sg"
    "xtcbcomp10svn\":0,\"sgxtcbcomp11svn\":0,\"sgxtcbcomp12svn\":0,\"sgxtcb"
    "comp13svn\":0,\"sgxtcbcomp14svn\":0,\"sgxtcbcomp15svn\":0,\"sgxtcbcomp"
    "16svn\":0,\"pcesvn\":6},\"tcbm\":\"05050204018001000000000000000000060"
    "0\",\"cert\":\"-----BEGIN%20CERTIFICATE-----%0AMIIEgTCCBCegAwIBAgIVAMl"
    "0gn%2FyTGg0szm6AZSJsfQ4nId%2BMAoGCCqGSM49BAMCMHExIzAhBgNV%0ABAMMGkludG"
    "VsIFNHWCBQQ0sgUHJvY2Vzc29yIENBMRowGAYDVQQKDBFJbnRlbCBDb3Jwb3JhdGlv%0Ab"
    "jEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNBMQswCQYDVQQGEwJVUzAeFw0"
    "xOTEw%0AMjIyMTMxMDhaFw0yNjEwMjIyMTMxMDhaMHAxIjAgBgNVBAMMGUludGVsIFNHWC"
    "BQQ0sgQ2VydGlm%0AaWNhdGUxGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMRQwEgYDV"
    "QQHDAtTYW50YSBDbGFyYTEL%0AMAkGA1UECAwCQ0ExCzAJBgNVBAYTAlVTMFkwEwYHKoZI"
    "zj0CAQYIKoZIzj0DAQcDQgAEe9F11Ntj%0AnX5a7Nfl%2FwjWISOfAvZR5xQfzUjwHyMf%"
    "2BZarzvd8B5UIPxVzGrP8YW1p3XYoIm6z%2FXktniW4Evkg%0Ai6OCApswggKXMB8GA1Ud"
    "IwQYMBaAFNDoqtp11%2FkuSReYPHsUZdDV8llNMF8GA1UdHwRYMFYwVKBS%0AoFCGTmh0d"
    "HBzOi8vYXBpLnRydXN0ZWRzZXJ2aWNlcy5pbnRlbC5jb20vc2d4L2NlcnRpZmljYXRp%0A"
    "b24vdjEvcGNrY3JsP2NhPXByb2Nlc3NvcjAdBgNVHQ4EFgQUthXfuhFFvtMnwgmBefqSJ8"
    "4hv1Ew%0ADgYDVR0PAQH%2FBAQDAgbAMAwGA1UdEwEB%2FwQCMAAwggHUBgkqhkiG%2BE0"
    "BDQEEggHFMIIBwTAeBgoq%0AhkiG%2BE0BDQEBBBB7l753xi1CRsYD0PTxGzG7MIIBZAYK"
    "KoZIhvhNAQ0BAjCCAVQwEAYLKoZIhvhN%0AAQ0BAgECAQUwEAYLKoZIhvhNAQ0BAgICAQU"
    "wEAYLKoZIhvhNAQ0BAgMCAQIwEAYLKoZIhvhNAQ0B%0AAgQCAQQwEAYLKoZIhvhNAQ0BAg"
    "UCAQEwEQYLKoZIhvhNAQ0BAgYCAgCAMBAGCyqGSIb4TQENAQIH%0AAgEBMBAGCyqGSIb4T"
    "QENAQIIAgEAMBAGCyqGSIb4TQENAQIJAgEAMBAGCyqGSIb4TQENAQIKAgEA%0AMBAGCyqG"
    "SIb4TQENAQILAgEAMBAGCyqGSIb4TQENAQIMAgEAMBAGCyqGSIb4TQENAQINAgEAMBAG%0"
    "ACyqGSIb4TQENAQIOAgEAMBAGCyqGSIb4TQENAQIPAgEAMBAGCyqGSIb4TQENAQIQAgEAM"
    "BAGCyqG%0ASIb4TQENAQIRAgEGMB8GCyqGSIb4TQENAQISBBAFBQIEAYABAAAAAAAAAAAA"
    "MBAGCiqGSIb4TQEN%0AAQMEAgAAMBQGCiqGSIb4TQENAQQEBgCQbqEAADAPBgoqhkiG%2B"
    "E0BDQEFCgEAMAoGCCqGSM49BAMC%0AA0gAMEUCIC9PuFFxvrutNKnZpVKGdDKqkgbff5m3"
    "9IZDBsPBehgtAiEA%2BUaoazq4L%2BogsvEdvr3e%0AjnmLyX7toAc1HhQKpcMCbI4%3D%"
    "0A-----END%20CERTIFICATE-----\"},{\"tcb\":{\"sgxtcbcomp01svn\":5,\"sgx"
    "tcbcomp02svn\":5,\"sgxtcbcomp03svn\":2,\"sgxtcbcomp04svn\":4,\"sgxtcbc"
    "omp05svn\":1,\"sgxtcbcomp06svn\":128,\"sgxtcbcomp07svn\":0,\"sgxtcbcom"
    "p08svn\":0,\"sgxtcbcomp09svn\":0,\"sgxtcbcomp10svn\":0,\"sgxtcbcomp11s"
    "vn\":0,\"sgxtcbcomp12svn\":0,\"sgxtcbcomp13svn\":0,\"sgxtcbcomp14svn\""
    ":0,\"sgxtcbcomp15svn\":0,\"sgxtcbcomp16svn\":0,\"pcesvn\":7},\"tcbm\":"
    "\"050502040180000000000000000000000700\",\"cert\":\"-----BEGIN%20CERTI"
    "FICATE-----%0AMIIEgTCCBCegAwIBAgIVAJ1mxDIzAXa%2BixcUKKaUmyYxoyJlMAoGCC"
    "qGSM49BAMCMHExIzAhBgNV%0ABAMMGkludGVsIFNHWCBQQ0sgUHJvY2Vzc29yIENBMRowG"
    "AYDVQQKDBFJbnRlbCBDb3Jwb3JhdGlv%0AbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJ"
    "BgNVBAgMAkNBMQswCQYDVQQGEwJVUzAeFw0xOTEw%0AMjIyMTMxMDhaFw0yNjEwMjIyMTM"
    "xMDhaMHAxIjAgBgNVBAMMGUludGVsIFNHWCBQQ0sgQ2VydGlm%0AaWNhdGUxGjAYBgNVBA"
    "oMEUludGVsIENvcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTEL%0AMAkGA1UEC"
    "AwCQ0ExCzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEF7aCJQzG%0A"
    "R7R%2FoeDkuyiFhknVXV4mKl72QUCD%2B02CS%2Ba0AUnJtKz37EmAyd5afJ38dFswPFL1"
    "upLY7yrEco99%0A3qOCApswggKXMB8GA1UdIwQYMBaAFNDoqtp11%2FkuSReYPHsUZdDV8"
    "llNMF8GA1UdHwRYMFYwVKBS%0AoFCGTmh0dHBzOi8vYXBpLnRydXN0ZWRzZXJ2aWNlcy5p"
    "bnRlbC5jb20vc2d4L2NlcnRpZmljYXRp%0Ab24vdjEvcGNrY3JsP2NhPXByb2Nlc3NvcjA"
    "dBgNVHQ4EFgQUFBTkM8dooH85tY3YGlV1MtZs1zEw%0ADgYDVR0PAQH%2FBAQDAgbAMAwG"
    "A1UdEwEB%2FwQCMAAwggHUBgkqhkiG%2BE0BDQEEggHFMIIBwTAeBgoq%0AhkiG%2BE0BD"
    "QEBBBB7l753xi1CRsYD0PTxGzG7MIIBZAYKKoZIhvhNAQ0BAjCCAVQwEAYLKoZIhvhN%0A"
    "AQ0BAgECAQUwEAYLKoZIhvhNAQ0BAgICAQUwEAYLKoZIhvhNAQ0BAgMCAQIwEAYLKoZIhv"
    "hNAQ0B%0AAgQCAQQwEAYLKoZIhvhNAQ0BAgUCAQEwEQYLKoZIhvhNAQ0BAgYCAgCAMBAGC"
    "yqGSIb4TQENAQIH%0AAgEAMBAGCyqGSIb4TQENAQIIAgEAMBAGCyqGSIb4TQENAQIJAgEA"
    "MBAGCyqGSIb4TQENAQIKAgEA%0AMBAGCyqGSIb4TQENAQILAgEAMBAGCyqGSIb4TQENAQI"
    "MAgEAMBAGCyqGSIb4TQENAQINAgEAMBAG%0ACyqGSIb4TQENAQIOAgEAMBAGCyqGSIb4TQ"
    "ENAQIPAgEAMBAGCyqGSIb4TQENAQIQAgEAMBAGCyqG%0ASIb4TQENAQIRAgEHMB8GCyqGS"
    "Ib4TQENAQISBBAFBQIEAYAAAAAAAAAAAAAAMBAGCiqGSIb4TQEN%0AAQMEAgAAMBQGCiqG"
    "SIb4TQENAQQEBgCQbqEAADAPBgoqhkiG%2BE0BDQEFCgEAMAoGCCqGSM49BAMC%0AA0gAM"
    "EUCIQCp7yWWNBSgS5F3I2TsTQzs4iKLMTbCyeZDkkodvy3a7QIgCZDe7QelYEq09%2FdY4"
    "m%2Bb%0Agatpb76k57o%2BenAazk0u6Mk%3D%0A-----END%20CERTIFICATE-----\"},"
    "{\"tcb\":{\"sgxtcbcomp01svn\":5,\"sgxtcbcomp02svn\":5,\"sgxtcbcomp03sv"
    "n\":2,\"sgxtcbcomp04svn\":4,\"sgxtcbcomp05svn\":1,\"sgxtcbcomp06svn\":"
    "128,\"sgxtcbcomp07svn\":0,\"sgxtcbcomp08svn\":0,\"sgxtcbcomp09svn\":0,"
    "\"sgxtcbcomp10svn\":0,\"sgxtcbcomp11svn\":0,\"sgxtcbcomp12svn\":0,\"sg"
    "xtcbcomp13svn\":0,\"sgxtcbcomp14svn\":0,\"sgxtcbcomp15svn\":0,\"sgxtcb"
    "comp16svn\":0,\"pcesvn\":6},\"tcbm\":\"0505020401800000000000000000000"
    "00600\",\"cert\":\"-----BEGIN%20CERTIFICATE-----%0AMIIEgDCCBCagAwIBAgI"
    "UNewReUR4oohkNEvf1SRWihVPzbwwCgYIKoZIzj0EAwIwcTEjMCEGA1UE%0AAwwaSW50ZW"
    "wgU0dYIFBDSyBQcm9jZXNzb3IgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9u%0AM"
    "RQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYTAlVTMB4XDTE"
    "5MTAy%0AMjIxMzEwOFoXDTI2MTAyMjIxMzEwOFowcDEiMCAGA1UEAwwZSW50ZWwgU0dYIF"
    "BDSyBDZXJ0aWZp%0AY2F0ZTEaMBgGA1UECgwRSW50ZWwgQ29ycG9yYXRpb24xFDASBgNVB"
    "AcMC1NhbnRhIENsYXJhMQsw%0ACQYDVQQIDAJDQTELMAkGA1UEBhMCVVMwWTATBgcqhkjO"
    "PQIBBggqhkjOPQMBBwNCAASTSfP%2FW5IX%0Ab6%2BcQuRdNxbtmKYQ6MuBFnJktku7xRY"
    "Drlc%2FSXfY5yIXSjyt%2BgaF65QN0SNgDKxYGuAAAtiiwjRp%0Ao4ICmzCCApcwHwYDVR"
    "0jBBgwFoAU0Oiq2nXX%2BS5JF5g8exRl0NXyWU0wXwYDVR0fBFgwVjBUoFKg%0AUIZOaHR"
    "0cHM6Ly9hcGkudHJ1c3RlZHNlcnZpY2VzLmludGVsLmNvbS9zZ3gvY2VydGlmaWNhdGlv%"
    "0Abi92MS9wY2tjcmw%2FY2E9cHJvY2Vzc29yMB0GA1UdDgQWBBQQwl04IEAaVlBA11EniD"
    "lItPZdnzAO%0ABgNVHQ8BAf8EBAMCBsAwDAYDVR0TAQH%2FBAIwADCCAdQGCSqGSIb4TQE"
    "NAQSCAcUwggHBMB4GCiqG%0ASIb4TQENAQEEEHuXvnfGLUJGxgPQ9PEbMbswggFkBgoqhk"
    "iG%2BE0BDQECMIIBVDAQBgsqhkiG%2BE0B%0ADQECAQIBBTAQBgsqhkiG%2BE0BDQECAgI"
    "BBTAQBgsqhkiG%2BE0BDQECAwIBAjAQBgsqhkiG%2BE0BDQEC%0ABAIBBDAQBgsqhkiG%2"
    "BE0BDQECBQIBATARBgsqhkiG%2BE0BDQECBgICAIAwEAYLKoZIhvhNAQ0BAgcC%0AAQAwE"
    "AYLKoZIhvhNAQ0BAggCAQAwEAYLKoZIhvhNAQ0BAgkCAQAwEAYLKoZIhvhNAQ0BAgoCAQA"
    "w%0AEAYLKoZIhvhNAQ0BAgsCAQAwEAYLKoZIhvhNAQ0BAgwCAQAwEAYLKoZIhvhNAQ0BAg"
    "0CAQAwEAYL%0AKoZIhvhNAQ0BAg4CAQAwEAYLKoZIhvhNAQ0BAg8CAQAwEAYLKoZIhvhNA"
    "Q0BAhACAQAwEAYLKoZI%0AhvhNAQ0BAhECAQYwHwYLKoZIhvhNAQ0BAhIEEAUFAgQBgAAA"
    "AAAAAAAAAAAwEAYKKoZIhvhNAQ0B%0AAwQCAAAwFAYKKoZIhvhNAQ0BBAQGAJBuoQAAMA8"
    "GCiqGSIb4TQENAQUKAQAwCgYIKoZIzj0EAwID%0ASAAwRQIhALF6%2Bt6WXR1GaZhJ2vwL"
    "OmfqCI3CBleC4L%2F3S3wXRs2AAiBopnudE6Pd%2B6WGtrLV4MNr%0ArLDVzsEBWVDrwS8"
    "Ay1dJHg%3D%3D%0A-----END%20CERTIFICATE-----\"},{\"tcb\":{\"sgxtcbcomp0"
    "1svn\":4,\"sgxtcbcomp02svn\":4,\"sgxtcbcomp03svn\":2,\"sgxtcbcomp04svn"
    "\":4,\"sgxtcbcomp05svn\":1,\"sgxtcbcomp06svn\":128,\"sgxtcbcomp07svn\""
    ":0,\"sgxtcbcomp08svn\":0,\"sgxtcbcomp09svn\":0,\"sgxtcbcomp10svn\":0,"
    "\"sgxtcbcomp11svn\":0,\"sgxtcbcomp12svn\":0,\"sgxtcbcomp13svn\":0,\"sg"
    "xtcbcomp14svn\":0,\"sgxtcbcomp15svn\":0,\"sgxtcbcomp16svn\":0,\"pcesvn"
    "\":5},\"tcbm\":\"040402040180000000000000000000000500\",\"cert\":\"---"
    "--BEGIN%20CERTIFICATE-----%0AMIIEgTCCBCegAwIBAgIVALVVpj4dmBpz7Mg%2FAib"
    "eo3c3VpjhMAoGCCqGSM49BAMCMHExIzAhBgNV%0ABAMMGkludGVsIFNHWCBQQ0sgUHJvY2"
    "Vzc29yIENBMRowGAYDVQQKDBFJbnRlbCBDb3Jwb3JhdGlv%0AbjEUMBIGA1UEBwwLU2Fud"
    "GEgQ2xhcmExCzAJBgNVBAgMAkNBMQswCQYDVQQGEwJVUzAeFw0xOTEw%0AMjIyMTMxMDha"
    "Fw0yNjEwMjIyMTMxMDhaMHAxIjAgBgNVBAMMGUludGVsIFNHWCBQQ0sgQ2VydGlm%0AaWN"
    "hdGUxGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyY"
    "TEL%0AMAkGA1UECAwCQ0ExCzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD"
    "QgAE3vNaKOZv%0At%2FEFNoIdruD3Bg6XnggsWHyE66dHh99ywN43NGnERFkVMswTQAO%2"
    "FTrRMHvAPGxbaB%2FPsaC0cluI%2F%0AFqOCApswggKXMB8GA1UdIwQYMBaAFNDoqtp11%"
    "2FkuSReYPHsUZdDV8llNMF8GA1UdHwRYMFYwVKBS%0AoFCGTmh0dHBzOi8vYXBpLnRydXN"
    "0ZWRzZXJ2aWNlcy5pbnRlbC5jb20vc2d4L2NlcnRpZmljYXRp%0Ab24vdjEvcGNrY3JsP2"
    "NhPXByb2Nlc3NvcjAdBgNVHQ4EFgQU0yM0DVMiOgj%2B%2B26xFX%2FzW4VxJGww%0ADgY"
    "DVR0PAQH%2FBAQDAgbAMAwGA1UdEwEB%2FwQCMAAwggHUBgkqhkiG%2BE0BDQEEggHFMII"
    "BwTAeBgoq%0AhkiG%2BE0BDQEBBBB7l753xi1CRsYD0PTxGzG7MIIBZAYKKoZIhvhNAQ0B"
    "AjCCAVQwEAYLKoZIhvhN%0AAQ0BAgECAQQwEAYLKoZIhvhNAQ0BAgICAQQwEAYLKoZIhvh"
    "NAQ0BAgMCAQIwEAYLKoZIhvhNAQ0B%0AAgQCAQQwEAYLKoZIhvhNAQ0BAgUCAQEwEQYLKo"
    "ZIhvhNAQ0BAgYCAgCAMBAGCyqGSIb4TQENAQIH%0AAgEAMBAGCyqGSIb4TQENAQIIAgEAM"
    "BAGCyqGSIb4TQENAQIJAgEAMBAGCyqGSIb4TQENAQIKAgEA%0AMBAGCyqGSIb4TQENAQIL"
    "AgEAMBAGCyqGSIb4TQENAQIMAgEAMBAGCyqGSIb4TQENAQINAgEAMBAG%0ACyqGSIb4TQE"
    "NAQIOAgEAMBAGCyqGSIb4TQENAQIPAgEAMBAGCyqGSIb4TQENAQIQAgEAMBAGCyqG%0ASI"
    "b4TQENAQIRAgEFMB8GCyqGSIb4TQENAQISBBAEBAIEAYAAAAAAAAAAAAAAMBAGCiqGSIb4"
    "TQEN%0AAQMEAgAAMBQGCiqGSIb4TQENAQQEBgCQbqEAADAPBgoqhkiG%2BE0BDQEFCgEAM"
    "AoGCCqGSM49BAMC%0AA0gAMEUCIQDYPkSjGa7kZN3bz58OMBN5ewRCL4BLDVDKuj50jVMY"
    "pgIgWeHIMK88v7EcsuTfWEQ8%0AvDQeOuBX%2BtaWZwILU2R57j0%3D%0A-----END%20C"
    "ERTIFICATE-----\"},{\"tcb\":{\"sgxtcbcomp01svn\":2,\"sgxtcbcomp02svn\""
    ":2,\"sgxtcbcomp03svn\":2,\"sgxtcbcomp04svn\":4,\"sgxtcbcomp05svn\":1,"
    "\"sgxtcbcomp06svn\":128,\"sgxtcbcomp07svn\":0,\"sgxtcbcomp08svn\":0,\""
    "sgxtcbcomp09svn\":0,\"sgxtcbcomp10svn\":0,\"sgxtcbcomp11svn\":0,\"sgxt"
    "cbcomp12svn\":0,\"sgxtcbcomp13svn\":0,\"sgxtcbcomp14svn\":0,\"sgxtcbco"
    "mp15svn\":0,\"sgxtcbcomp16svn\":0,\"pcesvn\":4},\"tcbm\":\"02020204018"
    "0000000000000000000000400\",\"cert\":\"-----BEGIN%20CERTIFICATE-----%0"
    "AMIIEgDCCBCagAwIBAgIUAiuOByY6QPUbf0qlobAVwg9i3wEwCgYIKoZIzj0EAwIwcTEjM"
    "CEGA1UE%0AAwwaSW50ZWwgU0dYIFBDSyBQcm9jZXNzb3IgQ0ExGjAYBgNVBAoMEUludGVs"
    "IENvcnBvcmF0aW9u%0AMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzA"
    "JBgNVBAYTAlVTMB4XDTE5MTAy%0AMjIxMzEwOFoXDTI2MTAyMjIxMzEwOFowcDEiMCAGA1"
    "UEAwwZSW50ZWwgU0dYIFBDSyBDZXJ0aWZp%0AY2F0ZTEaMBgGA1UECgwRSW50ZWwgQ29yc"
    "G9yYXRpb24xFDASBgNVBAcMC1NhbnRhIENsYXJhMQsw%0ACQYDVQQIDAJDQTELMAkGA1UE"
    "BhMCVVMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS6Tpvu875H%0A5R6Kmv%2FsCLlE9"
    "EyyoUY%2BlHRmExV0f%2F3cvQabbeKHwt24bR9B6YuJZy0hHWb%2BhzorEwOinG3MWKL6%"
    "0Ao4ICmzCCApcwHwYDVR0jBBgwFoAU0Oiq2nXX%2BS5JF5g8exRl0NXyWU0wXwYDVR0fBF"
    "gwVjBUoFKg%0AUIZOaHR0cHM6Ly9hcGkudHJ1c3RlZHNlcnZpY2VzLmludGVsLmNvbS9zZ"
    "3gvY2VydGlmaWNhdGlv%0Abi92MS9wY2tjcmw%2FY2E9cHJvY2Vzc29yMB0GA1UdDgQWBB"
    "S8KJG9eTLKdsFVVXhAGcg8F636OzAO%0ABgNVHQ8BAf8EBAMCBsAwDAYDVR0TAQH%2FBAI"
    "wADCCAdQGCSqGSIb4TQENAQSCAcUwggHBMB4GCiqG%0ASIb4TQENAQEEEHuXvnfGLUJGxg"
    "PQ9PEbMbswggFkBgoqhkiG%2BE0BDQECMIIBVDAQBgsqhkiG%2BE0B%0ADQECAQIBAjAQB"
    "gsqhkiG%2BE0BDQECAgIBAjAQBgsqhkiG%2BE0BDQECAwIBAjAQBgsqhkiG%2BE0BDQEC%"
    "0ABAIBBDAQBgsqhkiG%2BE0BDQECBQIBATARBgsqhkiG%2BE0BDQECBgICAIAwEAYLKoZI"
    "hvhNAQ0BAgcC%0AAQAwEAYLKoZIhvhNAQ0BAggCAQAwEAYLKoZIhvhNAQ0BAgkCAQAwEAY"
    "LKoZIhvhNAQ0BAgoCAQAw%0AEAYLKoZIhvhNAQ0BAgsCAQAwEAYLKoZIhvhNAQ0BAgwCAQ"
    "AwEAYLKoZIhvhNAQ0BAg0CAQAwEAYL%0AKoZIhvhNAQ0BAg4CAQAwEAYLKoZIhvhNAQ0BA"
    "g8CAQAwEAYLKoZIhvhNAQ0BAhACAQAwEAYLKoZI%0AhvhNAQ0BAhECAQQwHwYLKoZIhvhN"
    "AQ0BAhIEEAICAgQBgAAAAAAAAAAAAAAwEAYKKoZIhvhNAQ0B%0AAwQCAAAwFAYKKoZIhvh"
    "NAQ0BBAQGAJBuoQAAMA8GCiqGSIb4TQENAQUKAQAwCgYIKoZIzj0EAwID%0ASAAwRQIhAM"
    "orRnjG%2FweLSnHmioqEG5aKucdumFbAimHdDps7DqCcAiBWcZwnVuXgHj%2BzjXkeJK3O"
    "%0A8Ln4yDdayhDfk%2BYjHfPIEw%3D%3D%0A-----END%20CERTIFICATE-----\"}]";

constexpr char kExpectedPckCertsTextProto[] = R"proto(
  certs {
    tcb_level {
      components: "\x06\x06\x02\x04\x01\200\x01\x00\x00\x00\x00\x00\x00\x00"
                  "\x00\x00"
      pce_svn { value: 7 }
    }
    tcbm {
      cpu_svn {
        value: "\x06\x06\x02\x04\x01\200\x01\x00\x00\x00\x00\x00\x00\x00\x00"
               "\x00"
      }
      pce_svn { value: 7 }
    }
    cert {
      format: X509_PEM
      data: "-----BEGIN CERTIFICATE-----\n"
            "MIIEgDCCBCagAwIBAgIUVEUOECXhHHTveY0hS2kbngAuXowwCgYIKoZIzj0EAw"
            "Iw\ncTEjMCEGA1UEAwwaSW50ZWwgU0dYIFBDSyBQcm9jZXNzb3IgQ0ExGjAYBg"
            "NVBAoM\nEUludGVsIENvcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYT"
            "ELMAkGA1UE\nCAwCQ0ExCzAJBgNVBAYTAlVTMB4XDTE5MTAyMjIxMzEwOFoXDT"
            "I2MTAyMjIxMzEw\nOFowcDEiMCAGA1UEAwwZSW50ZWwgU0dYIFBDSyBDZXJ0aW"
            "ZpY2F0ZTEaMBgGA1UE\nCgwRSW50ZWwgQ29ycG9yYXRpb24xFDASBgNVBAcMC1"
            "NhbnRhIENsYXJhMQswCQYD\nVQQIDAJDQTELMAkGA1UEBhMCVVMwWTATBgcqhk"
            "jOPQIBBggqhkjOPQMBBwNCAAQ0\n6CXTMK6h/BR2sRaSssWO8MqEdbccOGWzyL"
            "jwiRx1zfyrreCqgAN2LOkGAKFlomqu\nV/CZ369yTSm7li4APNfCo4ICmzCCAp"
            "cwHwYDVR0jBBgwFoAU0Oiq2nXX+S5JF5g8\nexRl0NXyWU0wXwYDVR0fBFgwVj"
            "BUoFKgUIZOaHR0cHM6Ly9hcGkudHJ1c3RlZHNl\ncnZpY2VzLmludGVsLmNvbS"
            "9zZ3gvY2VydGlmaWNhdGlvbi92MS9wY2tjcmw/Y2E9\ncHJvY2Vzc29yMB0GA1"
            "UdDgQWBBRBM37ZBg6NUUSIMXn4sRcRjFN/PDAOBgNVHQ8B\nAf8EBAMCBsAwDA"
            "YDVR0TAQH/BAIwADCCAdQGCSqGSIb4TQENAQSCAcUwggHBMB4G\nCiqGSIb4TQ"
            "ENAQEEEHuXvnfGLUJGxgPQ9PEbMbswggFkBgoqhkiG+E0BDQECMIIB\nVDAQBg"
            "sqhkiG+E0BDQECAQIBBjAQBgsqhkiG+E0BDQECAgIBBjAQBgsqhkiG+E0B\nDQ"
            "ECAwIBAjAQBgsqhkiG+E0BDQECBAIBBDAQBgsqhkiG+E0BDQECBQIBATARBgsq"
            "\nhkiG+E0BDQECBgICAIAwEAYLKoZIhvhNAQ0BAgcCAQEwEAYLKoZIhvhNAQ0B"
            "AggC\nAQAwEAYLKoZIhvhNAQ0BAgkCAQAwEAYLKoZIhvhNAQ0BAgoCAQAwEAYL"
            "KoZIhvhN\nAQ0BAgsCAQAwEAYLKoZIhvhNAQ0BAgwCAQAwEAYLKoZIhvhNAQ0B"
            "Ag0CAQAwEAYL\nKoZIhvhNAQ0BAg4CAQAwEAYLKoZIhvhNAQ0BAg8CAQAwEAYL"
            "KoZIhvhNAQ0BAhAC\nAQAwEAYLKoZIhvhNAQ0BAhECAQcwHwYLKoZIhvhNAQ0B"
            "AhIEEAYGAgQBgAEAAAAA\nAAAAAAAwEAYKKoZIhvhNAQ0BAwQCAAAwFAYKKoZI"
            "hvhNAQ0BBAQGAJBuoQAAMA8G\nCiqGSIb4TQENAQUKAQAwCgYIKoZIzj0EAwID"
            "SAAwRQIgOeU15KgeYYEBPLDXF8du\n1g45KOz3Es7fBm9pJ9aXeSACIQC2pdR1"
            "J+UAhoMmj2MKIaQiBF5z3M27EElsAKtZ\nUXM37Q==\n"
            "-----END CERTIFICATE-----\n"
    }
  }
  certs {
    tcb_level {
      components: "\x06\x06\x02\x04\x01\200\x00\x00\x00\x00\x00\x00\x00\x00"
                  "\x00\x00"
      pce_svn { value: 7 }
    }
    tcbm {
      cpu_svn {
        value: "\x06\x06\x02\x04\x01\200\x00\x00\x00\x00\x00\x00\x00\x00\x00"
               "\x00"
      }
      pce_svn { value: 7 }
    }
    cert {
      format: X509_PEM
      data: "-----BEGIN CERTIFICATE-----\n"
            "MIIEgDCCBCegAwIBAgIVAKOnJWy71ZwjgzZ+dQ4kQtwDZ85nMAoGCCqGSM49BA"
            "MC\nMHExIzAhBgNVBAMMGkludGVsIFNHWCBQQ0sgUHJvY2Vzc29yIENBMRowGA"
            "YDVQQK\nDBFJbnRlbCBDb3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcm"
            "ExCzAJBgNV\nBAgMAkNBMQswCQYDVQQGEwJVUzAeFw0xOTEwMjIyMTMxMDhaFw"
            "0yNjEwMjIyMTMx\nMDhaMHAxIjAgBgNVBAMMGUludGVsIFNHWCBQQ0sgQ2VydG"
            "lmaWNhdGUxGjAYBgNV\nBAoMEUludGVsIENvcnBvcmF0aW9uMRQwEgYDVQQHDA"
            "tTYW50YSBDbGFyYTELMAkG\nA1UECAwCQ0ExCzAJBgNVBAYTAlVTMFkwEwYHKo"
            "ZIzj0CAQYIKoZIzj0DAQcDQgAE\nKq9bOB5+l5+D8Jy6m4N3fEfG143k4fBEIU"
            "HTI11TwGA6nXYPy3otv6ggl6d9mUsD\nt+t1tOjvgNCaVudrhUbPq6OCApswgg"
            "KXMB8GA1UdIwQYMBaAFNDoqtp11/kuSReY\nPHsUZdDV8llNMF8GA1UdHwRYMF"
            "YwVKBSoFCGTmh0dHBzOi8vYXBpLnRydXN0ZWRz\nZXJ2aWNlcy5pbnRlbC5jb2"
            "0vc2d4L2NlcnRpZmljYXRpb24vdjEvcGNrY3JsP2Nh\nPXByb2Nlc3NvcjAdBg"
            "NVHQ4EFgQU+fN53shxLxPvhXblSobC21HrvmIwDgYDVR0P\nAQH/BAQDAgbAMA"
            "wGA1UdEwEB/wQCMAAwggHUBgkqhkiG+E0BDQEEggHFMIIBwTAe\nBgoqhkiG+E"
            "0BDQEBBBB7l753xi1CRsYD0PTxGzG7MIIBZAYKKoZIhvhNAQ0BAjCC\nAVQwEA"
            "YLKoZIhvhNAQ0BAgECAQYwEAYLKoZIhvhNAQ0BAgICAQYwEAYLKoZIhvhN\nAQ"
            "0BAgMCAQIwEAYLKoZIhvhNAQ0BAgQCAQQwEAYLKoZIhvhNAQ0BAgUCAQEwEQYL"
            "\nKoZIhvhNAQ0BAgYCAgCAMBAGCyqGSIb4TQENAQIHAgEAMBAGCyqGSIb4TQEN"
            "AQII\nAgEAMBAGCyqGSIb4TQENAQIJAgEAMBAGCyqGSIb4TQENAQIKAgEAMBAG"
            "CyqGSIb4\nTQENAQILAgEAMBAGCyqGSIb4TQENAQIMAgEAMBAGCyqGSIb4TQEN"
            "AQINAgEAMBAG\nCyqGSIb4TQENAQIOAgEAMBAGCyqGSIb4TQENAQIPAgEAMBAG"
            "CyqGSIb4TQENAQIQ\nAgEAMBAGCyqGSIb4TQENAQIRAgEHMB8GCyqGSIb4TQEN"
            "AQISBBAGBgIEAYAAAAAA\nAAAAAAAAMBAGCiqGSIb4TQENAQMEAgAAMBQGCiqG"
            "SIb4TQENAQQEBgCQbqEAADAP\nBgoqhkiG+E0BDQEFCgEAMAoGCCqGSM49BAMC"
            "A0cAMEQCIAaNDss+0OVptuknGsuD\n1+NrEDUtZxYjt+x4XKZ2yFPRAiBxS/5h"
            "ETSU3v9EW45YoPipcgnNaIK/Yu4wjpo4\nRtWffQ==\n"
            "-----END CERTIFICATE-----\n"
    }
  }
  certs {
    tcb_level {
      components: "\x05\x05\x02\x04\x01\200\x01\x00\x00\x00\x00\x00\x00\x00"
                  "\x00\x00"
      pce_svn { value: 7 }
    }
    tcbm {
      cpu_svn {
        value: "\x05\x05\x02\x04\x01\200\x01\x00\x00\x00\x00\x00\x00\x00\x00"
               "\x00"
      }
      pce_svn { value: 7 }
    }
    cert {
      format: X509_PEM
      data: "-----BEGIN CERTIFICATE-----\n"
            "MIIEgTCCBCegAwIBAgIVAIudIsG0zFrcVwWCJpnF/oJ/Av3UMAoGCCqGSM49BA"
            "MC\nMHExIzAhBgNVBAMMGkludGVsIFNHWCBQQ0sgUHJvY2Vzc29yIENBMRowGA"
            "YDVQQK\nDBFJbnRlbCBDb3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcm"
            "ExCzAJBgNV\nBAgMAkNBMQswCQYDVQQGEwJVUzAeFw0xOTEwMjIyMTMxMDhaFw"
            "0yNjEwMjIyMTMx\nMDhaMHAxIjAgBgNVBAMMGUludGVsIFNHWCBQQ0sgQ2VydG"
            "lmaWNhdGUxGjAYBgNV\nBAoMEUludGVsIENvcnBvcmF0aW9uMRQwEgYDVQQHDA"
            "tTYW50YSBDbGFyYTELMAkG\nA1UECAwCQ0ExCzAJBgNVBAYTAlVTMFkwEwYHKo"
            "ZIzj0CAQYIKoZIzj0DAQcDQgAE\nvZb0pkVJLhna4zUXQy1jp/SMIkIE2ufJjS"
            "VCNU4g5ymzO0RKS++XpSwDOJHNxCpI\nyCkpWeYNbj9m6HDd0zWsHaOCApswgg"
            "KXMB8GA1UdIwQYMBaAFNDoqtp11/kuSReY\nPHsUZdDV8llNMF8GA1UdHwRYMF"
            "YwVKBSoFCGTmh0dHBzOi8vYXBpLnRydXN0ZWRz\nZXJ2aWNlcy5pbnRlbC5jb2"
            "0vc2d4L2NlcnRpZmljYXRpb24vdjEvcGNrY3JsP2Nh\nPXByb2Nlc3NvcjAdBg"
            "NVHQ4EFgQUiyOA3JWI9LZWgvm/ZZBMdTCRMt0wDgYDVR0P\nAQH/BAQDAgbAMA"
            "wGA1UdEwEB/wQCMAAwggHUBgkqhkiG+E0BDQEEggHFMIIBwTAe\nBgoqhkiG+E"
            "0BDQEBBBB7l753xi1CRsYD0PTxGzG7MIIBZAYKKoZIhvhNAQ0BAjCC\nAVQwEA"
            "YLKoZIhvhNAQ0BAgECAQUwEAYLKoZIhvhNAQ0BAgICAQUwEAYLKoZIhvhN\nAQ"
            "0BAgMCAQIwEAYLKoZIhvhNAQ0BAgQCAQQwEAYLKoZIhvhNAQ0BAgUCAQEwEQYL"
            "\nKoZIhvhNAQ0BAgYCAgCAMBAGCyqGSIb4TQENAQIHAgEBMBAGCyqGSIb4TQEN"
            "AQII\nAgEAMBAGCyqGSIb4TQENAQIJAgEAMBAGCyqGSIb4TQENAQIKAgEAMBAG"
            "CyqGSIb4\nTQENAQILAgEAMBAGCyqGSIb4TQENAQIMAgEAMBAGCyqGSIb4TQEN"
            "AQINAgEAMBAG\nCyqGSIb4TQENAQIOAgEAMBAGCyqGSIb4TQENAQIPAgEAMBAG"
            "CyqGSIb4TQENAQIQ\nAgEAMBAGCyqGSIb4TQENAQIRAgEHMB8GCyqGSIb4TQEN"
            "AQISBBAFBQIEAYABAAAA\nAAAAAAAAMBAGCiqGSIb4TQENAQMEAgAAMBQGCiqG"
            "SIb4TQENAQQEBgCQbqEAADAP\nBgoqhkiG+E0BDQEFCgEAMAoGCCqGSM49BAMC"
            "A0gAMEUCIQCQbgdf4D+VOGBu8DxS\nLEEO/vwJxWeNR+8VyzZd7ETb2QIgSpma"
            "Pfkq4/i4urdMi2j/ehL58ueUYn9RZCPP\njR5rUzs=\n"
            "-----END CERTIFICATE-----\n"
    }
  }
  certs {
    tcb_level {
      components: "\x05\x05\x02\x04\x01\200\x01\x00\x00\x00\x00\x00\x00\x00"
                  "\x00\x00"
      pce_svn { value: 6 }
    }
    tcbm {
      cpu_svn {
        value: "\x05\x05\x02\x04\x01\200\x01\x00\x00\x00\x00\x00\x00\x00\x00"
               "\x00"
      }
      pce_svn { value: 6 }
    }
    cert {
      format: X509_PEM
      data: "-----BEGIN CERTIFICATE-----\n"
            "MIIEgTCCBCegAwIBAgIVAMl0gn/yTGg0szm6AZSJsfQ4nId+MAoGCCqGSM49BA"
            "MC\nMHExIzAhBgNVBAMMGkludGVsIFNHWCBQQ0sgUHJvY2Vzc29yIENBMRowGA"
            "YDVQQK\nDBFJbnRlbCBDb3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcm"
            "ExCzAJBgNV\nBAgMAkNBMQswCQYDVQQGEwJVUzAeFw0xOTEwMjIyMTMxMDhaFw"
            "0yNjEwMjIyMTMx\nMDhaMHAxIjAgBgNVBAMMGUludGVsIFNHWCBQQ0sgQ2VydG"
            "lmaWNhdGUxGjAYBgNV\nBAoMEUludGVsIENvcnBvcmF0aW9uMRQwEgYDVQQHDA"
            "tTYW50YSBDbGFyYTELMAkG\nA1UECAwCQ0ExCzAJBgNVBAYTAlVTMFkwEwYHKo"
            "ZIzj0CAQYIKoZIzj0DAQcDQgAE\ne9F11NtjnX5a7Nfl/wjWISOfAvZR5xQfzU"
            "jwHyMf+Zarzvd8B5UIPxVzGrP8YW1p\n3XYoIm6z/XktniW4Evkgi6OCApswgg"
            "KXMB8GA1UdIwQYMBaAFNDoqtp11/kuSReY\nPHsUZdDV8llNMF8GA1UdHwRYMF"
            "YwVKBSoFCGTmh0dHBzOi8vYXBpLnRydXN0ZWRz\nZXJ2aWNlcy5pbnRlbC5jb2"
            "0vc2d4L2NlcnRpZmljYXRpb24vdjEvcGNrY3JsP2Nh\nPXByb2Nlc3NvcjAdBg"
            "NVHQ4EFgQUthXfuhFFvtMnwgmBefqSJ84hv1EwDgYDVR0P\nAQH/BAQDAgbAMA"
            "wGA1UdEwEB/wQCMAAwggHUBgkqhkiG+E0BDQEEggHFMIIBwTAe\nBgoqhkiG+E"
            "0BDQEBBBB7l753xi1CRsYD0PTxGzG7MIIBZAYKKoZIhvhNAQ0BAjCC\nAVQwEA"
            "YLKoZIhvhNAQ0BAgECAQUwEAYLKoZIhvhNAQ0BAgICAQUwEAYLKoZIhvhN\nAQ"
            "0BAgMCAQIwEAYLKoZIhvhNAQ0BAgQCAQQwEAYLKoZIhvhNAQ0BAgUCAQEwEQYL"
            "\nKoZIhvhNAQ0BAgYCAgCAMBAGCyqGSIb4TQENAQIHAgEBMBAGCyqGSIb4TQEN"
            "AQII\nAgEAMBAGCyqGSIb4TQENAQIJAgEAMBAGCyqGSIb4TQENAQIKAgEAMBAG"
            "CyqGSIb4\nTQENAQILAgEAMBAGCyqGSIb4TQENAQIMAgEAMBAGCyqGSIb4TQEN"
            "AQINAgEAMBAG\nCyqGSIb4TQENAQIOAgEAMBAGCyqGSIb4TQENAQIPAgEAMBAG"
            "CyqGSIb4TQENAQIQ\nAgEAMBAGCyqGSIb4TQENAQIRAgEGMB8GCyqGSIb4TQEN"
            "AQISBBAFBQIEAYABAAAA\nAAAAAAAAMBAGCiqGSIb4TQENAQMEAgAAMBQGCiqG"
            "SIb4TQENAQQEBgCQbqEAADAP\nBgoqhkiG+E0BDQEFCgEAMAoGCCqGSM49BAMC"
            "A0gAMEUCIC9PuFFxvrutNKnZpVKG\ndDKqkgbff5m39IZDBsPBehgtAiEA+Uao"
            "azq4L+ogsvEdvr3ejnmLyX7toAc1HhQK\npcMCbI4=\n"
            "-----END CERTIFICATE-----\n"
    }
  }
  certs {
    tcb_level {
      components: "\x05\x05\x02\x04\x01\200\x00\x00\x00\x00\x00\x00\x00\x00"
                  "\x00\x00"
      pce_svn { value: 7 }
    }
    tcbm {
      cpu_svn {
        value: "\x05\x05\x02\x04\x01\200\x00\x00\x00\x00\x00\x00\x00\x00\x00"
               "\x00"
      }
      pce_svn { value: 7 }
    }
    cert {
      format: X509_PEM
      data: "-----BEGIN CERTIFICATE-----\n"
            "MIIEgTCCBCegAwIBAgIVAJ1mxDIzAXa+ixcUKKaUmyYxoyJlMAoGCCqGSM49BA"
            "MC\nMHExIzAhBgNVBAMMGkludGVsIFNHWCBQQ0sgUHJvY2Vzc29yIENBMRowGA"
            "YDVQQK\nDBFJbnRlbCBDb3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcm"
            "ExCzAJBgNV\nBAgMAkNBMQswCQYDVQQGEwJVUzAeFw0xOTEwMjIyMTMxMDhaFw"
            "0yNjEwMjIyMTMx\nMDhaMHAxIjAgBgNVBAMMGUludGVsIFNHWCBQQ0sgQ2VydG"
            "lmaWNhdGUxGjAYBgNV\nBAoMEUludGVsIENvcnBvcmF0aW9uMRQwEgYDVQQHDA"
            "tTYW50YSBDbGFyYTELMAkG\nA1UECAwCQ0ExCzAJBgNVBAYTAlVTMFkwEwYHKo"
            "ZIzj0CAQYIKoZIzj0DAQcDQgAE\nF7aCJQzGR7R/oeDkuyiFhknVXV4mKl72QU"
            "CD+02CS+a0AUnJtKz37EmAyd5afJ38\ndFswPFL1upLY7yrEco993qOCApswgg"
            "KXMB8GA1UdIwQYMBaAFNDoqtp11/kuSReY\nPHsUZdDV8llNMF8GA1UdHwRYMF"
            "YwVKBSoFCGTmh0dHBzOi8vYXBpLnRydXN0ZWRz\nZXJ2aWNlcy5pbnRlbC5jb2"
            "0vc2d4L2NlcnRpZmljYXRpb24vdjEvcGNrY3JsP2Nh\nPXByb2Nlc3NvcjAdBg"
            "NVHQ4EFgQUFBTkM8dooH85tY3YGlV1MtZs1zEwDgYDVR0P\nAQH/BAQDAgbAMA"
            "wGA1UdEwEB/wQCMAAwggHUBgkqhkiG+E0BDQEEggHFMIIBwTAe\nBgoqhkiG+E"
            "0BDQEBBBB7l753xi1CRsYD0PTxGzG7MIIBZAYKKoZIhvhNAQ0BAjCC\nAVQwEA"
            "YLKoZIhvhNAQ0BAgECAQUwEAYLKoZIhvhNAQ0BAgICAQUwEAYLKoZIhvhN\nAQ"
            "0BAgMCAQIwEAYLKoZIhvhNAQ0BAgQCAQQwEAYLKoZIhvhNAQ0BAgUCAQEwEQYL"
            "\nKoZIhvhNAQ0BAgYCAgCAMBAGCyqGSIb4TQENAQIHAgEAMBAGCyqGSIb4TQEN"
            "AQII\nAgEAMBAGCyqGSIb4TQENAQIJAgEAMBAGCyqGSIb4TQENAQIKAgEAMBAG"
            "CyqGSIb4\nTQENAQILAgEAMBAGCyqGSIb4TQENAQIMAgEAMBAGCyqGSIb4TQEN"
            "AQINAgEAMBAG\nCyqGSIb4TQENAQIOAgEAMBAGCyqGSIb4TQENAQIPAgEAMBAG"
            "CyqGSIb4TQENAQIQ\nAgEAMBAGCyqGSIb4TQENAQIRAgEHMB8GCyqGSIb4TQEN"
            "AQISBBAFBQIEAYAAAAAA\nAAAAAAAAMBAGCiqGSIb4TQENAQMEAgAAMBQGCiqG"
            "SIb4TQENAQQEBgCQbqEAADAP\nBgoqhkiG+E0BDQEFCgEAMAoGCCqGSM49BAMC"
            "A0gAMEUCIQCp7yWWNBSgS5F3I2Ts\nTQzs4iKLMTbCyeZDkkodvy3a7QIgCZDe"
            "7QelYEq09/dY4m+bgatpb76k57o+enAa\nzk0u6Mk=\n"
            "-----END CERTIFICATE-----\n"
    }
  }
  certs {
    tcb_level {
      components: "\x05\x05\x02\x04\x01\200\x00\x00\x00\x00\x00\x00\x00\x00"
                  "\x00\x00"
      pce_svn { value: 6 }
    }
    tcbm {
      cpu_svn {
        value: "\x05\x05\x02\x04\x01\200\x00\x00\x00\x00\x00\x00\x00\x00\x00"
               "\x00"
      }
      pce_svn { value: 6 }
    }
    cert {
      format: X509_PEM
      data: "-----BEGIN CERTIFICATE-----\n"
            "MIIEgDCCBCagAwIBAgIUNewReUR4oohkNEvf1SRWihVPzbwwCgYIKoZIzj0EAw"
            "Iw\ncTEjMCEGA1UEAwwaSW50ZWwgU0dYIFBDSyBQcm9jZXNzb3IgQ0ExGjAYBg"
            "NVBAoM\nEUludGVsIENvcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYT"
            "ELMAkGA1UE\nCAwCQ0ExCzAJBgNVBAYTAlVTMB4XDTE5MTAyMjIxMzEwOFoXDT"
            "I2MTAyMjIxMzEw\nOFowcDEiMCAGA1UEAwwZSW50ZWwgU0dYIFBDSyBDZXJ0aW"
            "ZpY2F0ZTEaMBgGA1UE\nCgwRSW50ZWwgQ29ycG9yYXRpb24xFDASBgNVBAcMC1"
            "NhbnRhIENsYXJhMQswCQYD\nVQQIDAJDQTELMAkGA1UEBhMCVVMwWTATBgcqhk"
            "jOPQIBBggqhkjOPQMBBwNCAAST\nSfP/W5IXb6+cQuRdNxbtmKYQ6MuBFnJktk"
            "u7xRYDrlc/SXfY5yIXSjyt+gaF65QN\n0SNgDKxYGuAAAtiiwjRpo4ICmzCCAp"
            "cwHwYDVR0jBBgwFoAU0Oiq2nXX+S5JF5g8\nexRl0NXyWU0wXwYDVR0fBFgwVj"
            "BUoFKgUIZOaHR0cHM6Ly9hcGkudHJ1c3RlZHNl\ncnZpY2VzLmludGVsLmNvbS"
            "9zZ3gvY2VydGlmaWNhdGlvbi92MS9wY2tjcmw/Y2E9\ncHJvY2Vzc29yMB0GA1"
            "UdDgQWBBQQwl04IEAaVlBA11EniDlItPZdnzAOBgNVHQ8B\nAf8EBAMCBsAwDA"
            "YDVR0TAQH/BAIwADCCAdQGCSqGSIb4TQENAQSCAcUwggHBMB4G\nCiqGSIb4TQ"
            "ENAQEEEHuXvnfGLUJGxgPQ9PEbMbswggFkBgoqhkiG+E0BDQECMIIB\nVDAQBg"
            "sqhkiG+E0BDQECAQIBBTAQBgsqhkiG+E0BDQECAgIBBTAQBgsqhkiG+E0B\nDQ"
            "ECAwIBAjAQBgsqhkiG+E0BDQECBAIBBDAQBgsqhkiG+E0BDQECBQIBATARBgsq"
            "\nhkiG+E0BDQECBgICAIAwEAYLKoZIhvhNAQ0BAgcCAQAwEAYLKoZIhvhNAQ0B"
            "AggC\nAQAwEAYLKoZIhvhNAQ0BAgkCAQAwEAYLKoZIhvhNAQ0BAgoCAQAwEAYL"
            "KoZIhvhN\nAQ0BAgsCAQAwEAYLKoZIhvhNAQ0BAgwCAQAwEAYLKoZIhvhNAQ0B"
            "Ag0CAQAwEAYL\nKoZIhvhNAQ0BAg4CAQAwEAYLKoZIhvhNAQ0BAg8CAQAwEAYL"
            "KoZIhvhNAQ0BAhAC\nAQAwEAYLKoZIhvhNAQ0BAhECAQYwHwYLKoZIhvhNAQ0B"
            "AhIEEAUFAgQBgAAAAAAA\nAAAAAAAwEAYKKoZIhvhNAQ0BAwQCAAAwFAYKKoZI"
            "hvhNAQ0BBAQGAJBuoQAAMA8G\nCiqGSIb4TQENAQUKAQAwCgYIKoZIzj0EAwID"
            "SAAwRQIhALF6+t6WXR1GaZhJ2vwL\nOmfqCI3CBleC4L/3S3wXRs2AAiBopnud"
            "E6Pd+6WGtrLV4MNrrLDVzsEBWVDrwS8A\ny1dJHg==\n"
            "-----END CERTIFICATE-----\n"
    }
  }
  certs {
    tcb_level {
      components: "\x04\x04\x02\x04\x01\200\x00\x00\x00\x00\x00\x00\x00\x00"
                  "\x00\x00"
      pce_svn { value: 5 }
    }
    tcbm {
      cpu_svn {
        value: "\x04\x04\x02\x04\x01\200\x00\x00\x00\x00\x00\x00\x00\x00\x00"
               "\x00"
      }
      pce_svn { value: 5 }
    }
    cert {
      format: X509_PEM
      data: "-----BEGIN CERTIFICATE-----\n"
            "MIIEgTCCBCegAwIBAgIVALVVpj4dmBpz7Mg/Aibeo3c3VpjhMAoGCCqGSM49BA"
            "MC\nMHExIzAhBgNVBAMMGkludGVsIFNHWCBQQ0sgUHJvY2Vzc29yIENBMRowGA"
            "YDVQQK\nDBFJbnRlbCBDb3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcm"
            "ExCzAJBgNV\nBAgMAkNBMQswCQYDVQQGEwJVUzAeFw0xOTEwMjIyMTMxMDhaFw"
            "0yNjEwMjIyMTMx\nMDhaMHAxIjAgBgNVBAMMGUludGVsIFNHWCBQQ0sgQ2VydG"
            "lmaWNhdGUxGjAYBgNV\nBAoMEUludGVsIENvcnBvcmF0aW9uMRQwEgYDVQQHDA"
            "tTYW50YSBDbGFyYTELMAkG\nA1UECAwCQ0ExCzAJBgNVBAYTAlVTMFkwEwYHKo"
            "ZIzj0CAQYIKoZIzj0DAQcDQgAE\n3vNaKOZvt/EFNoIdruD3Bg6XnggsWHyE66"
            "dHh99ywN43NGnERFkVMswTQAO/TrRM\nHvAPGxbaB/PsaC0cluI/FqOCApswgg"
            "KXMB8GA1UdIwQYMBaAFNDoqtp11/kuSReY\nPHsUZdDV8llNMF8GA1UdHwRYMF"
            "YwVKBSoFCGTmh0dHBzOi8vYXBpLnRydXN0ZWRz\nZXJ2aWNlcy5pbnRlbC5jb2"
            "0vc2d4L2NlcnRpZmljYXRpb24vdjEvcGNrY3JsP2Nh\nPXByb2Nlc3NvcjAdBg"
            "NVHQ4EFgQU0yM0DVMiOgj++26xFX/zW4VxJGwwDgYDVR0P\nAQH/BAQDAgbAMA"
            "wGA1UdEwEB/wQCMAAwggHUBgkqhkiG+E0BDQEEggHFMIIBwTAe\nBgoqhkiG+E"
            "0BDQEBBBB7l753xi1CRsYD0PTxGzG7MIIBZAYKKoZIhvhNAQ0BAjCC\nAVQwEA"
            "YLKoZIhvhNAQ0BAgECAQQwEAYLKoZIhvhNAQ0BAgICAQQwEAYLKoZIhvhN\nAQ"
            "0BAgMCAQIwEAYLKoZIhvhNAQ0BAgQCAQQwEAYLKoZIhvhNAQ0BAgUCAQEwEQYL"
            "\nKoZIhvhNAQ0BAgYCAgCAMBAGCyqGSIb4TQENAQIHAgEAMBAGCyqGSIb4TQEN"
            "AQII\nAgEAMBAGCyqGSIb4TQENAQIJAgEAMBAGCyqGSIb4TQENAQIKAgEAMBAG"
            "CyqGSIb4\nTQENAQILAgEAMBAGCyqGSIb4TQENAQIMAgEAMBAGCyqGSIb4TQEN"
            "AQINAgEAMBAG\nCyqGSIb4TQENAQIOAgEAMBAGCyqGSIb4TQENAQIPAgEAMBAG"
            "CyqGSIb4TQENAQIQ\nAgEAMBAGCyqGSIb4TQENAQIRAgEFMB8GCyqGSIb4TQEN"
            "AQISBBAEBAIEAYAAAAAA\nAAAAAAAAMBAGCiqGSIb4TQENAQMEAgAAMBQGCiqG"
            "SIb4TQENAQQEBgCQbqEAADAP\nBgoqhkiG+E0BDQEFCgEAMAoGCCqGSM49BAMC"
            "A0gAMEUCIQDYPkSjGa7kZN3bz58O\nMBN5ewRCL4BLDVDKuj50jVMYpgIgWeHI"
            "MK88v7EcsuTfWEQ8vDQeOuBX+taWZwIL\nU2R57j0=\n"
            "-----END CERTIFICATE-----\n"
    }
  }
  certs {
    tcb_level {
      components: "\x02\x02\x02\x04\x01\200\x00\x00\x00\x00\x00\x00\x00\x00"
                  "\x00\x00"
      pce_svn { value: 4 }
    }
    tcbm {
      cpu_svn {
        value: "\x02\x02\x02\x04\x01\200\x00\x00\x00\x00\x00\x00\x00\x00\x00"
               "\x00"
      }
      pce_svn { value: 4 }
    }
    cert {
      format: X509_PEM
      data: "-----BEGIN CERTIFICATE-----\n"
            "MIIEgDCCBCagAwIBAgIUAiuOByY6QPUbf0qlobAVwg9i3wEwCgYIKoZIzj0EAw"
            "Iw\ncTEjMCEGA1UEAwwaSW50ZWwgU0dYIFBDSyBQcm9jZXNzb3IgQ0ExGjAYBg"
            "NVBAoM\nEUludGVsIENvcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYT"
            "ELMAkGA1UE\nCAwCQ0ExCzAJBgNVBAYTAlVTMB4XDTE5MTAyMjIxMzEwOFoXDT"
            "I2MTAyMjIxMzEw\nOFowcDEiMCAGA1UEAwwZSW50ZWwgU0dYIFBDSyBDZXJ0aW"
            "ZpY2F0ZTEaMBgGA1UE\nCgwRSW50ZWwgQ29ycG9yYXRpb24xFDASBgNVBAcMC1"
            "NhbnRhIENsYXJhMQswCQYD\nVQQIDAJDQTELMAkGA1UEBhMCVVMwWTATBgcqhk"
            "jOPQIBBggqhkjOPQMBBwNCAAS6\nTpvu875H5R6Kmv/sCLlE9EyyoUY+lHRmEx"
            "V0f/3cvQabbeKHwt24bR9B6YuJZy0h\nHWb+hzorEwOinG3MWKL6o4ICmzCCAp"
            "cwHwYDVR0jBBgwFoAU0Oiq2nXX+S5JF5g8\nexRl0NXyWU0wXwYDVR0fBFgwVj"
            "BUoFKgUIZOaHR0cHM6Ly9hcGkudHJ1c3RlZHNl\ncnZpY2VzLmludGVsLmNvbS"
            "9zZ3gvY2VydGlmaWNhdGlvbi92MS9wY2tjcmw/Y2E9\ncHJvY2Vzc29yMB0GA1"
            "UdDgQWBBS8KJG9eTLKdsFVVXhAGcg8F636OzAOBgNVHQ8B\nAf8EBAMCBsAwDA"
            "YDVR0TAQH/BAIwADCCAdQGCSqGSIb4TQENAQSCAcUwggHBMB4G\nCiqGSIb4TQ"
            "ENAQEEEHuXvnfGLUJGxgPQ9PEbMbswggFkBgoqhkiG+E0BDQECMIIB\nVDAQBg"
            "sqhkiG+E0BDQECAQIBAjAQBgsqhkiG+E0BDQECAgIBAjAQBgsqhkiG+E0B\nDQ"
            "ECAwIBAjAQBgsqhkiG+E0BDQECBAIBBDAQBgsqhkiG+E0BDQECBQIBATARBgsq"
            "\nhkiG+E0BDQECBgICAIAwEAYLKoZIhvhNAQ0BAgcCAQAwEAYLKoZIhvhNAQ0B"
            "AggC\nAQAwEAYLKoZIhvhNAQ0BAgkCAQAwEAYLKoZIhvhNAQ0BAgoCAQAwEAYL"
            "KoZIhvhN\nAQ0BAgsCAQAwEAYLKoZIhvhNAQ0BAgwCAQAwEAYLKoZIhvhNAQ0B"
            "Ag0CAQAwEAYL\nKoZIhvhNAQ0BAg4CAQAwEAYLKoZIhvhNAQ0BAg8CAQAwEAYL"
            "KoZIhvhNAQ0BAhAC\nAQAwEAYLKoZIhvhNAQ0BAhECAQQwHwYLKoZIhvhNAQ0B"
            "AhIEEAICAgQBgAAAAAAA\nAAAAAAAwEAYKKoZIhvhNAQ0BAwQCAAAwFAYKKoZI"
            "hvhNAQ0BBAQGAJBuoQAAMA8G\nCiqGSIb4TQENAQUKAQAwCgYIKoZIzj0EAwID"
            "SAAwRQIhAMorRnjG/weLSnHmioqE\nG5aKucdumFbAimHdDps7DqCcAiBWcZwn"
            "VuXgHj+zjXkeJK3O8Ln4yDdayhDfk+Yj\nHfPIEw==\n"
            "-----END CERTIFICATE-----\n"

    }
  }
)proto";

// Returns a valid PCK certificates in the format of google::protobuf::Value.
google::protobuf::Value CreateValidPckCertsFromJson() {
  google::protobuf::Value pck_certs;
  ASYLO_CHECK_OK(Status(
      google::protobuf::util::JsonStringToMessage(kValidPckCertsJson, &pck_certs)));
  return pck_certs;
}

// Returns a string representation of |json|.
std::string JsonToString(const google::protobuf::Value &json) {
  std::string json_string;
  ASYLO_CHECK_OK(Status(google::protobuf::util::MessageToJsonString(json, &json_string)));
  return json_string;
}

TEST(PckCertsFromJsonTest, InvalidJsonFailsToParse) {
  EXPECT_THAT(
      PckCertificatesFromJson("} Wait a minute! This isn't proper JSON!"),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PckCertsFromJsonTest, NonObjectJsonValueFailsToParse) {
  EXPECT_THAT(PckCertificatesFromJson("[\"An array, not an object\"]"),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PckCertsFromJsonTest, NonHexEncodedRawTcbFailsToParse) {
  google::protobuf::Value json = CreateValidPckCertsFromJson();
  json.mutable_list_value()
      ->mutable_values(0)
      ->mutable_struct_value()
      ->mutable_fields()
      ->at("tcbm")
      .set_string_value("Non hex encoded");
  EXPECT_THAT(PckCertificatesFromJson(JsonToString(json)),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PckCertsFromJsonTest, WrongSizedRawTcbFailsToParse) {
  google::protobuf::Value json = CreateValidPckCertsFromJson();
  json.mutable_list_value()
      ->mutable_values(0)
      ->mutable_struct_value()
      ->mutable_fields()
      ->at("tcbm")
      .set_string_value("\x00\x01\x02\x03");
  EXPECT_THAT(PckCertificatesFromJson(JsonToString(json)),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PckCertsFromJsonTest, WrongPemFormatCertFailsToParse) {
  google::protobuf::Value json = CreateValidPckCertsFromJson();
  json.mutable_list_value()
      ->mutable_values(0)
      ->mutable_struct_value()
      ->mutable_fields()
      ->at("cert")
      .set_string_value("not a certificate");
  EXPECT_THAT(PckCertificatesFromJson(JsonToString(json)),
              StatusIs(absl::StatusCode::kInternal));
}

TEST(PckCertsFromJsonTest, CorrectJsonParsesSuccessfully) {
  PckCertificates pck_certs_proto;
  ASYLO_ASSERT_OK_AND_ASSIGN(pck_certs_proto,
                             PckCertificatesFromJson(kValidPckCertsJson));
  PckCertificates expected_pck_certs_proto;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(kExpectedPckCertsTextProto,
                                                  &expected_pck_certs_proto));

  EXPECT_THAT(pck_certs_proto, EqualsProto(expected_pck_certs_proto));
}

TEST(PckCertsFromJsonTest, ExtraFieldsCausesLogWarning) {
  google::protobuf::Value json = CreateValidPckCertsFromJson();
  google::protobuf::Value value;
  value.set_number_value(0.);
  json.mutable_list_value()
      ->mutable_values(0)
      ->mutable_struct_value()
      ->mutable_fields()
      ->insert({"extra", value});

  OutputCollector warning_collector(kCollectStdout);
  PckCertificates pck_certs;
  ASYLO_ASSERT_OK_AND_ASSIGN(pck_certs,
                             PckCertificatesFromJson(JsonToString(json)));
  EXPECT_THAT(warning_collector.CollectOutputSoFar(),
              IsOkAndHolds(HasSubstr("Encountered unrecognized fields")));
}

}  // namespace
}  // namespace sgx
}  // namespace asylo
