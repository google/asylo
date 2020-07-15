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

#include "asylo/identity/provisioning/sgx/internal/fake_sgx_pki.h"

#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"

namespace asylo {
namespace sgx {

const CertificateAndPrivateKey kFakeSgxRootCa = {
    R"pem(-----BEGIN CERTIFICATE-----
MIIChDCCAiugAwIBAgIVAKk7nb9ghovhxdr15DdJaAYcCOLtMAoGCCqGSM49BAMC
MIGNMTAwLgYDVQQDDCdBc3lsbyBGYWtlIFNHWCBSb290IENBIEZvciBUZXN0aW5n
IE9ubHkxLDAqBgNVBAoMI0FzeWxvIEZha2UgU0dYIFBLSSBGb3IgVGVzdGluZyBP
bmx5MREwDwYDVQQHDAhLaXJrbGFuZDELMAkGA1UECAwCV0ExCzAJBgNVBAYTAlVT
MB4XDTE5MDEwMTAwMDAwMFoXDTQ5MTIzMTIzNTk1OVowgY0xMDAuBgNVBAMMJ0Fz
eWxvIEZha2UgU0dYIFJvb3QgQ0EgRm9yIFRlc3RpbmcgT25seTEsMCoGA1UECgwj
QXN5bG8gRmFrZSBTR1ggUEtJIEZvciBUZXN0aW5nIE9ubHkxETAPBgNVBAcMCEtp
cmtsYW5kMQswCQYDVQQIDAJXQTELMAkGA1UEBhMCVVMwWTATBgcqhkjOPQIBBggq
hkjOPQMBBwNCAARK97DEsISoPNf/uASTz68CIjZ7YXxUyZbF1Qp57pSxUNufMy9i
jd5XzwpIEReZoB12O46+rA4+6Z2Jm77dMeIvo2YwZDAfBgNVHSMEGDAWgBTMhCIh
J51Yc8ZMc3DIDaONAESnXDAdBgNVHQ4EFgQUzIQiISedWHPGTHNwyA2jjQBEp1ww
DgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAQECAQEwCgYIKoZIzj0EAwID
RwAwRAIgRre0NHzlp+vh/zYlnHGDQ0eOPtjfG6hzmf4Z8ciyuaoCICtA0lVm2GQB
zUf61sdGT+9NLBbB1f8ibdySIVujAmxv
-----END CERTIFICATE-----)pem",
    R"pem(-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIMsbxXDTgZq6WPEGniqIUPQP/cn3IpX1Zb6EXx77vruUoAoGCCqGSM49
AwEHoUQDQgAESvewxLCEqDzX/7gEk8+vAiI2e2F8VMmWxdUKee6UsVDbnzMvYo3e
V88KSBEXmaAddjuOvqwOPumdiZu+3THiLw==
-----END EC PRIVATE KEY-----)pem",
};

const CertificateAndPrivateKey kFakeSgxPlatformCa = {
    R"pem(-----BEGIN CERTIFICATE-----
MIICijCCAi+gAwIBAgIVAKTjQPjvKF3h9ViZDZ5rQycoMCt2MAoGCCqGSM49BAMC
MIGNMTAwLgYDVQQDDCdBc3lsbyBGYWtlIFNHWCBSb290IENBIEZvciBUZXN0aW5n
IE9ubHkxLDAqBgNVBAoMI0FzeWxvIEZha2UgU0dYIFBLSSBGb3IgVGVzdGluZyBP
bmx5MREwDwYDVQQHDAhLaXJrbGFuZDELMAkGA1UECAwCV0ExCzAJBgNVBAYTAlVT
MB4XDTE5MDEwMTAwMDAwMFoXDTM0MDEwMTAwMDAwMFowgZExNDAyBgNVBAMMK0Fz
eWxvIEZha2UgU0dYIFBsYXRmb3JtIENBIEZvciBUZXN0aW5nIE9ubHkxLDAqBgNV
BAoMI0FzeWxvIEZha2UgU0dYIFBLSSBGb3IgVGVzdGluZyBPbmx5MREwDwYDVQQH
DAhLaXJrbGFuZDELMAkGA1UECAwCV0ExCzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0C
AQYIKoZIzj0DAQcDQgAEaW/AhuvWCE54xAWzIFxQKH69Q9uFWEenMYClbz3YNNzT
EvRpjxZ5Kh3qv7yN3/lAfU80+xmlDpRcc0rRj+PMsqNmMGQwHwYDVR0jBBgwFoAU
zIQiISedWHPGTHNwyA2jjQBEp1wwHQYDVR0OBBYEFMcREC1SbTeykljun8DOLPkg
Jyd/MA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQEBAgEAMAoGCCqGSM49
BAMCA0kAMEYCIQD3cdKDFlc7+mfwcylgrWfB3sOhxhZDC1aaetrmkVaUcQIhALZA
Yusgokb6YjEsH5V8hZ2MmKSJ5R0WC7kxq2yiNFPP
-----END CERTIFICATE-----)pem",
    R"pem(-----BEGIN EC PRIVATE KEY-----
MHcCAQEEII2c4/uWfsYpG8ioplhz6Ka2fVK4gTat5kRo4nIL65PeoAoGCCqGSM49
AwEHoUQDQgAEaW/AhuvWCE54xAWzIFxQKH69Q9uFWEenMYClbz3YNNzTEvRpjxZ5
Kh3qv7yN3/lAfU80+xmlDpRcc0rRj+PMsg==
-----END EC PRIVATE KEY-----)pem",
};

const CertificateAndPrivateKey kFakeSgxProcessorCa = {
    R"pem(-----BEGIN CERTIFICATE-----
MIICiTCCAi+gAwIBAgIUOz7o2CDsWcVqpWM3KQEVczvh2s8wCgYIKoZIzj0EAwIw
gY0xMDAuBgNVBAMMJ0FzeWxvIEZha2UgU0dYIFJvb3QgQ0EgRm9yIFRlc3Rpbmcg
T25seTEsMCoGA1UECgwjQXN5bG8gRmFrZSBTR1ggUEtJIEZvciBUZXN0aW5nIE9u
bHkxETAPBgNVBAcMCEtpcmtsYW5kMQswCQYDVQQIDAJXQTELMAkGA1UEBhMCVVMw
HhcNMTkwMTAxMDAwMDAwWhcNMzQwMTAxMDAwMDAwWjCBkjE1MDMGA1UEAwwsQXN5
bG8gRmFrZSBTR1ggUHJvY2Vzc29yIENBIEZvciBUZXN0aW5nIE9ubHkxLDAqBgNV
BAoMI0FzeWxvIEZha2UgU0dYIFBLSSBGb3IgVGVzdGluZyBPbmx5MREwDwYDVQQH
DAhLaXJrbGFuZDELMAkGA1UECAwCV0ExCzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0C
AQYIKoZIzj0DAQcDQgAEM5G0Gwt+2H+aZ4cdpWJlUL8vy8QEi7xB/kEcNt5L6e9Q
cQhWhy14Db6AyIx3GKJZ80J58KxdTpt43RNrDNeX9KNmMGQwHwYDVR0jBBgwFoAU
zIQiISedWHPGTHNwyA2jjQBEp1wwHQYDVR0OBBYEFGcrTEqJ6BLf1E/ugIQFSw1f
i7opMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQEBAgEAMAoGCCqGSM49
BAMCA0gAMEUCIEaPBDr1N+nmSq+vqWSyNUxA4nnsmZQe2HOGWzaf3ipYAiEAuffT
LGUbBp0tJsFq4kHkHXZuI/lVh/26Qhyde38JAZ8=
-----END CERTIFICATE-----)pem",
    R"pem(-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIG8IOGHrX+m/UZMPsZQ5LlRtDN2qp3jRpDGae2IO8jy6oAoGCCqGSM49
AwEHoUQDQgAEM5G0Gwt+2H+aZ4cdpWJlUL8vy8QEi7xB/kEcNt5L6e9QcQhWhy14
Db6AyIx3GKJZ80J58KxdTpt43RNrDNeX9A==
-----END EC PRIVATE KEY-----)pem",
};

const CertificateAndPrivateKey kFakeSgxTcbSigner = {
    R"pem(-----BEGIN CERTIFICATE-----
MIICgTCCAiegAwIBAgIUVZNZVx55g09uske5m1G8nrhrjxEwCgYIKoZIzj0EAwIw
gY0xMDAuBgNVBAMMJ0FzeWxvIEZha2UgU0dYIFJvb3QgQ0EgRm9yIFRlc3Rpbmcg
T25seTEsMCoGA1UECgwjQXN5bG8gRmFrZSBTR1ggUEtJIEZvciBUZXN0aW5nIE9u
bHkxETAPBgNVBAcMCEtpcmtsYW5kMQswCQYDVQQIDAJXQTELMAkGA1UEBhMCVVMw
HhcNMTkwMTAxMDAwMDAwWhcNMjYwMTAxMDAwMDAwWjCBkDEzMDEGA1UEAwwqQXN5
bG8gRmFrZSBTR1ggVGNiIFNpZ25lciBGb3IgVGVzdGluZyBPbmx5MSwwKgYDVQQK
DCNBc3lsbyBGYWtlIFNHWCBQS0kgRm9yIFRlc3RpbmcgT25seTERMA8GA1UEBwwI
S2lya2xhbmQxCzAJBgNVBAgMAldBMQswCQYDVQQGEwJVUzBZMBMGByqGSM49AgEG
CCqGSM49AwEHA0IABCCFkejnokc+0MFTFYXWxUuRsvNVLYAQLWDyfTni2aAqJHv7
gty0bXfqYZZTdcBg8ZPvcgV9HStaUA6QmUT2AiujYDBeMB8GA1UdIwQYMBaAFMyE
IiEnnVhzxkxzcMgNo40ARKdcMB0GA1UdDgQWBBSKIpPrF/6+UEW7n0j4wEHFazDb
lTAOBgNVHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADAKBggqhkjOPQQDAgNIADBF
AiAsh51FjwCbdMKe4T7HtXqRzmkRThNz0RxODIx6NL2OBwIhAKSVZdtc8YI3Kj4L
8rk1f1l/tWHqII6f5haKpYmOD6Cc
-----END CERTIFICATE-----)pem",
    R"pem(-----BEGIN EC PRIVATE KEY-----
MHcCAQEEINJielbvwI0VMyj4aDhKKbNYLvPKUazVXjzqZk9shGVjoAoGCCqGSM49
AwEHoUQDQgAEIIWR6OeiRz7QwVMVhdbFS5Gy81UtgBAtYPJ9OeLZoCoke/uC3LRt
d+phllN1wGDxk+9yBX0dK1pQDpCZRPYCKw==
-----END EC PRIVATE KEY-----)pem",
};

const CertificateAndPrivateKey kFakeSgxPck = {
    R"pem(-----BEGIN CERTIFICATE-----
MIIEZzCCBAygAwIBAgIUWN4rW902Ui2mbVyD8vvmhqCpgK8wCgYIKoZIzj0EAwIw
gZIxNTAzBgNVBAMMLEFzeWxvIEZha2UgU0dYIFByb2Nlc3NvciBDQSBGb3IgVGVz
dGluZyBPbmx5MSwwKgYDVQQKDCNBc3lsbyBGYWtlIFNHWCBQS0kgRm9yIFRlc3Rp
bmcgT25seTERMA8GA1UEBwwIS2lya2xhbmQxCzAJBgNVBAgMAldBMQswCQYDVQQG
EwJVUzAeFw0xOTEyMjYyMjQ5MTJaFw0yNjEyMjQyMjQ5MTJaMIGVMTgwNgYDVQQD
DC9Bc3lsbyBGYWtlIFNHWCBQQ0sgQ2VydGlmaWNhdGUgRm9yIFRlc3RpbmcgT25s
eTEsMCoGA1UECgwjQXN5bG8gRmFrZSBTR1ggUEtJIEZvciBUZXN0aW5nIE9ubHkx
ETAPBgNVBAcMCEtpcmtsYW5kMQswCQYDVQQIDAJXQTELMAkGA1UEBhMCVVMwWTAT
BgcqhkjOPQIBBggqhkjOPQMBBwNCAATYz8RMPUVX0QXNkEHX56YEUm4HV6Hb9fJj
dl02tPyWrsVDRnoQ12agb6V1Af3h3oU+RFY4zBj6mkH5JDxedQVEo4ICOTCCAjUw
HwYDVR0jBBgwFoAUZytMSonoEt/UT+6AhAVLDV+LuikwHQYDVR0OBBYEFAGA3E8C
dQhTVocAnhq3znP97aKgMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMIIB
0wYJKoZIhvhNAQ0BBIIBxDCCAcAwHgYKKoZIhvhNAQ0BAQQQAQAAAFNWAACVoKrc
owVKjDCCAWMGCiqGSIb4TQENAQIwggFTMBAGCyqGSIb4TQENAQIBAgFBMBAGCyqG
SIb4TQENAQICAgEgMBAGCyqGSIb4TQENAQIDAgFmMBAGCyqGSIb4TQENAQIEAgFh
MBAGCyqGSIb4TQENAQIFAgFrMBAGCyqGSIb4TQENAQIGAgFlMBAGCyqGSIb4TQEN
AQIHAgEgMBAGCyqGSIb4TQENAQIIAgFUMBAGCyqGSIb4TQENAQIJAgFDMBAGCyqG
SIb4TQENAQIKAgFCMBAGCyqGSIb4TQENAQILAgEgMBAGCyqGSIb4TQENAQIMAgFs
MBAGCyqGSIb4TQENAQINAgFlMBAGCyqGSIb4TQENAQIOAgF2MBAGCyqGSIb4TQEN
AQIPAgFlMBAGCyqGSIb4TQENAQIQAgFsMBAGCyqGSIb4TQENAQIRAgECMB8GCyqG
SIb4TQENAQISBBBBIGZha2UgVENCIGxldmVsMBAGCiqGSIb4TQENAQMEAgAAMBQG
CiqGSIb4TQENAQQEBgEAAABTVjAPBgoqhkiG+E0BDQEFCgEAMAoGCCqGSM49BAMC
A0kAMEYCIQChG343CsWOKm1wc4Q8lbGr8L990Z859dYtkDZLWefNPwIhAPoNTVWj
DuBaDLzJyoz5Vtv4SBA2PZaeqC2RQoVJHBHC
-----END CERTIFICATE-----)pem",
    R"pem(-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIF0Z0yrz9NNVFQU1754rHRJs+Qt04mr3vEgNok8uyU8QoAoGCCqGSM49
AwEHoUQDQgAE2M/ETD1FV9EFzZBB1+emBFJuB1eh2/XyY3ZdNrT8lq7FQ0Z6ENdm
oG+ldQH94d6FPkRWOMwY+ppB+SQ8XnUFRA==
-----END EC PRIVATE KEY-----)pem",
};

const absl::string_view kFakePckPublicPem =
    R"pem(-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2M/ETD1FV9EFzZBB1+emBFJuB1eh
2/XyY3ZdNrT8lq7FQ0Z6ENdmoG+ldQH94d6FPkRWOMwY+ppB+SQ8XnUFRA==
-----END PUBLIC KEY-----)pem";

const absl::string_view kFakePckMachineConfigurationTextProto =
    R"pb(
  cpu_svn { value: "A fake TCB level" }
  sgx_type: STANDARD
    )pb";

void AppendFakePckCertificateChain(CertificateChain *certificate_chain) {
  Certificate *fake_pck_cert = certificate_chain->add_certificates();
  fake_pck_cert->set_format(Certificate::X509_PEM);
  fake_pck_cert->set_data(kFakeSgxPck.certificate_pem.data(),
                          kFakeSgxPck.certificate_pem.size());

  Certificate *fake_pck_processor_ca_cert =
      certificate_chain->add_certificates();
  fake_pck_processor_ca_cert->set_format(Certificate::X509_PEM);
  fake_pck_processor_ca_cert->set_data(
      kFakeSgxProcessorCa.certificate_pem.data(),
      kFakeSgxProcessorCa.certificate_pem.size());

  *certificate_chain->add_certificates() = GetFakeSgxRootCertificate();
}

Certificate GetFakeSgxRootCertificate() {
  Certificate fake_sgx_root_ca_cert;
  fake_sgx_root_ca_cert.set_format(Certificate::X509_PEM);
  fake_sgx_root_ca_cert.set_data(kFakeSgxRootCa.certificate_pem.data(),
                                 kFakeSgxRootCa.certificate_pem.size());
  return fake_sgx_root_ca_cert;
}

CertificateChain GetFakePckCertificateChain() {
  CertificateChain certificate_chain;
  AppendFakePckCertificateChain(&certificate_chain);
  return certificate_chain;
}

SgxExtensions GetFakePckCertificateExtensions() {
  SgxExtensions extensions;
  extensions.ppid.set_value(
      absl::HexStringToBytes("010000005356000095a0aadca3054a8c"));
  extensions.tcb.set_components("A fake TCB level");
  extensions.tcb.mutable_pce_svn()->set_value(2);
  extensions.cpu_svn.set_value("A fake TCB level");
  extensions.pce_id.set_value(0);
  extensions.fmspc.set_value(absl::HexStringToBytes("010000005356"));
  extensions.sgx_type = SgxType::STANDARD;
  return extensions;
}

}  // namespace sgx
}  // namespace asylo
