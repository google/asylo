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

#include "asylo/identity/attestation/sgx/internal/remote_assertion_generator_enclave_test_util.h"

#include <memory>
#include <string>

#include "asylo/client.h"
#include "asylo/crypto/certificate.pb.h"
#include "asylo/crypto/ecdsa_p256_sha256_signing_key.h"
#include "asylo/crypto/keys.pb.h"
#include "asylo/crypto/util/trivial_object_util.h"
#include "asylo/identity/attestation/sgx/internal/attestation_key_certificate_impl.h"
#include "asylo/identity/provisioning/sgx/internal/fake_sgx_pki.h"
#include "asylo/identity/sgx/identity_key_management_structs.h"
#include "asylo/identity/sgx/sgx_identity_util.h"
#include "asylo/identity/sgx/sgx_identity_util_internal.h"
#include "asylo/identity/sgx/sgx_infrastructural_enclave_manager.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace sgx {
namespace {

// A certificate for the public key defined in kFakePckPem.
constexpr char kFakeSgxPckCertificatePem[] =
    R"(-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----)";

StatusOr<Certificate> GenerateAndCertifyAttestationKey(
    SgxInfrastructuralEnclaveManager *manager) {
  static EcdsaP256Sha256SigningKey *pck =
      EcdsaP256Sha256SigningKey::CreateFromPem(kFakePckPem)
          .ValueOrDie()
          .release();

  // Use a well-formed Targetinfo (all reserved fields are cleared and all
  // required bits are set).
  Targetinfo targetinfo;
  SetTargetinfoFromSelfIdentity(&targetinfo);
  targetinfo.attributes = SecsAttributeSet::GetMustBeSetBits();
  targetinfo.miscselect = 0;
  TargetInfoProto pce_target_info;
  pce_target_info.set_value(ConvertTrivialObjectToBinaryString(targetinfo));

  ReportProto report;
  std::string pce_sign_report_payload;
  TargetedCertificateSigningRequest signing_request;  // Unused
  ASYLO_RETURN_IF_ERROR(manager->AgeGenerateKeyAndCsr(
      pce_target_info, &report, &pce_sign_report_payload, &signing_request));

  // Certify attestation key using the fake PCK.
  Signature pck_signature;
  ASYLO_RETURN_IF_ERROR(
      pck->Sign(ByteContainerView(report.value().data(), report.value().size()),
                &pck_signature));

  Certificate attestation_key_certificate;
  ASYLO_ASSIGN_OR_RETURN(attestation_key_certificate,
                         CreateAttestationKeyCertificate(
                             std::move(report), std::move(pck_signature),
                             std::move(pce_sign_report_payload)));
  return attestation_key_certificate;
}

// Appends a PCK Certificate, the Asylo Fake SGX Processor CA Certificate, and
// the Asylo Fake SGX Root CA certificate to |certificate_chain|.
void SetFakePckCertificateChain(CertificateChain *certificate_chain) {
  Certificate *fake_pck_cert = certificate_chain->add_certificates();
  fake_pck_cert->set_format(Certificate::X509_PEM);
  fake_pck_cert->set_data(kFakeSgxPckCertificatePem);

  Certificate *fake_pck_processor_ca_cert =
      certificate_chain->add_certificates();
  fake_pck_processor_ca_cert->set_format(Certificate::X509_PEM);
  fake_pck_processor_ca_cert->set_data(
      kFakeSgxProcessorCa.certificate_pem.data(),
      kFakeSgxProcessorCa.certificate_pem.size());

  Certificate *fake_sgx_root_ca_cert = certificate_chain->add_certificates();
  fake_sgx_root_ca_cert->set_format(Certificate::X509_PEM);
  fake_sgx_root_ca_cert->set_data(kFakeSgxRootCa.certificate_pem.data(),
                                  kFakeSgxRootCa.certificate_pem.size());
}

}  // namespace

StatusOr<CertificateChain> GenerateAttestationKeyAndFakeCertificateChain(
    EnclaveClient *assertion_generator_enclave_client) {
  // Don't create an IntelArchitecturalEnclaveInterface because only AGE APIs
  // are called.
  auto manager = absl::make_unique<SgxInfrastructuralEnclaveManager>(
      /*intel_ae_interface=*/nullptr, assertion_generator_enclave_client);
  return GenerateAttestationKeyAndFakeCertificateChain(manager.get());
}

StatusOr<CertificateChain> GenerateAttestationKeyAndFakeCertificateChain(
    SgxInfrastructuralEnclaveManager *manager) {
  CertificateChain certificate_chain;
  ASYLO_ASSIGN_OR_RETURN(*certificate_chain.add_certificates(),
                         GenerateAndCertifyAttestationKey(manager));
  SetFakePckCertificateChain(&certificate_chain);
  return certificate_chain;
}

CertificateChain GetFakePckCertificateChain() {
  CertificateChain certificate_chain;
  SetFakePckCertificateChain(&certificate_chain);
  return certificate_chain;
}

}  // namespace sgx
}  // namespace asylo
