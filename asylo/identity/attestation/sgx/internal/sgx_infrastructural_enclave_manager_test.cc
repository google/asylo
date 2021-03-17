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

#include "asylo/identity/attestation/sgx/internal/sgx_infrastructural_enclave_manager.h"

#include <memory>
#include <utility>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/certificate.pb.h"
#include "asylo/crypto/keys.pb.h"
#include "asylo/crypto/util/trivial_object_util.h"
#include "asylo/enclave.pb.h"
#include "asylo/identity/attestation/sgx/internal/attestation_key_certificate_impl.h"
#include "asylo/identity/attestation/sgx/internal/mock_intel_architectural_enclave_interface.h"
#include "asylo/identity/attestation/sgx/internal/pce_util.h"
#include "asylo/identity/attestation/sgx/internal/remote_assertion_generator_enclave.pb.h"
#include "asylo/identity/platform/sgx/internal/identity_key_management_structs.h"
#include "asylo/identity/platform/sgx/internal/sgx_identity_test_util.h"
#include "asylo/identity/platform/sgx/machine_configuration.pb.h"
#include "asylo/identity/provisioning/sgx/internal/platform_provisioning.pb.h"
#include "asylo/identity/sealing/sealed_secret.pb.h"
#include "asylo/test/util/memory_matchers.h"
#include "asylo/test/util/mock_enclave_client.h"
#include "asylo/test/util/proto_matchers.h"
#include "asylo/test/util/status_matchers.h"

namespace asylo {
namespace {

using ::testing::_;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Not;
using ::testing::NotNull;
using ::testing::Return;
using ::testing::SetArgPointee;
using ::testing::StrictMock;

constexpr uint16_t kPceId = 0;
constexpr uint16_t kPceSvn = 7;
constexpr SignatureScheme kPckSignatureScheme = ECDSA_P256_SHA256;
constexpr char kCpuSvn[] = "deadbeefdeadbeef";
constexpr char kEncryptedPpid[] = "encrypted ppid";
constexpr char kSecretCiphertext[] = "ciphertext";
constexpr char kCertificate[] = "Certificate";
constexpr char kEcdsaP256SignatureR[] =
    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
constexpr char kEcdsaP256SignatureS[] =
    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
constexpr char kPpidekPem[] =
    R"(-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAvxMDugH2cYvUWzjQhSgR
D4nT5Gj/2d2NHK3eZ52hzOfwn7Rv7PvNIzKWZWsI0SWfrOyZ3cZvuqRLvuUp3ouk
NPBfTMDGd6aUXK1U8ujgIIrSIY/Xq88tKoh3b63TuTgaMZuQhe+Yi5ME/JVMsHuc
SiY9SmCNJSLWJbNDnY8tMpnMLo027EN7gBIPinTQJK6IeqDkdsoxFXuydpC367bJ
qYSWSEbEgRpzrs4UUgdVMBc/fJU9zRqB50pFcVzbccFaB7XYiqZtrdqU07eorbpd
XINBBPFdfePByVdiUW6zfsxf8eUXLVXk9TioF1MqcJcVuHMndry2na28vQG9ZNH4
Glrb332S4+gfHYOTv5PJxLteIrWfyRstWxzuegpUcmrGSjgrMdjcuUOJjCnDJ2bW
0r0UE9um8JQodJKpILtTpq1rV+QlseUPu90ZID3OTk5PSne6NtJe7bN+9WeJspQO
C5xYNu944AfU3z0rnYRx0fEkiftBTiunrAioOA5jMQFHAgMBAAE=
-----END PUBLIC KEY-----)";
constexpr char kPceSignReportPayload[] = "pce sign report payload";
constexpr char kCertificateSignRequestData[] = "csr data";
constexpr char kInputMissingPceTargetInfoErrorMessage[] =
    "Input is missing pce_target_info";
constexpr char kInputMissingPpidEncryptionKeyErrorMessage[] =
    "Input is missing ppid_encryption_key";
constexpr char kNoAttestationKeyErrorMessage[] =
    "Cannot update certificates: no attestation key available";
constexpr char kServerAlreadyExistErrorMessage[] =
    "Cannot start remote assertion generator gRPC server: server already "
    "exists";
constexpr char kUnknownErrorMessage[] = "UNKNOWN";

sgx::Targetinfo PceTargetinfo() {
  return TrivialRandomObject<sgx::Targetinfo>();
}

sgx::ReportProto Report() {
  sgx::ReportProto report;
  report.set_value(
      ConvertTrivialObjectToBinaryString(TrivialRandomObject<sgx::Report>()));
  return report;
}

sgx::PceSvn PceSvn() {
  sgx::PceSvn pce_svn;
  pce_svn.set_value(kPceSvn);
  return pce_svn;
}

sgx::CpuSvn CreateCpuSvn() {
  sgx::CpuSvn cpu_svn;
  cpu_svn.set_value(kCpuSvn);
  return cpu_svn;
}

SealedSecret GetSealedSecret() {
  SealedSecret sealed_secret;
  sealed_secret.set_secret_ciphertext(kSecretCiphertext);
  return sealed_secret;
}

std::string PckSignature() {
  std::string signature_hex;
  signature_hex += kEcdsaP256SignatureR;
  signature_hex += kEcdsaP256SignatureS;
  return absl::HexStringToBytes(signature_hex);
}

Signature EcdsaSignature() {
  Signature signature;
  signature.set_signature_scheme(SignatureScheme::ECDSA_P256_SHA256);
  signature.mutable_ecdsa_signature()->set_r(
      absl::HexStringToBytes(kEcdsaP256SignatureR));
  signature.mutable_ecdsa_signature()->set_s(
      absl::HexStringToBytes(kEcdsaP256SignatureS));
  return signature;
}

sgx::TargetedCertificateSigningRequest TargetedCertificateSigningRequest() {
  sgx::TargetedCertificateSigningRequest targeted_csr;
  CertificateSigningRequest *csr =
      targeted_csr.mutable_certificate_signing_request();
  csr->set_format(CertificateSigningRequest::PKCS10_DER);
  csr->set_data(kCertificateSignRequestData);
  return targeted_csr;
}

void SetCertificateChain(std::vector<CertificateChain> *certificate_chains) {
  certificate_chains->emplace_back(CertificateChain::default_instance());
  Certificate *certificate = certificate_chains->back().add_certificates();
  certificate->set_format(Certificate::X509_DER);
  certificate->set_data(kCertificate);
}

asylo::AsymmetricEncryptionKeyProto Ppidek() {
  AsymmetricEncryptionKeyProto ppidek;
  ppidek.set_encryption_scheme(AsymmetricEncryptionScheme::RSA3072_OAEP);
  ppidek.set_key_type(AsymmetricEncryptionKeyProto::ENCRYPTION_KEY);
  ppidek.set_encoding(AsymmetricKeyEncoding::ASYMMETRIC_KEY_PEM);
  ppidek.set_key(kPpidekPem);
  return ppidek;
}

class SgxInfrastructuralEnclaveManagerTest : public ::testing::Test {
 public:
  void SetUp() override {
    mock_intel_ae_ =
        new StrictMock<sgx::MockIntelArchitecturalEnclaveInterface>();
    mock_assertion_generator_enclave_ =
        absl::make_unique<StrictMock<MockEnclaveClient>>();

    sgx_infrastructural_enclave_manager_ =
        absl::make_unique<SgxInfrastructuralEnclaveManager>(
            absl::WrapUnique(mock_intel_ae_),
            mock_assertion_generator_enclave_.get());
  }

 protected:
  // This pointer is not owned by the test fixture.
  StrictMock<sgx::MockIntelArchitecturalEnclaveInterface> *mock_intel_ae_;
  std::unique_ptr<StrictMock<MockEnclaveClient>>
      mock_assertion_generator_enclave_;

  std::unique_ptr<SgxInfrastructuralEnclaveManager>
      sgx_infrastructural_enclave_manager_;
};

TEST_F(SgxInfrastructuralEnclaveManagerTest, AgeGenerateKeyAndCsrSuccess) {
  EnclaveOutput expected_enclave_output;
  sgx::GenerateKeyAndCsrOutput *output =
      expected_enclave_output
          .MutableExtension(sgx::remote_assertion_generator_enclave_output)
          ->mutable_generate_key_and_csr_output();
  *output->mutable_report() = Report();
  *output->mutable_pce_sign_report_payload() = kPceSignReportPayload;
  *output->mutable_targeted_csr() = TargetedCertificateSigningRequest();
  EXPECT_CALL(*mock_assertion_generator_enclave_, EnterAndRun)
      .WillOnce(DoAll(SetArgPointee<1>(expected_enclave_output),
                      Return(absl::OkStatus())));

  sgx::TargetInfoProto pce_target_info;
  sgx::ReportProto report;
  std::string pce_sign_report_payload;
  sgx::TargetedCertificateSigningRequest targeted_csr;
  ASYLO_ASSERT_OK(sgx_infrastructural_enclave_manager_->AgeGenerateKeyAndCsr(
      pce_target_info, &report, &pce_sign_report_payload, &targeted_csr));
  EXPECT_THAT(report, EqualsProto(output->report()));
  EXPECT_THAT(pce_sign_report_payload, Eq(kPceSignReportPayload));
  EXPECT_THAT(targeted_csr, EqualsProto(output->targeted_csr()));
}

TEST_F(SgxInfrastructuralEnclaveManagerTest, AgeGenerateKeyAndCsrFailure) {
  EXPECT_CALL(*mock_assertion_generator_enclave_, EnterAndRun)
      .WillOnce(Return(Status(absl::StatusCode::kInvalidArgument,
                              kInputMissingPceTargetInfoErrorMessage)));

  sgx::TargetInfoProto pce_target_info;
  std::vector<std::string> target_certificate_authorities;
  sgx::ReportProto report;
  std::string pce_sign_report_payload;
  sgx::TargetedCertificateSigningRequest targeted_csr;
  EXPECT_THAT(
      sgx_infrastructural_enclave_manager_->AgeGenerateKeyAndCsr(
          pce_target_info, &report, &pce_sign_report_payload, &targeted_csr),
      StatusIs(absl::StatusCode::kInvalidArgument,
               kInputMissingPceTargetInfoErrorMessage));
}

TEST_F(SgxInfrastructuralEnclaveManagerTest,
       AgeGeneratePceInfoSgxHardwareReportSuccess) {
  EnclaveOutput expected_enclave_output;
  sgx::ReportProto expected_report = Report();
  *expected_enclave_output
       .MutableExtension(sgx::remote_assertion_generator_enclave_output)
       ->mutable_generate_pce_info_sgx_hardware_report_output()
       ->mutable_report() = expected_report;
  EXPECT_CALL(*mock_assertion_generator_enclave_, EnterAndRun)
      .WillOnce(DoAll(SetArgPointee<1>(expected_enclave_output),
                      Return(absl::OkStatus())));

  asylo::AsymmetricEncryptionKeyProto ppidek = Ppidek();
  sgx::TargetInfoProto pce_target_info;
  EXPECT_THAT(
      sgx_infrastructural_enclave_manager_->AgeGeneratePceInfoSgxHardwareReport(
          pce_target_info, ppidek),
      IsOkAndHolds(EqualsProto(expected_report)));
}

TEST_F(SgxInfrastructuralEnclaveManagerTest,
       AgeGeneratePceInfoSgxHardwareReportFailure) {
  EXPECT_CALL(*mock_assertion_generator_enclave_, EnterAndRun)
      .WillOnce(Return(Status(absl::StatusCode::kInvalidArgument,
                              kInputMissingPpidEncryptionKeyErrorMessage)));

  asylo::AsymmetricEncryptionKeyProto ppidek = Ppidek();
  sgx::TargetInfoProto pce_target_info;
  EXPECT_THAT(
      sgx_infrastructural_enclave_manager_->AgeGeneratePceInfoSgxHardwareReport(
          pce_target_info, ppidek),
      StatusIs(absl::StatusCode::kInvalidArgument,
               kInputMissingPpidEncryptionKeyErrorMessage));
}

TEST_F(SgxInfrastructuralEnclaveManagerTest, AgeUpdateCertsSuccess) {
  EnclaveOutput expected_enclave_output;
  SealedSecret expected_sealed_secret = GetSealedSecret();
  *expected_enclave_output
       .MutableExtension(sgx::remote_assertion_generator_enclave_output)
       ->mutable_update_certs_output()
       ->mutable_sealed_secret() = expected_sealed_secret;
  EXPECT_CALL(*mock_assertion_generator_enclave_, EnterAndRun)
      .WillOnce(DoAll(SetArgPointee<1>(expected_enclave_output),
                      Return(absl::OkStatus())));

  std::vector<CertificateChain> certificate_chains;
  SetCertificateChain(&certificate_chains);
  EXPECT_THAT(
      sgx_infrastructural_enclave_manager_->AgeUpdateCerts(certificate_chains),
      IsOkAndHolds(EqualsProto(expected_sealed_secret)));
}

TEST_F(SgxInfrastructuralEnclaveManagerTest, AgeUpdateCertsFailure) {
  EXPECT_CALL(*mock_assertion_generator_enclave_, EnterAndRun)
      .WillOnce(Return(Status(absl::StatusCode::kFailedPrecondition,
                              kNoAttestationKeyErrorMessage)));

  std::vector<CertificateChain> certificate_chains;
  SetCertificateChain(&certificate_chains);
  EXPECT_THAT(
      sgx_infrastructural_enclave_manager_->AgeUpdateCerts(certificate_chains),
      StatusIs(absl::StatusCode::kFailedPrecondition,
               kNoAttestationKeyErrorMessage));
}

TEST_F(SgxInfrastructuralEnclaveManagerTest,
       AgeStartServerWithoutSecretSuccess) {
  EXPECT_CALL(*mock_assertion_generator_enclave_, EnterAndRun)
      .WillOnce(Return(absl::OkStatus()));
  ASYLO_ASSERT_OK(sgx_infrastructural_enclave_manager_->AgeStartServer());
}

TEST_F(SgxInfrastructuralEnclaveManagerTest,
       AgeStartServerWithoutSecretFailure) {
  EXPECT_CALL(*mock_assertion_generator_enclave_, EnterAndRun)
      .WillOnce(Return(Status(absl::StatusCode::kAlreadyExists,
                              kServerAlreadyExistErrorMessage)));

  EXPECT_THAT(sgx_infrastructural_enclave_manager_->AgeStartServer(),
              StatusIs(absl::StatusCode::kAlreadyExists,
                       kServerAlreadyExistErrorMessage));
}

TEST_F(SgxInfrastructuralEnclaveManagerTest, AgeStartServerWithSecretSuccess) {
  EXPECT_CALL(*mock_assertion_generator_enclave_, EnterAndRun)
      .WillOnce(Return(absl::OkStatus()));

  SealedSecret sealed_secret = GetSealedSecret();
  ASYLO_ASSERT_OK(
      sgx_infrastructural_enclave_manager_->AgeStartServer(sealed_secret));
}

TEST_F(SgxInfrastructuralEnclaveManagerTest, AgeStartServerWithSecretFailure) {
  EXPECT_CALL(*mock_assertion_generator_enclave_, EnterAndRun)
      .WillOnce(Return(Status(absl::StatusCode::kAlreadyExists,
                              kServerAlreadyExistErrorMessage)));

  SealedSecret sealed_secret = GetSealedSecret();
  EXPECT_THAT(sgx_infrastructural_enclave_manager_->AgeStartServer(),
              StatusIs(absl::StatusCode::kAlreadyExists,
                       kServerAlreadyExistErrorMessage));
}

TEST_F(SgxInfrastructuralEnclaveManagerTest, AgeGetSgxIdentitySuccess) {
  EnclaveOutput expected_enclave_output;
  sgx::GetEnclaveIdentityOutput *expected_get_enclave_identity_output =
      expected_enclave_output
          .MutableExtension(sgx::remote_assertion_generator_enclave_output)
          ->mutable_get_enclave_identity_output();
  *expected_get_enclave_identity_output->mutable_sgx_identity() =
      sgx::GetRandomValidSgxIdentity();
  EXPECT_CALL(*mock_assertion_generator_enclave_, EnterAndRun)
      .WillOnce(DoAll(SetArgPointee<1>(expected_enclave_output),
                      Return(absl::OkStatus())));

  SgxIdentity sgx_identity;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      sgx_identity, sgx_infrastructural_enclave_manager_->AgeGetSgxIdentity());
  EXPECT_THAT(
      sgx_identity,
      EqualsProto(expected_get_enclave_identity_output->sgx_identity()));
}

TEST_F(SgxInfrastructuralEnclaveManagerTest, AgeGetSgxIdentityFails) {
  EXPECT_CALL(*mock_assertion_generator_enclave_, EnterAndRun)
      .WillOnce(Return(Status(absl::StatusCode::kUnknown, "UNKNOWN")));

  EXPECT_THAT(sgx_infrastructural_enclave_manager_->AgeGetSgxIdentity(),
              StatusIs(absl::StatusCode::kUnknown, "UNKNOWN"));
}

TEST_F(SgxInfrastructuralEnclaveManagerTest, PceGetTargetInfoSuccess) {
  sgx::Targetinfo expected_targetinfo = PceTargetinfo();
  EXPECT_CALL(*mock_intel_ae_, GetPceTargetinfo(NotNull(), NotNull()))
      .WillOnce(DoAll(SetArgPointee<0>(expected_targetinfo),
                      SetArgPointee<1>(kPceSvn), Return(absl::OkStatus())));

  sgx::TargetInfoProto pce_target_info;
  sgx::PceSvn pce_svn;
  ASYLO_ASSERT_OK(sgx_infrastructural_enclave_manager_->PceGetTargetInfo(
      &pce_target_info, &pce_svn));
  EXPECT_THAT(pce_svn.value(), Eq(kPceSvn));
  EXPECT_THAT(pce_target_info.value(),
              Eq(ConvertTrivialObjectToBinaryString(expected_targetinfo)));
}

TEST_F(SgxInfrastructuralEnclaveManagerTest, PceGetTargetInfoFailure) {
  EXPECT_CALL(*mock_intel_ae_, GetPceTargetinfo(NotNull(), NotNull()))
      .WillOnce(
          Return(Status(absl::StatusCode::kUnknown, kUnknownErrorMessage)));

  sgx::TargetInfoProto pce_target_info;
  sgx::PceSvn pce_svn;
  EXPECT_THAT(sgx_infrastructural_enclave_manager_->PceGetTargetInfo(
                  &pce_target_info, &pce_svn),
              StatusIs(absl::StatusCode::kUnknown));
}

TEST_F(SgxInfrastructuralEnclaveManagerTest, PceGetInfoSuccess) {
  EXPECT_CALL(*mock_intel_ae_,
              GetPceInfo(_, _, _, NotNull(), NotNull(), NotNull(), NotNull()))
      .WillOnce(DoAll(SetArgPointee<3>(kEncryptedPpid),
                      SetArgPointee<4>(kPceSvn), SetArgPointee<5>(kPceId),
                      SetArgPointee<6>(kPckSignatureScheme),
                      Return(absl::OkStatus())));

  sgx::ReportProto report = Report();
  asylo::AsymmetricEncryptionKeyProto ppidek = Ppidek();

  sgx::PceSvn pce_svn;
  sgx::PceId pce_id;
  asylo::SignatureScheme pck_signature_scheme;
  std::string encrypted_ppid;
  ASYLO_ASSERT_OK(sgx_infrastructural_enclave_manager_->PceGetInfo(
      report, ppidek, &pce_svn, &pce_id, &pck_signature_scheme,
      &encrypted_ppid));
  EXPECT_THAT(pce_svn.value(), Eq(kPceSvn));
  EXPECT_THAT(pce_id.value(), Eq(kPceId));
  EXPECT_THAT(pck_signature_scheme, Eq(kPckSignatureScheme));
  EXPECT_THAT(encrypted_ppid, Eq(kEncryptedPpid));
}

TEST_F(SgxInfrastructuralEnclaveManagerTest, PceGetInfoFailure) {
  EXPECT_CALL(*mock_intel_ae_,
              GetPceInfo(_, _, _, NotNull(), NotNull(), NotNull(), NotNull()))
      .WillOnce(
          Return(Status(absl::StatusCode::kUnknown, kUnknownErrorMessage)));

  sgx::ReportProto report = Report();
  asylo::AsymmetricEncryptionKeyProto ppidek = Ppidek();

  sgx::PceSvn pce_svn;
  sgx::PceId pce_id;
  asylo::SignatureScheme pck_signature_scheme;
  std::string encrypted_ppid;
  EXPECT_THAT(sgx_infrastructural_enclave_manager_->PceGetInfo(
                  report, ppidek, &pce_svn, &pce_id, &pck_signature_scheme,
                  &encrypted_ppid),
              StatusIs(absl::StatusCode::kUnknown));
}

TEST_F(SgxInfrastructuralEnclaveManagerTest, PceGetInfoWithInvalidReportFails) {
  // Uninitialized.
  sgx::ReportProto report;
  asylo::AsymmetricEncryptionKeyProto ppidek = Ppidek();

  sgx::PceSvn pce_svn;
  sgx::PceId pce_id;
  asylo::SignatureScheme pck_signature_scheme;
  std::string encrypted_ppid;
  EXPECT_THAT(sgx_infrastructural_enclave_manager_->PceGetInfo(
                  report, ppidek, &pce_svn, &pce_id, &pck_signature_scheme,
                  &encrypted_ppid),
              Not(IsOk()));
}

TEST_F(SgxInfrastructuralEnclaveManagerTest, PceGetInfoWithBadPpidekFails) {
  sgx::ReportProto report = Report();
  // Uninitialized.
  asylo::AsymmetricEncryptionKeyProto ppidek;

  sgx::PceSvn pce_svn;
  sgx::PceId pce_id;
  asylo::SignatureScheme pck_signature_scheme;
  std::string encrypted_ppid;
  EXPECT_THAT(sgx_infrastructural_enclave_manager_->PceGetInfo(
                  report, ppidek, &pce_svn, &pce_id, &pck_signature_scheme,
                  &encrypted_ppid),
              Not(IsOk()));
}

TEST_F(SgxInfrastructuralEnclaveManagerTest, PceSignReportSuccess) {
  EXPECT_CALL(*mock_intel_ae_, PceSignReport(_, _, _, _))
      .WillOnce(
          DoAll(SetArgPointee<3>(PckSignature()), Return(absl::OkStatus())));

  sgx::PceSvn pck_target_pce_svn = PceSvn();
  sgx::CpuSvn pck_target_cpu_svn = CreateCpuSvn();
  sgx::ReportProto report = Report();
  EXPECT_THAT(sgx_infrastructural_enclave_manager_->PceSignReport(
                  pck_target_pce_svn, pck_target_cpu_svn, report),
              IsOkAndHolds(EqualsProto(EcdsaSignature())));
}

TEST_F(SgxInfrastructuralEnclaveManagerTest, PceSignReportFailure) {
  EXPECT_CALL(*mock_intel_ae_, PceSignReport(_, _, _, _))
      .WillOnce(
          Return(Status(absl::StatusCode::kUnknown, kUnknownErrorMessage)));

  sgx::PceSvn pck_target_pce_svn = PceSvn();
  sgx::CpuSvn pck_target_cpu_svn = CreateCpuSvn();
  sgx::ReportProto report = Report();
  EXPECT_THAT(sgx_infrastructural_enclave_manager_->PceSignReport(
                  pck_target_pce_svn, pck_target_cpu_svn, report),
              StatusIs(absl::StatusCode::kUnknown));
}

TEST_F(SgxInfrastructuralEnclaveManagerTest, PceSignReportWithBadPceSvnFails) {
  // Uninitialized.
  sgx::PceSvn pck_target_pce_svn;
  sgx::CpuSvn pck_target_cpu_svn = CreateCpuSvn();
  sgx::ReportProto report = Report();
  EXPECT_THAT(sgx_infrastructural_enclave_manager_->PceSignReport(
                  pck_target_pce_svn, pck_target_cpu_svn, report),
              Not(IsOk()));
}

TEST_F(SgxInfrastructuralEnclaveManagerTest, PceSignReportWithBadCpuSvnFails) {
  sgx::PceSvn pck_target_pce_svn = PceSvn();
  // Uninitialized.
  sgx::CpuSvn pck_target_cpu_svn;
  sgx::ReportProto report = Report();
  EXPECT_THAT(sgx_infrastructural_enclave_manager_->PceSignReport(
                  pck_target_pce_svn, pck_target_cpu_svn, report),
              Not(IsOk()));
}

TEST_F(SgxInfrastructuralEnclaveManagerTest, PceSignWithBadReportFails) {
  sgx::PceSvn pck_target_pce_svn = PceSvn();
  sgx::CpuSvn pck_target_cpu_svn = CreateCpuSvn();
  // Uninitialized.
  sgx::ReportProto report;
  EXPECT_THAT(sgx_infrastructural_enclave_manager_->PceSignReport(
                  pck_target_pce_svn, pck_target_cpu_svn, report),
              Not(IsOk()));
}

TEST_F(SgxInfrastructuralEnclaveManagerTest, CertifyAgeGetTargetInfoFailure) {
  EXPECT_CALL(*mock_intel_ae_, GetPceTargetinfo(NotNull(), NotNull()))
      .WillOnce(
          Return(Status(absl::StatusCode::kUnknown, kUnknownErrorMessage)));

  EXPECT_THAT(sgx_infrastructural_enclave_manager_->CertifyAge(),
              StatusIs(absl::StatusCode::kUnknown));
}

TEST_F(SgxInfrastructuralEnclaveManagerTest,
       CertifyAgeGenerateKeyAndCsrFailure) {
  EXPECT_CALL(*mock_intel_ae_, GetPceTargetinfo(NotNull(), NotNull()))
      .WillOnce(DoAll(SetArgPointee<0>(PceTargetinfo()),
                      SetArgPointee<1>(PceSvn().value()),
                      Return(absl::OkStatus())));
  EXPECT_CALL(*mock_assertion_generator_enclave_, EnterAndRun)
      .WillOnce(
          Return(Status(absl::StatusCode::kUnknown, kUnknownErrorMessage)));

  EXPECT_THAT(sgx_infrastructural_enclave_manager_->CertifyAge(),
              StatusIs(absl::StatusCode::kUnknown));
}

TEST_F(SgxInfrastructuralEnclaveManagerTest, CertifyAgeGetSgxIdentityFailure) {
  EXPECT_CALL(*mock_intel_ae_, GetPceTargetinfo(NotNull(), NotNull()))
      .WillOnce(DoAll(SetArgPointee<0>(PceTargetinfo()),
                      SetArgPointee<1>(PceSvn().value()),
                      Return(absl::OkStatus())));
  EnclaveOutput expected_enclave_output;
  sgx::GenerateKeyAndCsrOutput *output =
      expected_enclave_output
          .MutableExtension(sgx::remote_assertion_generator_enclave_output)
          ->mutable_generate_key_and_csr_output();
  *output->mutable_report() = Report();
  *output->mutable_pce_sign_report_payload() = kPceSignReportPayload;
  *output->mutable_targeted_csr() = TargetedCertificateSigningRequest();

  EXPECT_CALL(*mock_assertion_generator_enclave_, EnterAndRun)
      .WillOnce(DoAll(SetArgPointee<1>(expected_enclave_output),
                      Return(absl::OkStatus())))
      .WillOnce(
          Return(Status(absl::StatusCode::kUnknown, kUnknownErrorMessage)));

  EXPECT_THAT(sgx_infrastructural_enclave_manager_->CertifyAge(),
              StatusIs(absl::StatusCode::kUnknown));
}

TEST_F(SgxInfrastructuralEnclaveManagerTest, CertifyAgePceSignReportFailure) {
  sgx::PceSvn pck_target_pce_svn = PceSvn();
  EXPECT_CALL(*mock_intel_ae_, GetPceTargetinfo(NotNull(), NotNull()))
      .WillOnce(DoAll(SetArgPointee<0>(PceTargetinfo()),
                      SetArgPointee<1>(pck_target_pce_svn.value()),
                      Return(absl::OkStatus())));

  EnclaveOutput expected_gen_key_and_csr_output;
  sgx::GenerateKeyAndCsrOutput *output =
      expected_gen_key_and_csr_output
          .MutableExtension(sgx::remote_assertion_generator_enclave_output)
          ->mutable_generate_key_and_csr_output();

  sgx::ReportProto report = Report();
  *output->mutable_report() = report;
  *output->mutable_pce_sign_report_payload() = kPceSignReportPayload;
  *output->mutable_targeted_csr() = TargetedCertificateSigningRequest();

  SgxIdentity age_identity = sgx::GetRandomValidSgxIdentityWithConstraints(
      /*mrenclave_constraint=*/{true},
      /*mrsigner_constraint=*/{true},
      /*cpu_svn_constraint=*/{true},
      /*sgx_type_constraint=*/{false});
  EnclaveOutput expected_get_enclave_identity_output;
  *expected_get_enclave_identity_output
       .MutableExtension(sgx::remote_assertion_generator_enclave_output)
       ->mutable_get_enclave_identity_output()
       ->mutable_sgx_identity() = age_identity;
  EXPECT_CALL(*mock_assertion_generator_enclave_, EnterAndRun)
      .WillOnce(DoAll(SetArgPointee<1>(expected_gen_key_and_csr_output),
                      Return(absl::OkStatus())))
      .WillOnce(DoAll(SetArgPointee<1>(expected_get_enclave_identity_output),
                      Return(absl::OkStatus())));

  sgx::Report expected_report;
  SetTrivialObjectFromBinaryString(report.value(), &expected_report);
  EXPECT_CALL(*mock_intel_ae_,
              PceSignReport(
                  TrivialObjectEq(expected_report), pck_target_pce_svn.value(),
                  UnsafeBytes<sgx::kCpusvnSize>(
                      age_identity.machine_configuration().cpu_svn().value()),
                  NotNull()))
      .WillOnce(
          Return(Status(absl::StatusCode::kUnknown, kUnknownErrorMessage)));

  EXPECT_THAT(sgx_infrastructural_enclave_manager_->CertifyAge(),
              StatusIs(absl::StatusCode::kUnknown));
}

TEST_F(SgxInfrastructuralEnclaveManagerTest, CertifyAgeSuccess) {
  sgx::PceSvn pck_target_pce_svn = PceSvn();
  EXPECT_CALL(*mock_intel_ae_, GetPceTargetinfo(NotNull(), NotNull()))
      .WillOnce(DoAll(SetArgPointee<0>(PceTargetinfo()),
                      SetArgPointee<1>(pck_target_pce_svn.value()),
                      Return(absl::OkStatus())));

  EnclaveOutput expected_gen_key_and_csr_output;
  sgx::GenerateKeyAndCsrOutput *output =
      expected_gen_key_and_csr_output
          .MutableExtension(sgx::remote_assertion_generator_enclave_output)
          ->mutable_generate_key_and_csr_output();

  sgx::ReportProto report = Report();
  *output->mutable_report() = report;
  *output->mutable_pce_sign_report_payload() = kPceSignReportPayload;
  *output->mutable_targeted_csr() = TargetedCertificateSigningRequest();

  SgxIdentity age_identity = sgx::GetRandomValidSgxIdentityWithConstraints(
      /*mrenclave_constraint=*/{true},
      /*mrsigner_constraint=*/{true},
      /*cpu_svn_constraint=*/{true},
      /*sgx_type_constraint=*/{false});
  EnclaveOutput expected_get_enclave_identity_output;
  *expected_get_enclave_identity_output
       .MutableExtension(sgx::remote_assertion_generator_enclave_output)
       ->mutable_get_enclave_identity_output()
       ->mutable_sgx_identity() = age_identity;
  EXPECT_CALL(*mock_assertion_generator_enclave_, EnterAndRun)
      .WillOnce(DoAll(SetArgPointee<1>(expected_gen_key_and_csr_output),
                      Return(absl::OkStatus())))
      .WillOnce(DoAll(SetArgPointee<1>(expected_get_enclave_identity_output),
                      Return(absl::OkStatus())));

  sgx::Report expected_report;
  SetTrivialObjectFromBinaryString(report.value(), &expected_report);
  EXPECT_CALL(*mock_intel_ae_,
              PceSignReport(
                  TrivialObjectEq(expected_report), pck_target_pce_svn.value(),
                  UnsafeBytes<sgx::kCpusvnSize>(
                      age_identity.machine_configuration().cpu_svn().value()),
                  NotNull()))
      .WillOnce(
          DoAll(SetArgPointee<3>(PckSignature()), Return(absl::OkStatus())));

  Certificate expected_certificate;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      expected_certificate,
      CreateAttestationKeyCertificate(report, EcdsaSignature(),
                                      kPceSignReportPayload));
  EXPECT_THAT(sgx_infrastructural_enclave_manager_->CertifyAge(),
              IsOkAndHolds(EqualsProto(expected_certificate)));
}

TEST_F(SgxInfrastructuralEnclaveManagerTest,
       CertifyAgeWithPceSvnAndCpuSvnSuccess) {
  EXPECT_CALL(*mock_intel_ae_, GetPceTargetinfo(NotNull(), NotNull()))
      .WillOnce(DoAll(SetArgPointee<0>(PceTargetinfo()),
                      SetArgPointee<1>(PceSvn().value()),
                      Return(absl::OkStatus())));

  EnclaveOutput expected_gen_key_and_csr_output;
  sgx::GenerateKeyAndCsrOutput *output =
      expected_gen_key_and_csr_output
          .MutableExtension(sgx::remote_assertion_generator_enclave_output)
          ->mutable_generate_key_and_csr_output();

  sgx::ReportProto report = Report();
  *output->mutable_report() = report;
  *output->mutable_pce_sign_report_payload() = kPceSignReportPayload;
  *output->mutable_targeted_csr() = TargetedCertificateSigningRequest();

  EXPECT_CALL(*mock_assertion_generator_enclave_, EnterAndRun)
      .WillOnce(DoAll(SetArgPointee<1>(expected_gen_key_and_csr_output),
                      Return(absl::OkStatus())));

  sgx::CpuSvn pck_target_cpu_svn = CreateCpuSvn();
  sgx::PceSvn pck_target_pce_svn;
  pck_target_pce_svn.set_value(kPceSvn + 1);

  sgx::Report expected_report;
  SetTrivialObjectFromBinaryString(report.value(), &expected_report);
  EXPECT_CALL(
      *mock_intel_ae_,
      PceSignReport(
          TrivialObjectEq(expected_report), pck_target_pce_svn.value(),
          UnsafeBytes<sgx::kCpusvnSize>(pck_target_cpu_svn.value()), NotNull()))
      .WillOnce(
          DoAll(SetArgPointee<3>(PckSignature()), Return(absl::OkStatus())));

  Certificate expected_certificate;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      expected_certificate,
      CreateAttestationKeyCertificate(report, EcdsaSignature(),
                                      kPceSignReportPayload));
  EXPECT_THAT(sgx_infrastructural_enclave_manager_->CertifyAge(
                  pck_target_pce_svn, pck_target_cpu_svn),
              IsOkAndHolds(EqualsProto(expected_certificate)));
}

}  // namespace
}  // namespace asylo
