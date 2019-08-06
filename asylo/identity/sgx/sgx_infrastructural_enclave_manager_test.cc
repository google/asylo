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

#include "asylo/identity/sgx/sgx_infrastructural_enclave_manager.h"

#include <memory>
#include <utility>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/memory/memory.h"
#include "absl/strings/escaping.h"
#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/keys.pb.h"
#include "asylo/crypto/util/trivial_object_util.h"
#include "asylo/identity/sgx/identity_key_management_structs.h"
#include "asylo/identity/sgx/mock_intel_architectural_enclave_interface.h"
#include "asylo/identity/sgx/pce_util.h"
#include "asylo/identity/sgx/platform_provisioning.pb.h"
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

sgx::CpuSvn CpuSvn() {
  sgx::CpuSvn cpu_svn;
  cpu_svn.set_value(kCpuSvn);
  return cpu_svn;
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

TEST_F(SgxInfrastructuralEnclaveManagerTest, PceGetTargetInfoSuccess) {
  sgx::Targetinfo expected_targetinfo = PceTargetinfo();
  EXPECT_CALL(*mock_intel_ae_, GetPceTargetinfo(NotNull(), NotNull()))
      .WillOnce(DoAll(SetArgPointee<0>(expected_targetinfo),
                      SetArgPointee<1>(kPceSvn), Return(Status::OkStatus())));

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
      .WillOnce(Return(Status(error::GoogleError::UNKNOWN, "Unknown")));

  sgx::TargetInfoProto pce_target_info;
  sgx::PceSvn pce_svn;
  EXPECT_THAT(sgx_infrastructural_enclave_manager_->PceGetTargetInfo(
                  &pce_target_info, &pce_svn),
              StatusIs(error::GoogleError::UNKNOWN));
}

TEST_F(SgxInfrastructuralEnclaveManagerTest, PceGetInfoSuccess) {
  EXPECT_CALL(*mock_intel_ae_,
              GetPceInfo(_, _, _, NotNull(), NotNull(), NotNull(), NotNull()))
      .WillOnce(DoAll(SetArgPointee<3>(kEncryptedPpid),
                      SetArgPointee<4>(kPceSvn), SetArgPointee<5>(kPceId),
                      SetArgPointee<6>(sgx::SignatureSchemeToPceSignatureScheme(
                                           kPckSignatureScheme)
                                           .value()),
                      Return(Status::OkStatus())));

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
      .WillOnce(Return(Status(error::GoogleError::UNKNOWN, "Unknown")));

  sgx::ReportProto report = Report();
  asylo::AsymmetricEncryptionKeyProto ppidek = Ppidek();

  sgx::PceSvn pce_svn;
  sgx::PceId pce_id;
  asylo::SignatureScheme pck_signature_scheme;
  std::string encrypted_ppid;
  EXPECT_THAT(sgx_infrastructural_enclave_manager_->PceGetInfo(
                  report, ppidek, &pce_svn, &pce_id, &pck_signature_scheme,
                  &encrypted_ppid),
              StatusIs(error::GoogleError::UNKNOWN));
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
          DoAll(SetArgPointee<3>(PckSignature()), Return(Status::OkStatus())));

  sgx::PceSvn pck_target_pce_svn = PceSvn();
  sgx::CpuSvn pck_target_cpu_svn = CpuSvn();
  sgx::ReportProto report = Report();
  EXPECT_THAT(sgx_infrastructural_enclave_manager_->PceSignReport(
                  pck_target_pce_svn, pck_target_cpu_svn, report),
              IsOkAndHolds(EqualsProto(EcdsaSignature())));
}

TEST_F(SgxInfrastructuralEnclaveManagerTest, PceSignReportFailure) {
  EXPECT_CALL(*mock_intel_ae_, PceSignReport(_, _, _, _))
      .WillOnce(Return(Status(error::GoogleError::UNKNOWN, "Unknown")));

  sgx::PceSvn pck_target_pce_svn = PceSvn();
  sgx::CpuSvn pck_target_cpu_svn = CpuSvn();
  sgx::ReportProto report = Report();
  EXPECT_THAT(
      sgx_infrastructural_enclave_manager_
          ->PceSignReport(pck_target_pce_svn, pck_target_cpu_svn, report)
          .status(),
      StatusIs(error::GoogleError::UNKNOWN));
}

TEST_F(SgxInfrastructuralEnclaveManagerTest, PceSignReportWithBadPceSvnFails) {
  // Uninitialized.
  sgx::PceSvn pck_target_pce_svn;
  sgx::CpuSvn pck_target_cpu_svn = CpuSvn();
  sgx::ReportProto report = Report();
  EXPECT_THAT(
      sgx_infrastructural_enclave_manager_
          ->PceSignReport(pck_target_pce_svn, pck_target_cpu_svn, report)
          .status(),
      Not(IsOk()));
}

TEST_F(SgxInfrastructuralEnclaveManagerTest, PceSignReportWithBadCpuSvnFails) {
  sgx::PceSvn pck_target_pce_svn = PceSvn();
  // Uninitialized.
  sgx::CpuSvn pck_target_cpu_svn;
  sgx::ReportProto report = Report();
  EXPECT_THAT(
      sgx_infrastructural_enclave_manager_
          ->PceSignReport(pck_target_pce_svn, pck_target_cpu_svn, report)
          .status(),
      Not(IsOk()));
}

TEST_F(SgxInfrastructuralEnclaveManagerTest, PceSignWithBadReportFails) {
  sgx::PceSvn pck_target_pce_svn = PceSvn();
  sgx::CpuSvn pck_target_cpu_svn = CpuSvn();
  // Uninitialized.
  sgx::ReportProto report;
  EXPECT_THAT(
      sgx_infrastructural_enclave_manager_
          ->PceSignReport(pck_target_pce_svn, pck_target_cpu_svn, report)
          .status(),
      Not(IsOk()));
}

}  // namespace
}  // namespace asylo
