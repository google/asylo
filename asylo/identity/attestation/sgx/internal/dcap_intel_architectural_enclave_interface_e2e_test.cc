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

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/flags/flag.h"
#include "absl/memory/memory.h"
#include "asylo/client.h"
#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/certificate.pb.h"
#include "asylo/crypto/ecdsa_p256_sha256_signing_key.h"
#include "asylo/crypto/keys.pb.h"
#include "asylo/crypto/rsa_oaep_encryption_key.h"
#include "asylo/crypto/util/trivial_object_util.h"
#include "asylo/crypto/x509_certificate.h"
#include "asylo/enclave.pb.h"
#include "asylo/enclave_manager.h"
#include "asylo/identity/attestation/sgx/internal/dcap_intel_architectural_enclave_interface.h"
#include "asylo/identity/attestation/sgx/internal/dcap_intel_architectural_enclave_path_setter.h"
#include "asylo/identity/attestation/sgx/internal/host_dcap_library_interface.h"
#include "asylo/identity/attestation/sgx/internal/intel_ecdsa_quote.h"
#include "asylo/identity/attestation/sgx/internal/pce_util.h"
#include "asylo/identity/attestation/sgx/internal/report_oracle_enclave_wrapper.h"
#include "asylo/identity/platform/sgx/architecture_bits.h"
#include "asylo/identity/platform/sgx/internal/secs_attributes.h"
#include "asylo/identity/provisioning/sgx/internal/pck_certificate_util.h"
#include "asylo/identity/provisioning/sgx/internal/platform_provisioning.h"
#include "asylo/identity/provisioning/sgx/internal/platform_provisioning.pb.h"
#include "asylo/platform/primitives/sgx/loader.pb.h"
#include "asylo/test/util/memory_matchers.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/cleansing_types.h"
#include "asylo/util/proto_flag.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "QuoteGeneration/pce_wrapper/inc/sgx_pce_constants.h"
#include "QuoteVerification/Src/AttestationLibrary/include/QuoteVerification/QuoteConstants.h"

// These values must be updated along with PCE and QE releases. These are not
// exposed via any Intel headers.
constexpr uint16_t kExpectedPceId = 0;
constexpr uint16_t kExpectedPceSvn = 7;
constexpr uint16_t kExpectedQeSvn = 2;

ABSL_FLAG(std::string, report_oracle_enclave_path, "",
          "Path of DCAP test enclave to be loaded.");

ABSL_FLAG(asylo::Certificate, pck_certificate, {},
          "The PCK certificate used to verify signature from the PCE");

namespace asylo {
namespace sgx {
namespace {

namespace constants = ::intel::sgx::qvl::constants;

using ::testing::ElementsAreArray;
using ::testing::Eq;

class DcapIntelArchitecturalEnclaveInterfaceE2eTest : public ::testing::Test {
 public:
  static void SetUpTestSuite() {
    SetIntelEnclaveDirFromFlags();
    ASSERT_FALSE(absl::GetFlag(FLAGS_report_oracle_enclave_path).empty());
  }

 protected:
  StatusOr<Report> GetEnclaveReport(const Targetinfo &targetinfo,
                                    const Reportdata &reportdata) {
    std::unique_ptr<ReportOracleEnclaveWrapper> report_oracle;
    ASYLO_ASSIGN_OR_RETURN(
        report_oracle, ReportOracleEnclaveWrapper::LoadFromFile(
                           absl::GetFlag(FLAGS_report_oracle_enclave_path)));

    return report_oracle->GetReport(targetinfo, reportdata);
  }

  DcapIntelArchitecturalEnclaveInterface enclave_interface_{
      absl::make_unique<HostDcapLibraryInterface>()};
};

TEST_F(DcapIntelArchitecturalEnclaveInterfaceE2eTest, GetPceTargetinfo) {
  SecsAttributeSet expected_attributes;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      expected_attributes,
      SecsAttributeSet::FromBits({AttributeBit::INIT,
                                  AttributeBit::MODE64BIT,
                                  AttributeBit::PROVISIONKEY}));

  Targetinfo targetinfo;
  uint16_t svn;
  ASYLO_ASSERT_OK(enclave_interface_.GetPceTargetinfo(&targetinfo, &svn));

  EXPECT_THAT(svn, Eq(kExpectedPceSvn));
  EXPECT_THAT(targetinfo.attributes.flags, Eq(expected_attributes.flags));
  // Do not check targetinfo.attributes.xfrm, as the features may vary
  // from platform to platform.
}

TEST_F(DcapIntelArchitecturalEnclaveInterfaceE2eTest, GetPceInfo) {
  Targetinfo pce_targetinfo;
  uint16_t pce_svn_from_get_target_info;
  ASYLO_ASSERT_OK(enclave_interface_.GetPceTargetinfo(
      &pce_targetinfo, &pce_svn_from_get_target_info));

  std::unique_ptr<RsaOaepDecryptionKey> ppid_decryption_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      ppid_decryption_key, RsaOaepDecryptionKey::CreateRsa3072OaepDecryptionKey(
                               kPpidRsaOaepHashAlgorithm));

  AsymmetricEncryptionKeyProto ppid_ek_proto;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      ppid_ek_proto,
      ConvertToAsymmetricEncryptionKeyProto(*ppid_decryption_key));

  Reportdata reportdata;
  ASYLO_ASSERT_OK_AND_ASSIGN(reportdata,
                             CreateReportdataForGetPceInfo(ppid_ek_proto));

  Report report;
  ASYLO_ASSERT_OK_AND_ASSIGN(report,
                             GetEnclaveReport(pce_targetinfo, reportdata));

  std::vector<uint8_t> ppid_ek;
  ASYLO_ASSERT_OK_AND_ASSIGN(ppid_ek, SerializePpidek(ppid_ek_proto));

  std::string ppid_encrypted;
  uint16_t pce_svn;
  uint16_t pce_id;
  SignatureScheme signature_scheme;
  ASYLO_ASSERT_OK(enclave_interface_.GetPceInfo(
      report, ppid_ek, ppid_decryption_key->GetEncryptionScheme(),
      &ppid_encrypted, &pce_svn, &pce_id, &signature_scheme));

  EXPECT_FALSE(ppid_encrypted.empty());
  EXPECT_THAT(pce_id, Eq(kExpectedPceId));
  EXPECT_THAT(signature_scheme, Eq(SignatureScheme::ECDSA_P256_SHA256));
  EXPECT_THAT(pce_svn_from_get_target_info, Eq(pce_svn));

  CleansingVector<uint8_t> ppid_decrypted;
  ASYLO_ASSERT_OK(
      ppid_decryption_key->Decrypt(ppid_encrypted, &ppid_decrypted));
  EXPECT_THAT(ppid_decrypted.size(), Eq(kPpidSize));
}

TEST_F(DcapIntelArchitecturalEnclaveInterfaceE2eTest, PceSignReport) {
  Targetinfo pce_targetinfo;
  uint16_t pce_svn;
  EXPECT_THAT(enclave_interface_.GetPceTargetinfo(&pce_targetinfo, &pce_svn),
              IsOk());

  Reportdata reportdata;
  reportdata.data.fill('a');
  Report report;
  ASYLO_ASSERT_OK_AND_ASSIGN(report,
                             GetEnclaveReport(pce_targetinfo, reportdata));

  Certificate pck_certificate = absl::GetFlag(FLAGS_pck_certificate);
  bool cert_provided = !pck_certificate.data().empty() &&
                       pck_certificate.format() == Certificate::X509_PEM;

  std::string signature;
  if (cert_provided) {
    PceSvn pck_pce_svn;
    ASYLO_ASSERT_OK_AND_ASSIGN(pck_pce_svn,
                               ExtractPceSvnFromPckCert(pck_certificate));
    CpuSvn pck_cpu_svn;
    ASYLO_ASSERT_OK_AND_ASSIGN(pck_cpu_svn,
                               ExtractCpuSvnFromPckCert(pck_certificate));
    ASYLO_ASSERT_OK(enclave_interface_.PceSignReport(
        report, pck_pce_svn.value(), pck_cpu_svn.value(), &signature));
  } else {
    ASYLO_ASSERT_OK(enclave_interface_.PceSignReport(
        report, pce_svn, report.body.cpusvn, &signature));
  }

  ASSERT_THAT(signature.length(), Eq(kEcdsaP256SignatureSize));

  if (cert_provided) {
    std::unique_ptr<X509Certificate> pck_x509;
    ASYLO_ASSERT_OK_AND_ASSIGN(pck_x509,
                               X509Certificate::Create(pck_certificate));
    std::string pck_pub_der;
    ASYLO_ASSERT_OK_AND_ASSIGN(pck_pub_der, pck_x509->SubjectKeyDer());
    std::unique_ptr<EcdsaP256Sha256VerifyingKey> pck_pub;
    ASYLO_ASSERT_OK_AND_ASSIGN(
        pck_pub, EcdsaP256Sha256VerifyingKey::CreateFromDer(pck_pub_der));

    Signature pck_sig;
    ASYLO_ASSERT_OK_AND_ASSIGN(
        pck_sig, CreateSignatureFromPckEcdsaP256Sha256Signature(signature));

    ASYLO_ASSERT_OK(pck_pub->Verify(
        ConvertTrivialObjectToBinaryString(report.body), pck_sig));
  }
}

TEST_F(DcapIntelArchitecturalEnclaveInterfaceE2eTest, GetQeQuote) {
  Targetinfo targetinfo;
  ASYLO_ASSERT_OK_AND_ASSIGN(targetinfo, enclave_interface_.GetQeTargetinfo());

  Reportdata reportdata = TrivialRandomObject<Reportdata>();
  Report report;
  ASYLO_ASSERT_OK_AND_ASSIGN(report, GetEnclaveReport(targetinfo, reportdata));

  std::vector<uint8_t> packed_quote;
  ASYLO_ASSERT_OK_AND_ASSIGN(packed_quote,
                             enclave_interface_.GetQeQuote(report));

  IntelQeQuote quote;
  ASYLO_ASSERT_OK_AND_ASSIGN(quote, ParseDcapPackedQuote(packed_quote));

  EXPECT_THAT(quote.header.version, Eq(constants::QUOTE_VERSION));
  EXPECT_THAT(quote.header.algorithm, Eq(constants::ECDSA_256_WITH_P256_CURVE));
  EXPECT_THAT(quote.header.qesvn, Eq(kExpectedQeSvn));
  EXPECT_THAT(quote.header.pcesvn, Eq(kExpectedPceSvn));
  EXPECT_THAT(quote.header.qe_vendor_id,
              ElementsAreArray(constants::INTEL_QE_VENDOR_ID));

  EXPECT_THAT(quote.body, TrivialObjectEq(report.body));

}

}  // namespace
}  // namespace sgx
}  // namespace asylo
