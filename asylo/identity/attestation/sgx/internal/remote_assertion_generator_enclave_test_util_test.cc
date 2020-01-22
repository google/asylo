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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/crypto/certificate.pb.h"
#include "asylo/crypto/certificate_util.h"
#include "asylo/crypto/ecdsa_p256_sha256_signing_key.h"
#include "asylo/crypto/signing_key.h"
#include "asylo/crypto/util/trivial_object_util.h"
#include "asylo/crypto/x509_certificate.h"
#include "asylo/identity/attestation/sgx/internal/attestation_key_certificate_impl.h"
#include "asylo/identity/attestation/sgx/internal/remote_assertion_generator_enclave_util.h"
#include "asylo/identity/sgx/identity_key_management_structs.h"
#include "asylo/identity/sgx/mock_sgx_infrastructural_enclave_manager.h"
#include "asylo/test/util/proto_matchers.h"
#include "asylo/test/util/status_matchers.h"

namespace asylo {
namespace sgx {
namespace {

using ::testing::_;
using ::testing::DoAll;
using ::testing::NotNull;
using ::testing::Return;
using ::testing::SetArgPointee;

TEST(RemoteAssertionGeneratorEnclaveTestUtilTest,
     FakePckCertificateChainIsValid) {
  CertificateInterfaceVector certificate_chain;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      certificate_chain,
      CreateCertificateChain({{Certificate::X509_PEM, X509Certificate::Create}},
                             GetFakePckCertificateChain()));

  ASYLO_ASSERT_OK(VerifyCertificateChain(
      certificate_chain, VerificationConfig(/*all_fields=*/true)));
}

TEST(RemoteAssertionGeneratorEnclaveTestUtilTest,
     GetFakePckCertificateChainMatchesAppendFakePckCertificateChain) {
  CertificateChain get_chain = GetFakePckCertificateChain();
  CertificateChain set_chain;
  AppendFakePckCertificateChain(&set_chain);
  EXPECT_THAT(get_chain, EqualsProto(set_chain));
}

// The method that takes an EnclaveClient* wraps the method that takes
// SgxInfrastructuralEnclaveManager* so it is untested.

TEST(RemoteAssertionGeneratorEnclaveTestUtilTest,
     GenerateAttestationKeyAndFakeCertificateChainAgeFailure) {
  MockSgxInfrastructuralEnclaveManager manager;
  EXPECT_CALL(manager, AgeGenerateKeyAndCsr(_, NotNull(), NotNull(), _))
      .WillOnce(Return(Status(error::GoogleError::UNAVAILABLE, "Unavailable")));

  EXPECT_THAT(GenerateAttestationKeyAndFakeCertificateChain(&manager),
              StatusIs(error::GoogleError::UNAVAILABLE, "Unavailable"));
}

TEST(RemoteAssertionGeneratorEnclaveTestUtilTest,
     FakeAkCertificateChainIsValid) {
  MockSgxInfrastructuralEnclaveManager manager;

  std::unique_ptr<VerifyingKey> public_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      public_key,
      EcdsaP256Sha256SigningKey::Create().ValueOrDie()->GetVerifyingKey());
  std::string pce_sign_report_payload;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      pce_sign_report_payload,
      CreateSerializedPceSignReportPayloadFromVerifyingKey(*public_key));

  Report report;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      report.body.reportdata,
      GenerateReportdataForPceSignReportProtocol(pce_sign_report_payload));
  ReportProto report_proto;
  report_proto.set_value(ConvertTrivialObjectToBinaryString(report));

  EXPECT_CALL(manager, AgeGenerateKeyAndCsr(_, NotNull(), NotNull(), _))
      .WillOnce(DoAll(SetArgPointee<1>(report_proto),
                      SetArgPointee<2>(pce_sign_report_payload),
                      Return(Status::OkStatus())));

  CertificateChain certificate_chain_proto;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      certificate_chain_proto,
      GenerateAttestationKeyAndFakeCertificateChain(&manager));

  CertificateInterfaceVector certificate_chain;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      certificate_chain,
      CreateCertificateChain({{Certificate::X509_PEM, X509Certificate::Create},
                              {Certificate::SGX_ATTESTATION_KEY_CERTIFICATE,
                               AttestationKeyCertificateImpl::Create}},
                             certificate_chain_proto));

  ASYLO_ASSERT_OK(VerifyCertificateChain(
      certificate_chain, VerificationConfig(/*all_fields=*/true)));
}

}  // namespace
}  // namespace sgx
}  // namespace asylo
