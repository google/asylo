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

#include <functional>
#include <memory>
#include <string>

#include <google/protobuf/text_format.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/strings/string_view.h"
#include "absl/time/clock.h"
#include "absl/types/span.h"
#include "asylo/crypto/certificate.pb.h"
#include "asylo/crypto/certificate_interface.h"
#include "asylo/crypto/certificate_util.h"
#include "asylo/crypto/ecdsa_p256_sha256_signing_key.h"
#include "asylo/crypto/signing_key.h"
#include "asylo/crypto/x509_certificate.h"
#include "asylo/identity/platform/sgx/machine_configuration.pb.h"
#include "asylo/test/util/proto_matchers.h"
#include "asylo/test/util/status_matchers.h"

namespace asylo {
namespace sgx {
namespace {

using ::testing::Ge;
using ::testing::Le;
using ::testing::TestWithParam;
using ::testing::Values;

// A test fixture for a single CertificateAndPrivateKey.
class FakeSgxPkiTest : public TestWithParam<const CertificateAndPrivateKey *> {
 protected:
  void SetUp() override {
    ASYLO_ASSERT_OK_AND_ASSIGN(certificate_, X509Certificate::CreateFromPem(
                                                 GetParam()->certificate_pem));
    ASYLO_ASSERT_OK_AND_ASSIGN(
        signing_key_,
        EcdsaP256Sha256SigningKey::CreateFromPem(GetParam()->signing_key_pem));
  }

  std::unique_ptr<CertificateInterface> certificate_;
  std::unique_ptr<SigningKey> signing_key_;
};

TEST_P(FakeSgxPkiTest, CertIsWithinValidityPeriod) {
  X509Validity validity;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      validity,
      CHECK_NOTNULL(dynamic_cast<X509Certificate *>(certificate_.get()))
          ->GetValidity());
  EXPECT_THAT(absl::Now(), Ge(validity.not_before));
  EXPECT_THAT(absl::Now(), Le(validity.not_after));
}

TEST_P(FakeSgxPkiTest, CertsIsForVerifyingKeyOfGivenSigningKey) {
  std::unique_ptr<VerifyingKey> expected_subject_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(expected_subject_key,
                             signing_key_->GetVerifyingKey());

  std::string subject_key_der;
  ASYLO_ASSERT_OK_AND_ASSIGN(subject_key_der, certificate_->SubjectKeyDer());
  std::unique_ptr<VerifyingKey> actual_subject_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      actual_subject_key,
      EcdsaP256Sha256VerifyingKey::CreateFromDer(subject_key_der));

  EXPECT_TRUE(*actual_subject_key == *expected_subject_key);
}

INSTANTIATE_TEST_SUITE_P(AllCertsAndSigningKeys, FakeSgxPkiTest,
                         Values(&kFakeSgxRootCa, &kFakeSgxPlatformCa,
                                &kFakeSgxProcessorCa, &kFakeSgxTcbSigner,
                                &kFakeSgxPck));

// A test fixture for a chain of CertificateAndPrivateKeys.
class FakeSgxPkiChainsTest
    : public TestWithParam<absl::Span<const CertificateAndPrivateKey *>> {
 protected:
  void SetUp() override {
    CertificateChain proto_chain;
    for (const CertificateAndPrivateKey *cert_and_key : GetParam()) {
      Certificate *certificate = proto_chain.add_certificates();
      certificate->set_format(Certificate::X509_PEM);
      certificate->set_data(cert_and_key->certificate_pem.data(),
                            cert_and_key->certificate_pem.size());
    }
    ASYLO_ASSERT_OK_AND_ASSIGN(
        chain_,
        CreateCertificateChain(
            {{Certificate::X509_PEM, X509Certificate::Create}}, proto_chain));
  }

  CertificateInterfaceVector chain_;
};

TEST_P(FakeSgxPkiChainsTest, ChainIsValid) {
  VerificationConfig config(/*all_fields=*/true);
  ASYLO_EXPECT_OK(VerifyCertificateChain(chain_, config));
}

const CertificateAndPrivateKey *kPlatformCaChain[] = {&kFakeSgxPlatformCa,
                                                      &kFakeSgxRootCa};
const CertificateAndPrivateKey *kProcessorCaChain[] = {&kFakeSgxProcessorCa,
                                                       &kFakeSgxRootCa};
const CertificateAndPrivateKey *kTcbSignerChain[] = {&kFakeSgxTcbSigner,
                                                     &kFakeSgxRootCa};
INSTANTIATE_TEST_SUITE_P(AllChains, FakeSgxPkiChainsTest,
                         Values(absl::MakeSpan(kPlatformCaChain),
                                absl::MakeSpan(kProcessorCaChain),
                                absl::MakeSpan(kTcbSignerChain)));

TEST(FakeSgxPkiKeyTest, FakePckMachineConfigurationIsValid) {
  MachineConfiguration machine_configuration;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(
      std::string(kFakePckMachineConfigurationTextProto),
      &machine_configuration));

  EXPECT_EQ(machine_configuration.sgx_type(), SgxType::STANDARD);
  EXPECT_EQ(machine_configuration.cpu_svn().value(), "A fake TCB level");
}

TEST(FakeSgxPkiKeyTest, FakePckPairIsValid) {
  std::unique_ptr<SigningKey> signing_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      signing_key,
      EcdsaP256Sha256SigningKey::CreateFromPem(kFakeSgxPck.signing_key_pem));

  std::unique_ptr<VerifyingKey> expected_verifying_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      expected_verifying_key,
      EcdsaP256Sha256VerifyingKey::CreateFromPem(kFakePckPublicPem));

  std::unique_ptr<VerifyingKey> actual_verifying_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(actual_verifying_key,
                             signing_key->GetVerifyingKey());

  EXPECT_TRUE(*actual_verifying_key == *expected_verifying_key);
}

TEST(FakeSgxPkiTest, FakeSgxRootMatchesExpectedValue) {
  Certificate expected_fake_root;
  expected_fake_root.set_format(Certificate::X509_PEM);
  expected_fake_root.set_data(kFakeSgxRootCa.certificate_pem.data(),
                              kFakeSgxRootCa.certificate_pem.size());
  EXPECT_THAT(GetFakeSgxRootCertificate(), EqualsProto(expected_fake_root));
}

TEST(FakeSgxPckCertChainTest, CertificateChainIsValid) {
  CertificateInterfaceVector certificate_chain;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      certificate_chain,
      CreateCertificateChain({{Certificate::X509_PEM, X509Certificate::Create}},
                             GetFakePckCertificateChain()));

  ASYLO_ASSERT_OK(VerifyCertificateChain(
      certificate_chain, VerificationConfig(/*all_fields=*/true)));
}

TEST(FakeSgxPckCertChainTest,
     GetFakePckCertificateChainMatchesAppendFakePckCertificateChain) {
  CertificateChain get_chain = GetFakePckCertificateChain();
  CertificateChain set_chain;
  AppendFakePckCertificateChain(&set_chain);
  EXPECT_THAT(get_chain, EqualsProto(set_chain));
}

}  // namespace
}  // namespace sgx
}  // namespace asylo
