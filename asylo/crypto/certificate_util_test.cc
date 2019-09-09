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

#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/memory/memory.h"
#include "absl/types/optional.h"
#include "absl/types/span.h"
#include "asylo/crypto/certificate.pb.h"
#include "asylo/crypto/certificate_interface.h"
#include "asylo/crypto/fake_certificate.h"
#include "asylo/crypto/fake_certificate.pb.h"
#include "asylo/test/util/status_matchers.h"

namespace asylo {
namespace {

constexpr char kRootKey[] = "f00d";
constexpr char kIntermediateKey[] = "c0ff33";
constexpr char kExtraIntermediateKey[] = "c0c0a";
constexpr char kEndUserKey[] = "fun";

// Data for a malformed FakeCertificate;
constexpr char kMalformedCertData[] = "food food food food";

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
  certificate.set_data("foobar");
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
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(CertificateUtilTest,
     ValidateCertificateSigningRequestReturnsErrorIfUnknownFormat) {
  CertificateSigningRequest csr = CreateValidCertificateSigningRequest();
  csr.set_format(CertificateSigningRequest::UNKNOWN);
  EXPECT_THAT(ValidateCertificateSigningRequest(csr),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(CertificateUtilTest,
     ValidateCertificateSigningRequestReturnsErrorIfNoData) {
  CertificateSigningRequest csr = CreateValidCertificateSigningRequest();
  csr.clear_data();
  EXPECT_THAT(ValidateCertificateSigningRequest(csr),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
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
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(CertificateUtilTest, ValidateCertificateReturnsErrorIfUnknownFormat) {
  Certificate certificate = CreateValidCertificate();
  certificate.set_format(Certificate::UNKNOWN);
  EXPECT_THAT(ValidateCertificate(certificate),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(CertificateUtilTest, ValidateCertificateReturnsErrorIfNoData) {
  Certificate certificate = CreateValidCertificate();
  certificate.clear_data();
  EXPECT_THAT(ValidateCertificate(certificate),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(CertificateUtilTest, ValidateCertificateSucceedsIfCertificateIsValid) {
  ASYLO_EXPECT_OK(ValidateCertificate(CreateValidCertificate()));
}

TEST(CertificateUtilTest,
     ValidateCertificateChainFailsIfAContainedCertificateIsInvalid) {
  CertificateChain certificate_chain = CreateValidCertificateChain(1);
  certificate_chain.mutable_certificates(0)->clear_format();
  EXPECT_THAT(ValidateCertificateChain(certificate_chain),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));

  certificate_chain = CreateValidCertificateChain(5);
  certificate_chain.mutable_certificates(1)->clear_format();
  EXPECT_THAT(ValidateCertificateChain(certificate_chain),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
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
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(CertificateUtilTest,
     ValidateCertificateRevocationListReturnsErrorIfUnknownFormat) {
  CertificateRevocationList crl = CreateValidCertificateRevocationList();
  crl.set_format(CertificateRevocationList::UNKNOWN);
  EXPECT_THAT(ValidateCertificateRevocationList(crl),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(CertificateUtilTest,
     ValidateCertificateRevocationListReturnsErrorIfNoData) {
  CertificateRevocationList crl = CreateValidCertificateRevocationList();
  crl.clear_data();
  EXPECT_THAT(ValidateCertificateRevocationList(crl),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
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
      /*pathlength=*/absl::nullopt));
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kIntermediateKey, kRootKey, /*is_ca=*/absl::nullopt, /*pathlength=*/0));
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kRootKey, kRootKey, /*is_ca=*/absl::nullopt, /*pathlength=*/1));

  VerificationConfig config(/*all_fields=*/true);
  ASYLO_EXPECT_OK(VerifyCertificateChain(absl::MakeConstSpan(chain), config));
}

TEST(CertificateUtilTest, VerifyCertificateChainSuccessWithoutPathLengths) {
  CertificateInterfaceVector chain;
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kEndUserKey, kIntermediateKey, /*is_ca=*/absl::nullopt,
      /*pathlength=*/absl::nullopt));
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kIntermediateKey, kRootKey, /*is_ca=*/true,
      /*pathlength=*/absl::nullopt));
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kRootKey, kRootKey,
      /*is_ca=*/false, /*pathlength=*/absl::nullopt));

  VerificationConfig config(/*all_fields=*/true);
  ASYLO_EXPECT_OK(VerifyCertificateChain(absl::MakeConstSpan(chain), config));
}

TEST(CertificateUtilTest, VerifyCertificateChainVerificationErrorForwarded) {
  CertificateInterfaceVector chain;
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kEndUserKey, kExtraIntermediateKey, /*is_ca=*/absl::nullopt,
      /*pathlength=*/absl::nullopt));
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kIntermediateKey, kRootKey, /*is_ca=*/absl::nullopt, /*pathlength=*/0));
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kRootKey, kRootKey, /*is_ca=*/absl::nullopt, /*pathlength=*/1));

  VerificationConfig config(/*all_fields=*/false);
  EXPECT_THAT(VerifyCertificateChain(absl::MakeConstSpan(chain), config),
              StatusIs(error::GoogleError::UNAUTHENTICATED));
}

TEST(CertificateUtilTest, VerifyCertificateChainBadRootPathlen) {
  CertificateInterfaceVector chain;
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kEndUserKey, kIntermediateKey, /*is_ca=*/absl::nullopt,
      /*pathlength=*/absl::nullopt));
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kIntermediateKey, kRootKey, /*is_ca=*/absl::nullopt, /*pathlength=*/0));
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kRootKey, kRootKey, /*is_ca=*/absl::nullopt, /*pathlength=*/0));

  VerificationConfig config(/*all_fields=*/true);
  EXPECT_THAT(VerifyCertificateChain(absl::MakeConstSpan(chain), config),
              StatusIs(error::GoogleError::UNAUTHENTICATED));
}

TEST(CertificateUtilTest, VerifyCertificateChainBadIntermediatePathlen) {
  CertificateInterfaceVector chain;
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kEndUserKey, kExtraIntermediateKey, /*is_ca=*/absl::nullopt,
      /*pathlength=*/absl::nullopt));
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kExtraIntermediateKey, kIntermediateKey, /*is_ca=*/absl::nullopt,
      /*pathlength=*/0));
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kIntermediateKey, kRootKey, /*is_ca=*/absl::nullopt, /*pathlength=*/0));
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kRootKey, kRootKey, /*is_ca=*/absl::nullopt, /*pathlength=*/2));

  VerificationConfig config(/*all_fields=*/true);
  EXPECT_THAT(VerifyCertificateChain(absl::MakeConstSpan(chain), config),
              StatusIs(error::GoogleError::UNAUTHENTICATED));
}

TEST(CertificateUtilTest, VerifyCertificateChainBadPathlenNoCheck) {
  CertificateInterfaceVector chain;
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kEndUserKey, kIntermediateKey, /*is_ca=*/absl::nullopt,
      /*pathlength=*/absl::nullopt));
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kIntermediateKey, kRootKey, /*is_ca=*/absl::nullopt, /*pathlength=*/0));
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kRootKey, kRootKey, /*is_ca=*/absl::nullopt, /*pathlength=*/0));

  VerificationConfig config(/*all_fields=*/false);
  ASYLO_EXPECT_OK(VerifyCertificateChain(absl::MakeConstSpan(chain), config));
}

TEST(CertificateUtilTest, VerifyCertificateChainCaValuesSet) {
  CertificateInterfaceVector chain;
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kEndUserKey, kExtraIntermediateKey, /*is_ca=*/false,
      /*pathlength=*/absl::nullopt));
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kExtraIntermediateKey, kIntermediateKey, /*is_ca=*/false,
      /*pathlength=*/absl::nullopt));
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kIntermediateKey, kRootKey, /*is_ca=*/true, /*pathlength=*/0));
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kRootKey, kRootKey, /*is_ca=*/true, /*pathlength=*/1));

  VerificationConfig config(/*all_fields=*/true);
  ASYLO_EXPECT_OK(VerifyCertificateChain(absl::MakeConstSpan(chain), config));
}

TEST(CertificateUtilTest, CreateCertificateChainMissingFormat) {
  CertificateFactoryMap factory_map = CreateFactoryMap({Certificate::X509_PEM});
  EXPECT_THAT(
      CreateCertificateChain(factory_map, TestCertificateChain()).status(),
      StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(CertificateUtilTest, CreateCertificateChainMalformedCertificate) {
  CertificateFactoryMap factory_map = CreateFactoryMap({Certificate::X509_PEM});
  CertificateChain chain;
  Certificate *malformed_cert = chain.add_certificates();
  malformed_cert->set_format(Certificate::X509_PEM);
  malformed_cert->set_data(kMalformedCertData);

  EXPECT_THAT(CreateCertificateChain(factory_map, chain).status(),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
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

}  // namespace
}  // namespace asylo
