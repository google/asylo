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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/crypto/certificate.pb.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status.h"

namespace asylo {
namespace {

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

}  // namespace
}  // namespace asylo
