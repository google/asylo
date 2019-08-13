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

#include "asylo/identity/sgx/pck_certificates.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/strings/str_cat.h"
#include "asylo/crypto/certificate.pb.h"
#include "asylo/util/logging.h"
#include "asylo/identity/sgx/pck_certificates.pb.h"
#include "asylo/identity/sgx/platform_provisioning.h"
#include "asylo/identity/sgx/platform_provisioning.pb.h"
#include "asylo/identity/sgx/tcb.pb.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status.h"

namespace asylo {
namespace sgx {
namespace {

// Returns a valid PckCertificates message with |length| certs.
PckCertificates CreateValidPckCertificates(int length) {
  CHECK_LE(length, kPceSvnMaxValue);
  PckCertificates pck_certificates;
  for (int i = 0; i < length; ++i) {
    PckCertificates::PckCertificateInfo *cert_info =
        pck_certificates.add_certs();
    cert_info->mutable_tcb_level()->set_components("0123456789abcdef");
    cert_info->mutable_tcb_level()->mutable_pce_svn()->set_value(i);
    cert_info->mutable_tcbm()->mutable_cpu_svn()->set_value("0123456789abcdef");
    cert_info->mutable_tcbm()->mutable_pce_svn()->set_value(i);
    cert_info->mutable_cert()->set_format(asylo::Certificate::X509_PEM);
    cert_info->mutable_cert()->set_data(absl::StrCat("Certificate(", i, ")"));
  }
  return pck_certificates;
}

TEST(PckCertificatesTest, PckCertificateInfoWithoutTcbLevelIsInvalid) {
  PckCertificates pck_certificates = CreateValidPckCertificates(1);
  pck_certificates.mutable_certs(0)->clear_tcb_level();
  EXPECT_THAT(ValidatePckCertificates(pck_certificates),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(PckCertificatesTest, PckCertificateInfoWithInvalidTcbLevelIsInvalid) {
  PckCertificates pck_certificates = CreateValidPckCertificates(1);
  pck_certificates.mutable_certs(0)->mutable_tcb_level()->set_components("");
  EXPECT_THAT(ValidatePckCertificates(pck_certificates),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(PckCertificatesTest, PckCertificateInfoWithoutTcbmIsInvalid) {
  PckCertificates pck_certificates = CreateValidPckCertificates(1);
  pck_certificates.mutable_certs(0)->clear_tcbm();
  EXPECT_THAT(ValidatePckCertificates(pck_certificates),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(PckCertificatesTest, PckCertificateInfoWithInvalidTcbmIsInvalid) {
  PckCertificates pck_certificates = CreateValidPckCertificates(1);
  pck_certificates.mutable_certs(0)->mutable_tcbm()->clear_cpu_svn();
  EXPECT_THAT(ValidatePckCertificates(pck_certificates),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(PckCertificatesTest, PckCertificateInfoWithoutCertIsInvalid) {
  PckCertificates pck_certificates = CreateValidPckCertificates(1);
  pck_certificates.mutable_certs(0)->clear_cert();
  EXPECT_THAT(ValidatePckCertificates(pck_certificates),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(PckCertificatesTest, PckCertificateInfoWithInvalidCertIsInvalid) {
  PckCertificates pck_certificates = CreateValidPckCertificates(1);
  pck_certificates.mutable_certs(0)->mutable_cert()->set_format(
      asylo::Certificate::UNKNOWN);
  EXPECT_THAT(ValidatePckCertificates(pck_certificates),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(PckCertificatesTest, PckCertificateInfoWithDifferingPceSvnsIsInvalid) {
  PckCertificates pck_certificates = CreateValidPckCertificates(1);
  pck_certificates.mutable_certs(0)
      ->mutable_tcbm()
      ->mutable_pce_svn()
      ->set_value(29);
  EXPECT_THAT(ValidatePckCertificates(pck_certificates),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(PckCertificatesTest,
     PckCertificatesWithDistinctEntriesWithSameTcbLevelIsInvalid) {
  PckCertificates pck_certificates = CreateValidPckCertificates(2);
  *pck_certificates.mutable_certs(1)->mutable_tcb_level() =
      pck_certificates.certs(0).tcb_level();
  EXPECT_THAT(ValidatePckCertificates(pck_certificates),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(PckCertificatesTest,
     PckCertificatesWithDistinctEntriesWithSameTcbmIsInvalid) {
  PckCertificates pck_certificates = CreateValidPckCertificates(2);
  *pck_certificates.mutable_certs(1)->mutable_tcbm() =
      pck_certificates.certs(0).tcbm();
  EXPECT_THAT(ValidatePckCertificates(pck_certificates),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(PckCertificatesTest, ValidPckCertificatesIsValid) {
  ASYLO_EXPECT_OK(ValidatePckCertificates(CreateValidPckCertificates(0)));
  ASYLO_EXPECT_OK(ValidatePckCertificates(CreateValidPckCertificates(1)));
  ASYLO_EXPECT_OK(ValidatePckCertificates(CreateValidPckCertificates(74)));
}

TEST(PckCertificatesTest, PckCertificatesWithRepeatedEntriesIsValid) {
  PckCertificates pck_certificates = CreateValidPckCertificates(1);
  *pck_certificates.add_certs() = pck_certificates.certs(0);
  ASYLO_EXPECT_OK(ValidatePckCertificates(pck_certificates));
}

}  // namespace
}  // namespace sgx
}  // namespace asylo
