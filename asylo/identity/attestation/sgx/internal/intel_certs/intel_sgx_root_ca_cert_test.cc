/*
 *
 * Copyright 2020 Asylo authors
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

#include "asylo/identity/attestation/sgx/internal/intel_certs/intel_sgx_root_ca_cert.h"

#include <memory>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/crypto/asn1.h"
#include "asylo/crypto/certificate.pb.h"
#include "asylo/crypto/x509_certificate.h"
#include "asylo/test/util/status_matchers.h"

namespace asylo {
namespace {

X509Name GetExpectedRootIssuerName() {
  // The Intel PCK Certificate spec says that the root is "CN=Intel SGX Root CA,
  // O=Intel Corporation, L=Santa Clara, ST=CA, C=US".
  // https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_PCK_Certificate_CRL_Spec-1.1.pdf
  return {{ObjectId::CreateFromShortName("CN").value(), "Intel SGX Root CA"},
          {ObjectId::CreateFromShortName("O").value(), "Intel Corporation"},
          {ObjectId::CreateFromShortName("L").value(), "Santa Clara"},
          {ObjectId::CreateFromShortName("ST").value(), "CA"},
          {ObjectId::CreateFromShortName("C").value(), "US"}};
}

TEST(IntelSgxRootCaCertTest, IsIntelCertValidPem) {
  std::unique_ptr<X509Certificate> cert;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      cert, X509Certificate::CreateFromPem(kIntelSgxRootCaCertificate));

  X509Name issuer;
  ASYLO_ASSERT_OK_AND_ASSIGN(issuer, cert->GetIssuerName());

  X509Name subject;
  ASYLO_ASSERT_OK_AND_ASSIGN(subject, cert->GetSubjectName());

  EXPECT_EQ(issuer, subject);
  EXPECT_EQ(issuer, GetExpectedRootIssuerName());
}

TEST(IntelSgxRootCaCertTest, IntelCertProtoMatchesRawData) {
  Certificate cert = MakeIntelSgxRootCaCertificateProto();
  EXPECT_EQ(cert.format(), Certificate::X509_PEM);
  EXPECT_EQ(cert.data(), kIntelSgxRootCaCertificate);
}

}  // namespace
}  // namespace asylo
