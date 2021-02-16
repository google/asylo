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

#include "asylo/crypto/fake_certificate.h"

#include <memory>
#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/status/status.h"
#include "absl/types/optional.h"
#include "asylo/crypto/certificate.pb.h"
#include "asylo/crypto/certificate_interface.h"
#include "asylo/crypto/fake_certificate.pb.h"
#include "asylo/test/util/status_matchers.h"

namespace asylo {
namespace {

using ::testing::Eq;
using ::testing::IsTrue;
using ::testing::Optional;
using ::testing::Pointee;
using ::testing::StrEq;

TEST(FakeCertificateTest, CreateFailsWithMalformedData) {
  Certificate cert;
  cert.set_format(Certificate::X509_DER);
  cert.set_data("bad data 1-k");

  EXPECT_THAT(FakeCertificate::Create(cert),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(FakeCertificateTest, CreateSucceedsWithCorrectIncludedData) {
  FakeCertificateProto fake_cert_proto;
  fake_cert_proto.set_subject_key("f00d");
  fake_cert_proto.set_issuer_key("c0ff33");
  fake_cert_proto.set_is_ca(true);
  fake_cert_proto.set_pathlength(2);
  fake_cert_proto.set_subject_name("my name is cert");

  Certificate cert;
  cert.set_format(Certificate::X509_PEM);
  ASSERT_TRUE(fake_cert_proto.SerializeToString(cert.mutable_data()));

  std::unique_ptr<FakeCertificate> fake_cert;
  ASYLO_ASSERT_OK_AND_ASSIGN(fake_cert, FakeCertificate::Create(cert));

  EXPECT_THAT(fake_cert->SubjectKeyDer(), IsOkAndHolds("f00d"));
  EXPECT_THAT(fake_cert->CertPathLength(), Optional(2));
  EXPECT_THAT(fake_cert->IsCa(), Optional(true));
  EXPECT_THAT(fake_cert->SubjectName(), Optional(StrEq("my name is cert")));
}

TEST(FakeCertificateTest, CreateSucceedsWithCorrectOptionalData) {
  FakeCertificateProto fake_cert_proto;
  fake_cert_proto.set_subject_key("f00d");
  fake_cert_proto.set_issuer_key("c0ff33");

  Certificate cert;
  cert.set_format(Certificate::X509_PEM);
  ASSERT_TRUE(fake_cert_proto.SerializeToString(cert.mutable_data()));

  std::unique_ptr<FakeCertificate> fake_cert;
  ASYLO_ASSERT_OK_AND_ASSIGN(fake_cert, FakeCertificate::Create(cert));

  EXPECT_THAT(fake_cert->SubjectKeyDer(), IsOkAndHolds("f00d"));
  EXPECT_THAT(fake_cert->CertPathLength(), Eq(absl::nullopt));
  EXPECT_THAT(fake_cert->IsCa(), Eq(absl::nullopt));
  EXPECT_THAT(fake_cert->SubjectName(), Eq(absl::nullopt));
}

TEST(FakeCertificateTest, EqualsSuccess) {
  const std::string subject_key = "Subject key";
  const std::string issuer_key = "Issuer key";
  const absl::optional<bool> is_ca = true;
  const absl::optional<int64_t> pathlength = absl::nullopt;
  const absl::optional<std::string> subject_name = absl::nullopt;

  FakeCertificate lhs(subject_key, issuer_key, is_ca, pathlength, subject_name);
  FakeCertificate rhs(subject_key, issuer_key, is_ca, pathlength, subject_name);

  EXPECT_TRUE(lhs == rhs);
}

TEST(FakeCertificateTest, EqualsFailure) {
  FakeCertificate lhs(/*subject_key=*/"c0ff33", /*issuer_key=*/"f00d",
                      /*is_ca=*/absl::nullopt, /*pathlength=*/absl::nullopt,
                      /*subject_name=*/absl::nullopt);
  FakeCertificate rhs(/*subject_key=*/"c0c0a", /*issuer_key=*/"sm0r3s",
                      /*is_ca=*/absl::nullopt, /*pathlength=*/absl::nullopt,
                      /*subject_name=*/absl::nullopt);

  EXPECT_FALSE(lhs == rhs);
}

TEST(FakeCertificateTest, NotEqualsSuccess) {
  FakeCertificate lhs(/*subject_key=*/"c0ff33", /*issuer_key=*/"f00d",
                      /*is_ca=*/absl::nullopt, /*pathlength=*/absl::nullopt,
                      /*subject_name=*/absl::nullopt);
  FakeCertificate rhs(/*subject_key=*/"c0c0a", /*issuer_key=*/"sm0r3s",
                      /*is_ca=*/absl::nullopt, /*pathlength=*/absl::nullopt,
                      /*subject_name=*/absl::nullopt);

  EXPECT_TRUE(lhs != rhs);
}

TEST(FakeCertificateTest, NotEqualsFailure) {
  const std::string subject_key = "Subject key";
  const std::string issuer_key = "Issuer key";
  const absl::optional<bool> is_ca = true;
  const absl::optional<int64_t> pathlength = absl::nullopt;
  const absl::optional<std::string> subject_name = absl::nullopt;

  FakeCertificate lhs(subject_key, issuer_key, is_ca, pathlength, subject_name);
  FakeCertificate rhs(subject_key, issuer_key, is_ca, pathlength, subject_name);

  EXPECT_FALSE(lhs != rhs);
}

TEST(FakeCertificateTest, VerifySuccess) {
  const std::string issuer_subject_key = "c0c0a";

  FakeCertificate subject(/*subject_key=*/"c0ff33", issuer_subject_key,
                          /*is_ca=*/absl::nullopt,
                          /*pathlength=*/absl::nullopt,
                          /*subject_name=*/absl::nullopt);
  FakeCertificate issuer(issuer_subject_key, /*issuer_key=*/"f00d",
                         /*is_ca=*/absl::nullopt, /*pathlength=*/absl::nullopt,
                         /*subject_name=*/absl::nullopt);

  VerificationConfig config(/*all_fields=*/true);
  ASYLO_EXPECT_OK(subject.Verify(issuer, config));
}

TEST(FakeCertificateTest, VerifySuccessWithRootCert) {
  const std::string issuer_subject_key = "c0c0a";

  FakeCertificate subject(/*subject_key=*/"c0ff33", issuer_subject_key,
                          /*is_ca=*/absl::nullopt,
                          /*pathlength=*/absl::nullopt,
                          /*subject_name=*/absl::nullopt);
  FakeCertificate issuer(issuer_subject_key, issuer_subject_key,
                         /*is_ca=*/true, /*pathlength=*/0,
                         /*subject_name=*/"subject");

  VerificationConfig config(/*all_fields=*/true);
  ASYLO_EXPECT_OK(subject.Verify(issuer, config));
}

TEST(FakeCertificateTest, VerifyFailure) {
  FakeCertificate subject(/*subject_key=*/"c0ff33", /*issuer_key=*/"c0c0a",
                          /*is_ca=*/absl::nullopt,
                          /*pathlength=*/absl::nullopt,
                          /*subject_name=*/absl::nullopt);
  FakeCertificate issuer(/*subject_key=*/"n0tc0c0a", /*issuer_key=*/"f00d",
                         /*is_ca=*/absl::nullopt, /*pathlength=*/absl::nullopt,
                         /*subject_name=*/absl::nullopt);

  VerificationConfig config(/*all_fields=*/true);
  EXPECT_THAT(subject.Verify(subject, config),
              StatusIs(absl::StatusCode::kUnauthenticated));
}

TEST(FakeCertificateTest, ToCertificateProtoCreateRoundTrip) {
  FakeCertificate src(/*subject_key=*/"c0ff33", /*issuer_key=*/"c0c0a",
                      /*is_ca=*/true, /*pathlength=*/5,
                      /*subject_name=*/"super cert");

  Certificate certificate;
  ASYLO_ASSERT_OK_AND_ASSIGN(certificate,
                             src.ToCertificateProto(Certificate::X509_PEM));

  EXPECT_THAT(FakeCertificate::Create(certificate), IsOkAndHolds(Pointee(src)));
}

TEST(FakeCertificateTest, ToCertificateProtoFieldsMatch) {
  FakeCertificate src(/*subject_key=*/"badc0de", /*issuer_key=*/"d00d",
                      /*is_ca=*/true, /*pathlength=*/42,
                      /*subject_name=*/"this is a test");

  Certificate certificate;
  ASYLO_ASSERT_OK_AND_ASSIGN(certificate,
                             src.ToCertificateProto(Certificate::X509_PEM));

  FakeCertificateProto fake_cert;
  ASSERT_TRUE(fake_cert.ParseFromString(certificate.data()));

  EXPECT_THAT(fake_cert.subject_key(), Eq("badc0de"));
  EXPECT_THAT(fake_cert.issuer_key(), Eq("d00d"));
  EXPECT_THAT(fake_cert.pathlength(), Eq(42));
  EXPECT_THAT(fake_cert.is_ca(), IsTrue());
  EXPECT_THAT(fake_cert.subject_name(), Eq("this is a test"));
}

}  // namespace
}  // namespace asylo
