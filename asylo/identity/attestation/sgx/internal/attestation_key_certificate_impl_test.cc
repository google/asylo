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

#include "asylo/identity/attestation/sgx/internal/attestation_key_certificate_impl.h"

#include <memory>
#include <string>

#include <google/protobuf/text_format.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/strings/escaping.h"
#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/certificate.pb.h"
#include "asylo/crypto/certificate_interface.h"
#include "asylo/crypto/ecdsa_p256_sha256_signing_key.h"
#include "asylo/crypto/fake_certificate.h"
#include "asylo/crypto/keys.pb.h"
#include "asylo/crypto/signing_key.h"
#include "asylo/identity/additional_authenticated_data_generator.h"
#include "asylo/identity/attestation/sgx/internal/attestation_key.pb.h"
#include "asylo/identity/attestation/sgx/internal/attestation_key_certificate.pb.h"
#include "asylo/identity/platform/sgx/sgx_identity.pb.h"
#include "asylo/identity/provisioning/sgx/internal/platform_provisioning.h"
#include "asylo/identity/sgx/identity_key_management_structs.h"
#include "asylo/test/util/proto_matchers.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace sgx {
namespace {

using ::testing::Eq;

constexpr char kTestSigningIssuerKeyDerHex[] =
    "3077020101042058074ece9f20068fba38b3dd32febed75e9a3c54c7cd320d4d47ca45c9f2"
    "7d60a00a06082a8648ce3d030107a144034200049093de86699e3953f3cfe3107f6f8808cf"
    "82a59bd016aec0343615922fda73f8cb12018928048812d4b73b765a769d1cd6798487d3ba"
    "a861f3d8729e27050473";

constexpr char kTestVerifyingIssuerKeyDerHex[] =
    "3059301306072a8648ce3d020106082a8648ce3d030107034200049093de86699e3953f3cf"
    "e3107f6f8808cf82a59bd016aec0343615922fda73f8cb12018928048812d4b73b765a769d"
    "1cd6798487d3baa861f3d8729e27050473";

constexpr char kTestVerifyingSubjectKeyDerHex[] =
    "3059301306072a8648ce3d020106082a8648ce3d03010703420004bb69f2e901d926d9d7e7"
    "469d690176f904148b96887e890e5bb1b21c6018c85333f65500ca2699d4702ec98986cc0c"
    "10a0ff13ae37517aae3926328c3f0b8268";

// The attestation public key is DER-encoded.
constexpr char kTestAttestationKeyCertificateDerKeyHex[] =
    "0ab3030ab00300000000000000000000000000000000010000000000000000000000000000"
    "000000000000000000000000000000000027000000000000002700000000000000b0f58825"
    "c26d5277c20aaaef3b3493aafcef70f36957b3d90712ee2c96b3f652000000000000000000"
    "0000000000000000000000000000000000000000000000bdf1e39990510cf9429fae5fa64b"
    "6cd39a67c99958a0103ba9be7948aae7de0c00000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000"
    "0000001e2c389c000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000164dc4494a164c"
    "30afafb33f4bbbef77506c65b1d48fe4a47729594a86e2affa000000000000000000000000"
    "000000004153594c4f205349474e5245504f52540000000000000000000000000000000000"
    "000000000000000000000000000000e2543dbcb2c76a13001e0a9aa072526912dd010ac401"
    "0a63080210011802225b3059301306072a8648ce3d020106082a8648ce3d03010703420004"
    "bb69f2e901d926d9d7e7469d690176f904148b96887e890e5bb1b21c6018c85333f65500ca"
    "2699d4702ec98986cc0c10a0ff13ae37517aae3926328c3f0b82681230417373657274696f"
    "6e2047656e657261746f7220456e636c617665204174746573746174696f6e204b65792076"
    "302e311a2b417373657274696f6e2047656e657261746f7220456e636c6176652041747465"
    "73746174696f6e204b65791214504345205369676e205265706f72742076302e311a480801"
    "12440a20a6a6e3bf578aa7bb236bae4cf90eb2d69ce703c35354c860826f8a8d424d9b7d12"
    "20b375ee4ba12e616889ebb0ad47489c73c7977fa053c40476c2ee9852f1279d51";

// The SGX identity asserted by the above certificate.
constexpr char kTestAttestationKeyAssertedIdentity[] = R"pb(
  code_identity {
    mrenclave {
      hash: "\xb0\xf5\x88\x25\xc2\x6d\x52\x77\xc2\x0a\xaa\xef\x3b\x34\x93\xaa\xfc\xef\x70\xf3\x69\x57\xb3\xd9\x07\x12\xee\x2c\x96\xb3\xf6\x52"
    }
    signer_assigned_identity {
      mrsigner {
        hash: "\xbd\xf1\xe3\x99\x90\x51\x0c\xf9\x42\x9f\xae\x5f\xa6\x4b\x6c\xd3\x9a\x67\xc9\x99\x58\xa0\x10\x3b\xa9\xbe\x79\x48\xaa\xe7\xde\x0c"
      }
      isvprodid: 11294
      isvsvn: 39992
    }
    miscselect: 1
    attributes { flags: 39 xfrm: 39 }
  }
  machine_configuration {
    cpu_svn {
      value: "\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000"
    }
  }
)pb";

// The attestation public key is PEM-encoded.
constexpr char kTestAttestationKeyCertificatePemKeyHex[] =
    "0ab3030ab00300000000000000000000000000000000010000000000000000000000000000"
    "000000000000000000000000000000000027000000000000002700000000000000b0f58825"
    "c26d5277c20aaaef3b3493aafcef70f36957b3d90712ee2c96b3f652000000000000000000"
    "0000000000000000000000000000000000000000000000bdf1e39990510cf9429fae5fa64b"
    "6cd39a67c99958a0103ba9be7948aae7de0c00000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000"
    "0000001e2c389c000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000071c2f37026e7d7"
    "248031d6fd9da79d77a1e698ebcc80066c6cb67fe87633fdda000000000000000000000000"
    "000000004153594c4f205349474e5245504f52540000000000000000000000000000000000"
    "000000000000000000000000000000d242f9ba79c1575a4eeb310500c7e46612b5020a9c02"
    "0aba0108021001180122b1012d2d2d2d2d424547494e205055424c4943204b45592d2d2d2d"
    "2d0a4d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a304441516344516741"
    "4575326e793651485a4a746e5835306164615146322b515155693561490a666f6b4f573747"
    "794847415979464d7a396c55417969615a3148417579596d477a4177516f503854726a6452"
    "657134354a6a4b4d5077754361413d3d0a2d2d2d2d2d454e44205055424c4943204b45592d"
    "2d2d2d2d1230417373657274696f6e2047656e657261746f7220456e636c61766520417474"
    "6573746174696f6e204b65792076302e311a2b417373657274696f6e2047656e657261746f"
    "7220456e636c617665204174746573746174696f6e204b65791214504345205369676e2052"
    "65706f72742076302e311a48080112440a20096bce1ef93334c2c3b30b223b034d875e2b77"
    "11ac9811d95c6f5da07365a3401220659d78530a9349f995356286ff80a9a97ab9ee18bdf3"
    "f9beccf821864e55ee82";

StatusOr<Certificate> ModifyAndSerializeAkCert(
    const PceSignReportPayload &pce_sign_report_payload,
    AttestationKeyCertificate ak_cert) {
  // Re-serialize the PCE payload.
  if (!pce_sign_report_payload.SerializeToString(
          ak_cert.mutable_pce_sign_report_payload())) {
    return Status(error::GoogleError::INTERNAL,
                  "Could not serialize PCE Sign Report payload");
  }

  // Modify the report data of the report.
  Report report;
  ASYLO_ASSIGN_OR_RETURN(report,
                         ConvertReportProtoToHardwareReport(ak_cert.report()));
  std::unique_ptr<AdditionalAuthenticatedDataGenerator> data_generator =
      AdditionalAuthenticatedDataGenerator::CreatePceSignReportAadGenerator();
  ASYLO_ASSIGN_OR_RETURN(
      report.body.reportdata.data,
      data_generator->Generate(pce_sign_report_payload.SerializeAsString()));
  ak_cert.mutable_report()->set_value(
      ConvertTrivialObjectToBinaryString(report));

  // Recompute the signature.
  std::unique_ptr<SigningKey> signing_key;
  ASYLO_ASSIGN_OR_RETURN(
      signing_key, EcdsaP256Sha256SigningKey::CreateFromDer(
                       absl::HexStringToBytes(kTestSigningIssuerKeyDerHex)));
  ASYLO_RETURN_IF_ERROR(
      signing_key->Sign(ak_cert.report().value(), ak_cert.mutable_signature()));

  return CreateAttestationKeyCertificate(
      std::move(*ak_cert.mutable_report()),
      std::move(*ak_cert.mutable_signature()),
      std::move(*ak_cert.mutable_pce_sign_report_payload()));
}

TEST(AttestationKeyCertificateImplTest, CreateAttestationKeyCertificate) {
  AttestationKeyCertificate ak_cert;
  ASSERT_TRUE(ak_cert.ParseFromString(
      absl::HexStringToBytes(kTestAttestationKeyCertificateDerKeyHex)));

  Certificate cert;
  ASYLO_ASSERT_OK_AND_ASSIGN(cert, CreateAttestationKeyCertificate(
                                       ak_cert.report(), ak_cert.signature(),
                                       ak_cert.pce_sign_report_payload()));

  EXPECT_THAT(cert.format(), Eq(Certificate::SGX_ATTESTATION_KEY_CERTIFICATE));

  AttestationKeyCertificate actual_ak_cert;
  ASSERT_TRUE(actual_ak_cert.ParseFromString(cert.data()));
  EXPECT_THAT(actual_ak_cert, EqualsProto(ak_cert));
}

TEST(AttestationKeyCertificateImplTest, CreateFailsWithMalformedData) {
  Certificate cert;
  cert.set_format(Certificate::SGX_ATTESTATION_KEY_CERTIFICATE);
  cert.set_data("Malformed data");

  EXPECT_THAT(AttestationKeyCertificateImpl::Create(cert).status(),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(AttestationKeyCertificateImplTest, CreateFailsWithInvalidFormat) {
  Certificate cert;
  cert.set_format(Certificate::X509_PEM);
  cert.set_data(
      absl::HexStringToBytes(kTestAttestationKeyCertificateDerKeyHex));

  EXPECT_THAT(AttestationKeyCertificateImpl::Create(cert).status(),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(AttestationKeyCertificateImplTest, CreateSuccess) {
  Certificate cert;
  cert.set_format(Certificate::SGX_ATTESTATION_KEY_CERTIFICATE);
  cert.set_data(
      absl::HexStringToBytes(kTestAttestationKeyCertificateDerKeyHex));

  ASYLO_EXPECT_OK(AttestationKeyCertificateImpl::Create(cert));
}

TEST(AttestationKeyCertificateImplTest, GetAssertedIdentitySuccess) {
  Certificate cert;
  cert.set_format(Certificate::SGX_ATTESTATION_KEY_CERTIFICATE);
  cert.set_data(
      absl::HexStringToBytes(kTestAttestationKeyCertificateDerKeyHex));

  std::unique_ptr<AttestationKeyCertificateImpl> ak_cert_impl;
  ASYLO_ASSERT_OK_AND_ASSIGN(ak_cert_impl,
                             AttestationKeyCertificateImpl::Create(cert));

  SgxIdentity identity;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(
      kTestAttestationKeyAssertedIdentity, &identity));
  EXPECT_THAT(ak_cert_impl->GetAssertedSgxIdentity(), EqualsProto(identity));
}

TEST(AttestationKeyCertificateImplTest, EqualsSuccess) {
  Certificate cert;
  cert.set_format(Certificate::SGX_ATTESTATION_KEY_CERTIFICATE);
  cert.set_data(
      absl::HexStringToBytes(kTestAttestationKeyCertificateDerKeyHex));

  std::unique_ptr<AttestationKeyCertificateImpl> ak_cert_impl;
  ASYLO_ASSERT_OK_AND_ASSIGN(ak_cert_impl,
                             AttestationKeyCertificateImpl::Create(cert));

  EXPECT_TRUE(*ak_cert_impl == *ak_cert_impl);
}

TEST(AttestationKeyCertificateImplTest, EqualsNonAkCertFailure) {
  Certificate cert;
  cert.set_format(Certificate::SGX_ATTESTATION_KEY_CERTIFICATE);
  cert.set_data(
      absl::HexStringToBytes(kTestAttestationKeyCertificateDerKeyHex));

  std::unique_ptr<AttestationKeyCertificateImpl> ak_cert_impl;
  ASYLO_ASSERT_OK_AND_ASSIGN(ak_cert_impl,
                             AttestationKeyCertificateImpl::Create(cert));

  FakeCertificate fake_cert(/*subject_key=*/"Subject key",
                            /*issuer_key=*/"Issuer key", /*is_ca=*/false,
                            /*pathlength=*/absl::nullopt);

  EXPECT_FALSE(*ak_cert_impl == fake_cert);
}

TEST(AttestationKeyCertificateImplTest, EqualsAkCertFailure) {
  Certificate lhs_cert;
  lhs_cert.set_format(Certificate::SGX_ATTESTATION_KEY_CERTIFICATE);
  lhs_cert.set_data(
      absl::HexStringToBytes(kTestAttestationKeyCertificateDerKeyHex));

  std::unique_ptr<AttestationKeyCertificateImpl> ak_cert_impl_lhs;
  ASYLO_ASSERT_OK_AND_ASSIGN(ak_cert_impl_lhs,
                             AttestationKeyCertificateImpl::Create(lhs_cert));

  Certificate rhs_cert;
  rhs_cert.set_format(Certificate::SGX_ATTESTATION_KEY_CERTIFICATE);
  rhs_cert.set_data(
      absl::HexStringToBytes(kTestAttestationKeyCertificatePemKeyHex));

  std::unique_ptr<AttestationKeyCertificateImpl> ak_cert_impl_rhs;
  ASYLO_ASSERT_OK_AND_ASSIGN(ak_cert_impl_rhs,
                             AttestationKeyCertificateImpl::Create(rhs_cert));

  EXPECT_FALSE(*ak_cert_impl_lhs == *ak_cert_impl_rhs);
}

TEST(AttestationKeyCertificateImplTest, VerifySignatureFailure) {
  Certificate cert;
  cert.set_format(Certificate::SGX_ATTESTATION_KEY_CERTIFICATE);
  cert.set_data(
      absl::HexStringToBytes(kTestAttestationKeyCertificateDerKeyHex));

  std::unique_ptr<AttestationKeyCertificateImpl> ak_cert_impl;
  ASYLO_ASSERT_OK_AND_ASSIGN(ak_cert_impl,
                             AttestationKeyCertificateImpl::Create(cert));

  FakeCertificate fake_cert(
      absl::HexStringToBytes(kTestVerifyingSubjectKeyDerHex),
      /*issuer_key=*/"Irrelevant for the test",
      /*is_ca=*/false, /*pathlength=*/absl::nullopt);
  VerificationConfig config;
  EXPECT_THAT(ak_cert_impl->Verify(fake_cert, config),
              StatusIs(error::GoogleError::INTERNAL));
}

TEST(AttestationKeyCertificateImplTest, CreatePcePayloadVersionFailure) {
  AttestationKeyCertificate ak_cert;
  ASSERT_TRUE(ak_cert.ParseFromString(
      absl::HexStringToBytes(kTestAttestationKeyCertificateDerKeyHex)));

  PceSignReportPayload pce_sign_report;
  ASSERT_TRUE(
      pce_sign_report.ParseFromString(ak_cert.pce_sign_report_payload()));
  pce_sign_report.set_version("Random version");

  Certificate cert;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      cert, ModifyAndSerializeAkCert(pce_sign_report, std::move(ak_cert)));

  EXPECT_THAT(AttestationKeyCertificateImpl::Create(cert),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(AttestationKeyCertificateImplTest, CreateKeyProtoVersionFailure) {
  AttestationKeyCertificate ak_cert;
  ASSERT_TRUE(ak_cert.ParseFromString(
      absl::HexStringToBytes(kTestAttestationKeyCertificateDerKeyHex)));

  PceSignReportPayload pce_sign_report;
  ASSERT_TRUE(
      pce_sign_report.ParseFromString(ak_cert.pce_sign_report_payload()));
  pce_sign_report.mutable_attestation_public_key()->set_version(
      "Random version");

  Certificate cert;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      cert, ModifyAndSerializeAkCert(pce_sign_report, std::move(ak_cert)));

  EXPECT_THAT(AttestationKeyCertificateImpl::Create(cert),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(AttestationKeyCertificateImplTest, CreateKeyProtoPurposeFailure) {
  AttestationKeyCertificate ak_cert;
  ASSERT_TRUE(ak_cert.ParseFromString(
      absl::HexStringToBytes(kTestAttestationKeyCertificateDerKeyHex)));

  PceSignReportPayload pce_sign_report;
  ASSERT_TRUE(
      pce_sign_report.ParseFromString(ak_cert.pce_sign_report_payload()));
  pce_sign_report.mutable_attestation_public_key()->set_purpose(
      "Random purpose");

  Certificate cert;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      cert, ModifyAndSerializeAkCert(pce_sign_report, std::move(ak_cert)));

  EXPECT_THAT(AttestationKeyCertificateImpl::Create(cert),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(AttestationKeyCertificateImplTest, CreateMismatchedAadFailure) {
  AttestationKeyCertificate ak_cert;
  ASSERT_TRUE(ak_cert.ParseFromString(
      absl::HexStringToBytes(kTestAttestationKeyCertificateDerKeyHex)));

  PceSignReportPayload pce_sign_report;
  ASSERT_TRUE(
      pce_sign_report.ParseFromString(ak_cert.pce_sign_report_payload()));
  pce_sign_report.mutable_attestation_public_key()
      ->mutable_attestation_public_key()
      ->set_key(kTestVerifyingIssuerKeyDerHex);
  ASSERT_TRUE(pce_sign_report.SerializeToString(
      ak_cert.mutable_pce_sign_report_payload()));

  Certificate cert;
  cert.set_format(Certificate::SGX_ATTESTATION_KEY_CERTIFICATE);
  ASSERT_TRUE(ak_cert.SerializeToString(cert.mutable_data()));

  EXPECT_THAT(AttestationKeyCertificateImpl::Create(cert),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(AttestationKeyCertificateImplTest, CreateSignatureSchemeInvalid) {
  AttestationKeyCertificate ak_cert;
  ASSERT_TRUE(ak_cert.ParseFromString(
      absl::HexStringToBytes(kTestAttestationKeyCertificateDerKeyHex)));
  ak_cert.mutable_signature()->set_signature_scheme(UNKNOWN_SIGNATURE_SCHEME);

  Certificate cert;
  cert.set_format(Certificate::SGX_ATTESTATION_KEY_CERTIFICATE);
  ASSERT_TRUE(ak_cert.SerializeToString(cert.mutable_data()));

  EXPECT_THAT(AttestationKeyCertificateImpl::Create(cert),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(AttestationKeyCertificateImplTest, VerifySuccess) {
  Certificate cert;
  cert.set_format(Certificate::SGX_ATTESTATION_KEY_CERTIFICATE);
  cert.set_data(
      absl::HexStringToBytes(kTestAttestationKeyCertificateDerKeyHex));

  std::unique_ptr<AttestationKeyCertificateImpl> ak_cert_impl;
  ASYLO_ASSERT_OK_AND_ASSIGN(ak_cert_impl,
                             AttestationKeyCertificateImpl::Create(cert));

  FakeCertificate fake_cert(
      absl::HexStringToBytes(kTestVerifyingIssuerKeyDerHex),
      /*issuer_key=*/"Irrelevant for the test",
      /*is_ca=*/false, /*pathlength=*/absl::nullopt);
  VerificationConfig config;
  ASYLO_EXPECT_OK(ak_cert_impl->Verify(fake_cert, config));
}

TEST(AttestationKeyCertificateImplTest, SubjectKeyDerCorrectValue) {
  Certificate cert;
  cert.set_format(Certificate::SGX_ATTESTATION_KEY_CERTIFICATE);
  cert.set_data(
      absl::HexStringToBytes(kTestAttestationKeyCertificateDerKeyHex));

  std::unique_ptr<AttestationKeyCertificateImpl> ak_cert_impl;
  ASYLO_ASSERT_OK_AND_ASSIGN(ak_cert_impl,
                             AttestationKeyCertificateImpl::Create(cert));

  EXPECT_THAT(
      ak_cert_impl->SubjectKeyDer(),
      IsOkAndHolds(absl::HexStringToBytes(kTestVerifyingSubjectKeyDerHex)));
}

TEST(AttestationKeyCertificateImplTest, SubjectKeyDerCorrectValueFromPem) {
  Certificate cert;
  cert.set_format(Certificate::SGX_ATTESTATION_KEY_CERTIFICATE);
  cert.set_data(
      absl::HexStringToBytes(kTestAttestationKeyCertificatePemKeyHex));

  std::unique_ptr<AttestationKeyCertificateImpl> ak_cert_impl;
  ASYLO_ASSERT_OK_AND_ASSIGN(ak_cert_impl,
                             AttestationKeyCertificateImpl::Create(cert));

  EXPECT_THAT(
      ak_cert_impl->SubjectKeyDer(),
      IsOkAndHolds(absl::HexStringToBytes(kTestVerifyingSubjectKeyDerHex)));
}

TEST(AttestationKeyCertificateImplTest, ToCertificateProtoSuccess) {
  Certificate cert;
  cert.set_format(Certificate::SGX_ATTESTATION_KEY_CERTIFICATE);
  cert.set_data(
      absl::HexStringToBytes(kTestAttestationKeyCertificatePemKeyHex));

  std::unique_ptr<AttestationKeyCertificateImpl> ak_cert_impl;
  ASYLO_ASSERT_OK_AND_ASSIGN(ak_cert_impl,
                             AttestationKeyCertificateImpl::Create(cert));

  EXPECT_THAT(ak_cert_impl->ToCertificateProto(
                  Certificate::SGX_ATTESTATION_KEY_CERTIFICATE),
              IsOkAndHolds(EqualsProto(cert)));
}

TEST(AttestationKeyCertificateImplTest, ToCertificateProtoFailure) {
  Certificate cert;
  cert.set_format(Certificate::SGX_ATTESTATION_KEY_CERTIFICATE);
  cert.set_data(
      absl::HexStringToBytes(kTestAttestationKeyCertificatePemKeyHex));

  std::unique_ptr<AttestationKeyCertificateImpl> ak_cert_impl;
  ASYLO_ASSERT_OK_AND_ASSIGN(ak_cert_impl,
                             AttestationKeyCertificateImpl::Create(cert));

  EXPECT_THAT(ak_cert_impl->ToCertificateProto(Certificate::X509_PEM),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

}  // namespace
}  // namespace sgx
}  // namespace asylo
