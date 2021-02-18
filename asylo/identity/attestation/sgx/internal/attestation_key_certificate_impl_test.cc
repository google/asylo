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
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/time/time.h"
#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/certificate.pb.h"
#include "asylo/crypto/certificate_interface.h"
#include "asylo/crypto/ecdsa_p256_sha256_signing_key.h"
#include "asylo/crypto/fake_certificate.h"
#include "asylo/crypto/keys.pb.h"
#include "asylo/crypto/signing_key.h"
#include "asylo/crypto/x509_certificate.h"
#include "asylo/identity/additional_authenticated_data_generator.h"
#include "asylo/identity/attestation/sgx/internal/attestation_key.pb.h"
#include "asylo/identity/attestation/sgx/internal/attestation_key_certificate.pb.h"
#include "asylo/identity/platform/sgx/internal/identity_key_management_structs.h"
#include "asylo/identity/platform/sgx/sgx_identity.pb.h"
#include "asylo/identity/provisioning/sgx/internal/platform_provisioning.h"
#include "asylo/test/util/proto_matchers.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace sgx {
namespace {

using ::testing::Eq;
using ::testing::IsFalse;
using ::testing::Optional;

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
    "3059301306072a8648ce3d020106082a8648ce3d030107034200044ed53c3c04981028bc33"
    "cc9dacb34e7e39115c09b20f6fd71af082978e8edd62e9a31f700031d140ace832f33a2683"
    "464b51b5acd85654f52602f2b7d8ea8b5d";

// The attestation public key is DER-encoded.
constexpr char kTestAttestationKeyCertificateDerKeyHex[] =
    "0ab3030ab00300000000000000000000000000000000010000000000000000000000000000"
    "000000000000000000000000000000000035000000000000003f0000000000000093136c09"
    "7359f6fa329a765cbfed1c47de2bcc2ea85c35c826cff2de9d3860d8000000000000000000"
    "0000000000000000000000000000000000000000000000c81210c60d3935b097b706111d57"
    "0661ccf84c95183ae2f02a25feef8c80b00f00000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000023bd1205000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000013c28729d2e054"
    "0c57e401c896babbfd142a607a610c2975b8ae49f89330698f000000000000000000000000"
    "000000004153594c4f205349474e5245504f52540000000000000000000000000000000000"
    "000000000000000000000000000000e0ae182f6a886b324127d4d4c1ab5e8712dd010ac401"
    "0a63080210011802225b3059301306072a8648ce3d020106082a8648ce3d03010703420004"
    "4ed53c3c04981028bc33cc9dacb34e7e39115c09b20f6fd71af082978e8edd62e9a31f7000"
    "31d140ace832f33a2683464b51b5acd85654f52602f2b7d8ea8b5d1230417373657274696f"
    "6e2047656e657261746f7220456e636c617665204174746573746174696f6e204b65792076"
    "302e311a2b417373657274696f6e2047656e657261746f7220456e636c6176652041747465"
    "73746174696f6e204b65791214504345205369676e205265706f72742076302e311a480801"
    "12440a2044eea6fd8ac2a3776f7e5e2dfb4f20a941a6bf7096fb3eb3e4835112b39301f312"
    "208f4ed097226251debb3fb38fb3b2130daf3dbcae5702b3dfa1f34d57b9d3284d";

// The PCK Certificate that signed |kRealAttestationKeyCertificate|.
constexpr char kRealPckCertificatePem[] = R"proto(
-----BEGIN CERTIFICATE-----
MIIEgjCCBCegAwIBAgIVAJ1mxDIzAXa+ixcUKKaUmyYxoyJlMAoGCCqGSM49BAMC
MHExIzAhBgNVBAMMGkludGVsIFNHWCBQQ0sgUHJvY2Vzc29yIENBMRowGAYDVQQK
DBFJbnRlbCBDb3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNV
BAgMAkNBMQswCQYDVQQGEwJVUzAeFw0yMDA0MDYyMzA0NTRaFw0yNzA0MDYyMzA0
NTRaMHAxIjAgBgNVBAMMGUludGVsIFNHWCBQQ0sgQ2VydGlmaWNhdGUxGjAYBgNV
BAoMEUludGVsIENvcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkG
A1UECAwCQ0ExCzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
F7aCJQzGR7R/oeDkuyiFhknVXV4mKl72QUCD+02CS+a0AUnJtKz37EmAyd5afJ38
dFswPFL1upLY7yrEco993qOCApswggKXMB8GA1UdIwQYMBaAFNDoqtp11/kuSReY
PHsUZdDV8llNMF8GA1UdHwRYMFYwVKBSoFCGTmh0dHBzOi8vYXBpLnRydXN0ZWRz
ZXJ2aWNlcy5pbnRlbC5jb20vc2d4L2NlcnRpZmljYXRpb24vdjEvcGNrY3JsP2Nh
PXByb2Nlc3NvcjAdBgNVHQ4EFgQUFBTkM8dooH85tY3YGlV1MtZs1zEwDgYDVR0P
AQH/BAQDAgbAMAwGA1UdEwEB/wQCMAAwggHUBgkqhkiG+E0BDQEEggHFMIIBwTAe
BgoqhkiG+E0BDQEBBBB7l753xi1CRsYD0PTxGzG7MIIBZAYKKoZIhvhNAQ0BAjCC
AVQwEAYLKoZIhvhNAQ0BAgECAQUwEAYLKoZIhvhNAQ0BAgICAQUwEAYLKoZIhvhN
AQ0BAgMCAQIwEAYLKoZIhvhNAQ0BAgQCAQQwEAYLKoZIhvhNAQ0BAgUCAQEwEQYL
KoZIhvhNAQ0BAgYCAgCAMBAGCyqGSIb4TQENAQIHAgEAMBAGCyqGSIb4TQENAQII
AgEAMBAGCyqGSIb4TQENAQIJAgEAMBAGCyqGSIb4TQENAQIKAgEAMBAGCyqGSIb4
TQENAQILAgEAMBAGCyqGSIb4TQENAQIMAgEAMBAGCyqGSIb4TQENAQINAgEAMBAG
CyqGSIb4TQENAQIOAgEAMBAGCyqGSIb4TQENAQIPAgEAMBAGCyqGSIb4TQENAQIQ
AgEAMBAGCyqGSIb4TQENAQIRAgEHMB8GCyqGSIb4TQENAQISBBAFBQIEAYAAAAAA
AAAAAAAAMBAGCiqGSIb4TQENAQMEAgAAMBQGCiqGSIb4TQENAQQEBgCQbqEAADAP
BgoqhkiG+E0BDQEFCgEAMAoGCCqGSM49BAMCA0kAMEYCIQDJhxrvcvf4lr6xDYWB
ZxA73WFR4tq1SPkia6FI7YMR0gIhAIIEy0jpvDsHPftPQE/or/O+ZEzdwpIHPltk
aYbM6iTW
-----END CERTIFICATE-----
)proto";

// An Attestation key certificate using data generated by a PCE for a machine.
constexpr char kRealAttestationKeyCertificateHex[] =
    "080312e0050ab3030ab003050e020401800000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000150000000000000007000000000000"
    "00e68366df3152d42bd2fbed5e9642c442f176228369d9f2486a39a739d3ab014600000000"
    "0000000000000000000000000000000000000000000000000000000083d719e77deaca1470"
    "f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e0000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000000066e2"
    "271ac13e0781b42d84becbaa03a218bdfd83d6280e04fe16619b4912116800000000000000"
    "0000000000000000004153594c4f205349474e5245504f52548745c5174ea57419621c69a0"
    "d290ab4700000000000000000000000000000000bdf1a4cd7e193d04772fd71df846edf312"
    "dd010ac4010a63080210011802225b3059301306072a8648ce3d020106082a8648ce3d0301"
    "07034200045ae229d04c8b27e304d9ef468ca504f5e37a059eed71f2cc4165de7fda67d3c6"
    "5c93904987fb88566b4c99e101f868f022bb68f3fcae1f0f6d0725fc3e48d9e71230417373"
    "657274696f6e2047656e657261746f7220456e636c617665204174746573746174696f6e20"
    "4b65792076302e311a2b417373657274696f6e2047656e657261746f7220456e636c617665"
    "204174746573746174696f6e204b65791214504345205369676e205265706f72742076302e"
    "311a48080112440a201fbd7b2d85b4e9af4147b5263c74faf84764fe21030dd2dae61eda4f"
    "c7bbfa841220966e02ef943b87b20eec19855a6f6a656ccaed102cfb42495e9e792f921d75"
    "33";

// The SGX identity asserted by |kTestAttestationKeyCertificateDerKeyHex|.
constexpr char kTestAttestationKeyAssertedIdentity[] = R"pb(
  code_identity {
    mrenclave {
      hash: "\223\023l\tsY\366\3722\232v\\\277\355\034G\336+\314.\250\\5\310&\317\362\336\2358`\330"
    }
    signer_assigned_identity {
      mrsigner {
        hash: "\310\022\020\306\r95\260\227\267\006\021\035W\006a\314\370L\225\030:\342\360*%\376\357\214\200\260\017"
      }
      isvprodid: 48419
      isvsvn: 1298
    }
    miscselect: 1
    attributes { flags: 53 xfrm: 63 }
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
    "000000000000000000000000000000000035000000000000003f0000000000000093136c09"
    "7359f6fa329a765cbfed1c47de2bcc2ea85c35c826cff2de9d3860d8000000000000000000"
    "0000000000000000000000000000000000000000000000c81210c60d3935b097b706111d57"
    "0661ccf84c95183ae2f02a25feef8c80b00f00000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000023bd1205000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000ad73e44f8c3a6f"
    "4dbd0d88477766c4b4f14384076aac9f00fbe652c5b0e3e8ad000000000000000000000000"
    "000000004153594c4f205349474e5245504f52540000000000000000000000000000000000"
    "0000000000000000000000000000005c42ccf2061e1de92f2d359c6bac2cd812b6020a9d02"
    "0abb0108021001180122b2012d2d2d2d2d424547494e205055424c4943204b45592d2d2d2d"
    "2d0a4d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a304441516344516741"
    "455474553850415359454369384d387964724c4e4f666a6b5258416d790a44322f58477643"
    "436c34364f33574c706f78397741444852514b7a6f4d764d364a6f4e4753314731724e6857"
    "5650556d41764b33324f714c58513d3d0a2d2d2d2d2d454e44205055424c4943204b45592d"
    "2d2d2d2d0a1230417373657274696f6e2047656e657261746f7220456e636c617665204174"
    "746573746174696f6e204b65792076302e311a2b417373657274696f6e2047656e65726174"
    "6f7220456e636c617665204174746573746174696f6e204b65791214504345205369676e20"
    "5265706f72742076302e311a48080112440a201d5894b9c7748da401fae5bb9160905f3b61"
    "de58892a6747957fe576843b347a122042060e233bbf90acf437d03505acb3b42205002c2e"
    "369abc0dd1070d9b75be9c";

StatusOr<Certificate> ModifyAndSerializeAkCert(
    const PceSignReportPayload &pce_sign_report_payload,
    AttestationKeyCertificate ak_cert) {
  // Re-serialize the PCE payload.
  if (!pce_sign_report_payload.SerializeToString(
          ak_cert.mutable_pce_sign_report_payload())) {
    return Status(absl::StatusCode::kInternal,
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
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AttestationKeyCertificateImplTest, CreateFailsWithInvalidFormat) {
  Certificate cert;
  cert.set_format(Certificate::X509_PEM);
  cert.set_data(
      absl::HexStringToBytes(kTestAttestationKeyCertificateDerKeyHex));

  EXPECT_THAT(AttestationKeyCertificateImpl::Create(cert).status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
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
                            /*pathlength=*/absl::nullopt,
                            /*subject_name=*/absl::nullopt);

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
      /*is_ca=*/false, /*pathlength=*/absl::nullopt,
      /*subject_name=*/absl::nullopt);
  VerificationConfig config;
  EXPECT_THAT(ak_cert_impl->Verify(fake_cert, config),
              StatusIs(absl::StatusCode::kInternal));
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
              StatusIs(absl::StatusCode::kInvalidArgument));
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
              StatusIs(absl::StatusCode::kInvalidArgument));
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
              StatusIs(absl::StatusCode::kInvalidArgument));
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
              StatusIs(absl::StatusCode::kInvalidArgument));
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
              StatusIs(absl::StatusCode::kInvalidArgument));
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
      /*is_ca=*/false, /*pathlength=*/absl::nullopt,
      /*subject_name=*/absl::nullopt);
  VerificationConfig config;
  ASYLO_EXPECT_OK(ak_cert_impl->Verify(fake_cert, config));
}

TEST(AttestationKeyCertificateImplTest, VerifyRealAKCert) {
  Certificate ak_cert_proto;
  ak_cert_proto.ParseFromString(
      absl::HexStringToBytes(kRealAttestationKeyCertificateHex));
  std::unique_ptr<AttestationKeyCertificateImpl> ak_cert_impl;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      ak_cert_impl, AttestationKeyCertificateImpl::Create(ak_cert_proto));

  AttestationKeyCertificate ak_cert;
  ak_cert.ParseFromString(ak_cert_proto.data());

  Certificate pck_cert_proto;
  pck_cert_proto.set_format(Certificate::X509_PEM);
  pck_cert_proto.set_data(kRealPckCertificatePem);

  std::unique_ptr<X509Certificate> pck_cert;
  ASYLO_ASSERT_OK_AND_ASSIGN(pck_cert, X509Certificate::Create(pck_cert_proto));

  VerificationConfig config(/*all_fields=*/true);
  ASYLO_EXPECT_OK(ak_cert_impl->Verify(*pck_cert, config));
}

TEST(AttestationKeyCertificateImplTest, VerifyFixedAccessorValues) {
  Certificate cert;
  cert.set_format(Certificate::SGX_ATTESTATION_KEY_CERTIFICATE);
  cert.set_data(
      absl::HexStringToBytes(kTestAttestationKeyCertificateDerKeyHex));

  std::unique_ptr<AttestationKeyCertificateImpl> ak_cert_impl;
  ASYLO_ASSERT_OK_AND_ASSIGN(ak_cert_impl,
                             AttestationKeyCertificateImpl::Create(cert));
  EXPECT_THAT(ak_cert_impl->SubjectName(), Eq(absl::nullopt));
  EXPECT_THAT(ak_cert_impl->IsCa(), Optional(IsFalse()));
  EXPECT_THAT(ak_cert_impl->CertPathLength(), Eq(absl::nullopt));
  EXPECT_THAT(ak_cert_impl->KeyUsage(), Eq(absl::nullopt));
  EXPECT_THAT(ak_cert_impl->WithinValidityPeriod(absl::Now()),
              IsOkAndHolds(true));
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
              StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace
}  // namespace sgx
}  // namespace asylo
