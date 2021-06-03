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

#include "asylo/identity/provisioning/sgx/internal/fake_sgx_pcs_client.h"

#include <algorithm>
#include <cstdint>
#include <memory>
#include <string>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

#include "google/protobuf/duration.pb.h"
#include "google/protobuf/timestamp.pb.h"
#include <google/protobuf/repeated_field.h>
#include <google/protobuf/util/time_util.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "absl/types/optional.h"
#include "absl/types/span.h"
#include "asylo/crypto/asn1.h"
#include "asylo/crypto/certificate.pb.h"
#include "asylo/crypto/certificate_interface.h"
#include "asylo/crypto/certificate_util.h"
#include "asylo/crypto/ecdsa_p256_sha256_signing_key.h"
#include "asylo/crypto/signing_key.h"
#include "asylo/crypto/x509_certificate.h"
#include "asylo/util/logging.h"
#include "asylo/identity/platform/sgx/machine_configuration.pb.h"
#include "asylo/identity/provisioning/sgx/internal/fake_sgx_pki.h"
#include "asylo/identity/provisioning/sgx/internal/pck_certificate_util.h"
#include "asylo/identity/provisioning/sgx/internal/pck_certificates.pb.h"
#include "asylo/identity/provisioning/sgx/internal/platform_provisioning.pb.h"
#include "asylo/identity/provisioning/sgx/internal/sgx_pcs_client.h"
#include "asylo/identity/provisioning/sgx/internal/sgx_pcs_client.pb.h"
#include "asylo/identity/provisioning/sgx/internal/tcb.h"
#include "asylo/identity/provisioning/sgx/internal/tcb.pb.h"
#include "asylo/identity/provisioning/sgx/internal/tcb_info_from_json.h"
#include "asylo/identity/provisioning/sgx/internal/tcb_info_reader.h"
#include "asylo/test/util/proto_matchers.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status.h"
#include "asylo/util/time_conversions.h"

namespace asylo {
namespace sgx {
namespace {

using ::testing::_;
using ::testing::ContainerEq;
using ::testing::Eq;
using ::testing::Ge;
using ::testing::Gt;
using ::testing::Le;
using ::testing::Lt;
using ::testing::Ne;
using ::testing::Optional;
using ::testing::SizeIs;
using ::testing::TestWithParam;
using ::testing::Values;

// A DER-encoded ECDSA-P256 public key different from the default fake PCK key.
constexpr char kDifferentPckDerHex[] =
    "3059301306072a8648ce3d020106082a8648ce3d03010703420004eaeda5103e89194f43bf"
    "e0d844f3e79f000957fc3c9237c7ea8ddcd67e22c75cd75119ea9aa02f76cecacbbf1b2fe6"
    "1c69fc9eeada1fe29a567d6ceb468e16bd";

// Matches a TcbStatus if it is a known status and is UP_TO_DATE.
MATCHER(IsUpToDateTcbStatus,
        negation ? "isn't an UP_TO_DATE status" : "is an UP_TO_DATE status") {
  if (arg.value_case() != TcbStatus::kKnownStatus) {
    *result_listener << "which isn't a known status";
    return false;
  }
  if (arg.known_status() != TcbStatus::UP_TO_DATE) {
    *result_listener << "which is not UP_TO_DATE";
    return false;
  }
  return true;
}

// Matches a TcbStatus if it is a known status and is OUT_OF_DATE.
MATCHER(IsOutOfDateTcbStatus,
        negation ? "isn't an OUT_OF_DATE status" : "is an OUT_OF_DATE status") {
  if (arg.value_case() != TcbStatus::kKnownStatus) {
    *result_listener << "which isn't a known status";
    return false;
  }
  if (arg.known_status() != TcbStatus::OUT_OF_DATE) {
    *result_listener << "which is not OUT_OF_DATE";
    return false;
  }
  return true;
}

class FakeSgxPcsClientTest : public TestWithParam<absl::optional<std::string>> {
 protected:
  void SetUp() override {
    if (GetParam().has_value()) {
      fake_client_.emplace(GetParam().value());
    } else {
      fake_client_.emplace();
    }

    Certificate root_cert;
    root_cert.set_format(Certificate::X509_PEM);
    root_cert.set_data(kFakeSgxRootCa.certificate_pem.data(),
                       kFakeSgxRootCa.certificate_pem.size());

    Certificate *platform_ca_certificate =
        platform_ca_issuer_chain_.add_certificates();
    platform_ca_certificate->set_format(Certificate::X509_PEM);
    platform_ca_certificate->set_data(
        kFakeSgxPlatformCa.certificate_pem.data(),
        kFakeSgxPlatformCa.certificate_pem.size());
    *platform_ca_issuer_chain_.add_certificates() = root_cert;

    Certificate *processor_ca_certificate =
        processor_ca_issuer_chain_.add_certificates();
    processor_ca_certificate->set_format(Certificate::X509_PEM);
    processor_ca_certificate->set_data(
        kFakeSgxProcessorCa.certificate_pem.data(),
        kFakeSgxProcessorCa.certificate_pem.size());
    *processor_ca_issuer_chain_.add_certificates() = root_cert;

    Certificate *tcb_signing_certificate =
        tcb_info_issuer_chain_.add_certificates();
    tcb_signing_certificate->set_format(Certificate::X509_PEM);
    tcb_signing_certificate->set_data(kFakeSgxTcbSigner.certificate_pem.data(),
                                      kFakeSgxTcbSigner.certificate_pem.size());
    *tcb_info_issuer_chain_.add_certificates() = std::move(root_cert);

    std::unique_ptr<SigningKey> platform_ca_signing_key;
    ASYLO_ASSERT_OK_AND_ASSIGN(platform_ca_signing_key,
                               EcdsaP256Sha256SigningKey::CreateFromPem(
                                   kFakeSgxPlatformCa.signing_key_pem));
    ASYLO_ASSERT_OK_AND_ASSIGN(platform_ca_verifying_key_,
                               platform_ca_signing_key->GetVerifyingKey());

    std::unique_ptr<SigningKey> processor_ca_signing_key;
    ASYLO_ASSERT_OK_AND_ASSIGN(processor_ca_signing_key,
                               EcdsaP256Sha256SigningKey::CreateFromPem(
                                   kFakeSgxProcessorCa.signing_key_pem));
    ASYLO_ASSERT_OK_AND_ASSIGN(processor_ca_verifying_key_,
                               processor_ca_signing_key->GetVerifyingKey());

    std::unique_ptr<SigningKey> tcb_info_signing_key;
    ASYLO_ASSERT_OK_AND_ASSIGN(tcb_info_signing_key,
                               EcdsaP256Sha256SigningKey::CreateFromPem(
                                   kFakeSgxTcbSigner.signing_key_pem));
    ASYLO_ASSERT_OK_AND_ASSIGN(tcb_info_verifying_key_,
                               tcb_info_signing_key->GetVerifyingKey());

    platform_properties_.ca = SgxCaType::PROCESSOR;
    platform_properties_.pce_id.set_value(0);
  }

  // Checks that |certificate| is valid under |issuer_chain|, matches the SGX
  // PCK certificate specification to the degree guaranteed by FakeSgxPcsClient,
  // and contains SGX extensions that reflect |expected_ppid|, |expected_tcb|,
  // |expected_cpu_svn|, |expected_fmspc|, and |expected_platform|.
  //
  // If |expected_ppid| is absl::nullopt, then the PPID in the SGX extensions is
  // not checked.
  void VerifyPckCertificate(
      const Certificate &certificate, const CertificateChain &issuer_chain,
      const absl::optional<Ppid> &expected_ppid, const Tcb &expected_tcb,
      const CpuSvn &expected_cpu_svn, const Fmspc &expected_fmspc,
      const FakeSgxPcsClient::PlatformProperties &expected_platform) {
    static const ObjectId *kCommonNameOid =
        new ObjectId(ObjectId::CreateFromShortName("CN").value());
    static const std::string *kFakePckPublicDer = new std::string(
        EcdsaP256Sha256VerifyingKey::CreateFromPem(kFakePckPublicPem)
            .value()
            ->SerializeToDer()
            .value());

    EXPECT_THAT(certificate.format(), Eq(Certificate::X509_PEM));

    std::unique_ptr<X509Certificate> interface;
    ASYLO_ASSERT_OK_AND_ASSIGN(interface, X509Certificate::Create(certificate));
    CertificateInterfaceVector chain;
    ASYLO_ASSERT_OK_AND_ASSIGN(
        chain,
        CreateCertificateChain(
            {{Certificate::X509_PEM, X509Certificate::Create}}, issuer_chain));
    X509Certificate *issuer =
        CHECK_NOTNULL(dynamic_cast<X509Certificate *>(chain[0].get()));

    EXPECT_THAT(interface->GetVersion(), Eq(X509Version::kVersion3));

    X509Name expected_issuer;
    ASYLO_ASSERT_OK_AND_ASSIGN(expected_issuer, issuer->GetSubjectName());
    EXPECT_THAT(interface->GetIssuerName(),
                IsOkAndHolds(ContainerEq(expected_issuer)));

    X509Validity validity;
    ASYLO_ASSERT_OK_AND_ASSIGN(validity, interface->GetValidity());
    EXPECT_THAT(validity.not_before, Le(absl::Now()));
    EXPECT_THAT(validity.not_after, Ge(absl::Now()));

    X509Name expected_subject = std::move(expected_issuer);
    auto common_name =
        std::find_if(expected_subject.begin(), expected_subject.end(),
                     [](const X509NameEntry &entry) {
                       return entry.field == *kCommonNameOid;
                     });
    ASSERT_THAT(common_name, Ne(expected_subject.end()));
    common_name->value = "Asylo Fake SGX PCK Certificate For Testing Only";
    EXPECT_THAT(interface->GetSubjectName(),
                IsOkAndHolds(ContainerEq(expected_subject)));

    if (GetParam().has_value()) {
      EXPECT_THAT(interface->SubjectKeyDer(), IsOkAndHolds(GetParam().value()));
    } else {
      EXPECT_THAT(interface->SubjectKeyDer(), IsOkAndHolds(*kFakePckPublicDer));
    }

    absl::optional<std::vector<uint8_t>> expected_aki;
    ASYLO_ASSERT_OK_AND_ASSIGN(expected_aki, issuer->GetSubjectKeyIdentifier());
    ASSERT_TRUE(expected_aki.has_value());
    EXPECT_THAT(interface->GetAuthorityKeyIdentifier(),
                IsOkAndHolds(expected_aki));

    EXPECT_THAT(interface->GetSubjectKeyIdentifier(),
                IsOkAndHolds(Optional(_)));

    absl::optional<KeyUsageInformation> key_usage = interface->KeyUsage();
    ASSERT_TRUE(key_usage.has_value());
    EXPECT_FALSE(key_usage->certificate_signing);
    EXPECT_FALSE(key_usage->crl_signing);
    EXPECT_TRUE(key_usage->digital_signature);

    absl::optional<BasicConstraints> basic_constraints;
    ASYLO_ASSERT_OK_AND_ASSIGN(basic_constraints,
                               interface->GetBasicConstraints());
    ASSERT_TRUE(basic_constraints.has_value());
    EXPECT_FALSE(basic_constraints->is_ca);
    EXPECT_THAT(basic_constraints->pathlen, Eq(absl::nullopt));

    std::vector<X509Extension> extensions;
    ASYLO_ASSERT_OK_AND_ASSIGN(extensions, interface->GetOtherExtensions());
    ASSERT_THAT(extensions, SizeIs(1));
    ASSERT_THAT(extensions[0].oid, Eq(GetSgxExtensionsOid()));
    EXPECT_FALSE(extensions[0].is_critical);

    SgxExtensions extension_data;
    ASYLO_ASSERT_OK_AND_ASSIGN(extension_data,
                               ReadSgxExtensions(extensions[0].value));
    if (expected_ppid.has_value()) {
      EXPECT_THAT(extension_data.ppid, EqualsProto(expected_ppid.value()));
    }
    EXPECT_THAT(extension_data.tcb, EqualsProto(expected_tcb));
    EXPECT_THAT(extension_data.cpu_svn, EqualsProto(expected_cpu_svn));
    EXPECT_THAT(extension_data.pce_id, EqualsProto(expected_platform.pce_id));
    EXPECT_THAT(extension_data.fmspc, EqualsProto(expected_fmspc));
    EXPECT_THAT(extension_data.sgx_type, Eq(SgxType::STANDARD));

    chain.insert(chain.begin(), std::move(interface));
    ASYLO_EXPECT_OK(
        VerifyCertificateChain(chain, VerificationConfig(/*all_fields=*/true)));
  }

  // Checks that |signed_tcb_info| is valid and that the signature can be
  // verified.
  void VerifySignedTcbInfo(const SignedTcbInfo &signed_tcb_info) {
    ASSERT_TRUE(signed_tcb_info.has_tcb_info_json());
    ASSERT_TRUE(signed_tcb_info.has_signature());
    ASYLO_EXPECT_OK(tcb_info_verifying_key_->Verify(
        signed_tcb_info.tcb_info_json(), signed_tcb_info.signature()));
  }

  // Checks that |actual_tcb_info| is valid, that its |issue_date| is
  // approximately now, that its |next_update| is one month after its
  // |issue_date|, and that it equals |expected_tcb_info| except for the
  // |issue_date| and |next_update|.
  static void VerifyEqualsExpectedExceptDates(const TcbInfo &actual_tcb_info,
                                              TcbInfo expected_tcb_info) {
    ASYLO_ASSERT_OK(ValidateTcbInfo(actual_tcb_info));
    google::protobuf::Timestamp now = google::protobuf::util::TimeUtil::GetCurrentTime();
    EXPECT_THAT(actual_tcb_info.impl().issue_date(), Gt(now - NowMaxError()));
    EXPECT_THAT(actual_tcb_info.impl().issue_date(), Lt(now + NowMaxError()));
    EXPECT_THAT(
        actual_tcb_info.impl().next_update(),
        Eq(actual_tcb_info.impl().issue_date() + TcbInfoUpdatePeriod()));
    *expected_tcb_info.mutable_impl()->mutable_issue_date() =
        actual_tcb_info.impl().issue_date();
    *expected_tcb_info.mutable_impl()->mutable_next_update() =
        actual_tcb_info.impl().next_update();
    EXPECT_THAT(actual_tcb_info, EqualsProto(expected_tcb_info));
  }

  // Returns a TCB info of the given |version| for the configured
  // PlatformProperties and given |fmspc|.
  TcbInfo SomeTcbInfo(int version, Fmspc fmspc) {
    CHECK(version == 1 || version == 2)
        << "Invalid TCB info version: " << version;
    TcbInfo tcb_info;
    TcbInfoImpl *impl = tcb_info.mutable_impl();
    impl->set_version(version);
    impl->mutable_issue_date()->set_seconds(0);
    impl->mutable_next_update()->set_seconds(1);
    *impl->mutable_fmspc() = std::move(fmspc);
    *impl->mutable_pce_id() = platform_properties_.pce_id;
    TcbLevel *tcb_level = impl->add_tcb_levels();
    tcb_level->mutable_tcb()->set_components("0123456789abcdef");
    tcb_level->mutable_tcb()->mutable_pce_svn()->set_value(7);
    tcb_level->mutable_status()->set_known_status(TcbStatus::UP_TO_DATE);
    if (version == 2) {
      impl->set_tcb_type(TcbType::TCB_TYPE_0);
      impl->set_tcb_evaluation_data_number(2);
      *tcb_level->mutable_tcb_date() =
          google::protobuf::util::TimeUtil::TimeTToTimestamp(1000);
      tcb_level->mutable_tcb_date()->clear_nanos();
    }
    return tcb_info;
  }

  // Returns a TCB info of the given |version| for the configured
  // PlatformProperties and given |fmspc|. The returned TCB info is not equal to
  // the one returned by SomeTcbInfo() for the same |version| and |fmspc|.
  TcbInfo OtherTcbInfo(int version, Fmspc fmspc) {
    CHECK(version == 1 || version == 2)
        << "Invalid TCB info version: " << version;
    TcbInfo tcb_info = SomeTcbInfo(version, std::move(fmspc));
    TcbInfoImpl *impl = tcb_info.mutable_impl();
    TcbLevel *tcb_level = impl->mutable_tcb_levels(0);
    tcb_level->mutable_tcb()->set_components("fedcba9876543210");
    tcb_level->mutable_tcb()->mutable_pce_svn()->set_value(10);
    tcb_level->mutable_status()->set_known_status(TcbStatus::UP_TO_DATE);
    if (version == 2) {
      impl->set_tcb_evaluation_data_number(3);
      tcb_level->add_advisory_ids("Some Advisory ID");
    }
    return tcb_info;
  }

  // Returns a reasonable margin of error for comparing values of "now" recently
  // generated by a FakeSgxPcsClient.
  static google::protobuf::Duration NowMaxError() {
    return ConvertDuration<google::protobuf::Duration>(absl::Seconds(5))
        .value();
  }

  // Returns the expected time-to-next-update for a TCB info structure.
  static google::protobuf::Duration TcbInfoUpdatePeriod() {
    return ConvertDuration<google::protobuf::Duration>(absl::Hours(24 * 30))
        .value();
  }

  CertificateChain platform_ca_issuer_chain_;
  CertificateChain processor_ca_issuer_chain_;
  CertificateChain tcb_info_issuer_chain_;
  std::unique_ptr<VerifyingKey> platform_ca_verifying_key_;
  std::unique_ptr<VerifyingKey> processor_ca_verifying_key_;
  std::unique_ptr<VerifyingKey> tcb_info_verifying_key_;
  FakeSgxPcsClient::PlatformProperties platform_properties_;

  // Use absl::optional<> to delay initialization.
  absl::optional<FakeSgxPcsClient> fake_client_;
};

TEST_P(FakeSgxPcsClientTest, GetPckCertificateIsUnimplemented) {
  Ppid ppid;
  ppid.set_value("0123456789abcdef");
  CpuSvn cpu_svn;
  cpu_svn.set_value("01234567898abcdef");
  PceSvn pce_svn;
  pce_svn.set_value(7);
  PceId pce_id;
  pce_id.set_value(0);

  EXPECT_THAT(fake_client_->GetPckCertificate(ppid, cpu_svn, pce_svn, pce_id),
              StatusIs(absl::StatusCode::kUnimplemented));
}

TEST_P(FakeSgxPcsClientTest, GetPckCertificatesFailsOnInvalidArguments) {
  Ppid valid_ppid;
  valid_ppid.set_value("0123456789abcdef");
  PceId valid_pce_id;
  valid_pce_id.set_value(0);

  EXPECT_THAT(fake_client_->GetPckCertificates(Ppid(), valid_pce_id),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(fake_client_->GetPckCertificates(valid_ppid, PceId()),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(FakeSgxPcsClientTest,
       GetPckCertificatesFailsOnPpidNotMatchingFakeFormat) {
  Ppid ppid;
  ppid.set_value(
      "\xff"
      "123456789abcdef");
  PceId pce_id;
  pce_id.set_value(0);

  EXPECT_THAT(fake_client_->GetPckCertificates(ppid, pce_id),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(FakeSgxPcsClientTest, GetPckCertificatesFailsOnPpidWithUnknownFmspc) {
  Fmspc fmspc;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      fmspc, fake_client_->CreateFmspcWithProperties(platform_properties_));
  Ppid ppid;
  ASYLO_ASSERT_OK_AND_ASSIGN(ppid, FakeSgxPcsClient::CreatePpidForFmspc(fmspc));
  EXPECT_THAT(
      fake_client_->GetPckCertificates(ppid, platform_properties_.pce_id),
      StatusIs(absl::StatusCode::kNotFound));
}

TEST_P(FakeSgxPcsClientTest,
       GetPckCertificatesReturnsOnePckCertificateForEachTcbLevelInTcbInfo) {

  for (SgxCaType ca_type : {SgxCaType::PLATFORM, SgxCaType::PROCESSOR}) {
    FakeSgxPcsClient::PlatformProperties platform;
    platform.ca = ca_type;
    platform.pce_id.set_value(0);

    Fmspc fmspc;
    ASYLO_ASSERT_OK_AND_ASSIGN(
        fmspc, fake_client_->CreateFmspcWithProperties(platform));
    TcbInfo tcb_info = SomeTcbInfo(/*version=*/2, fmspc);
    ASSERT_THAT(fake_client_->AddFmspc(fmspc, tcb_info), IsOkAndHolds(true));

    Ppid ppid;
    ASYLO_ASSERT_OK_AND_ASSIGN(ppid,
                               FakeSgxPcsClient::CreatePpidForFmspc(fmspc));
    GetPckCertificatesResult result;
    ASYLO_ASSERT_OK_AND_ASSIGN(
        result, fake_client_->GetPckCertificates(ppid, platform.pce_id));
    ASYLO_ASSERT_OK(ValidatePckCertificates(result.pck_certs));
    ASYLO_ASSERT_OK(ValidateCertificateChain(result.issuer_cert_chain));

    TcbInfoReader reader;
    ASYLO_ASSERT_OK_AND_ASSIGN(reader, TcbInfoReader::Create(tcb_info));
    EXPECT_THAT(reader.GetConsistencyWith(result.pck_certs),
                IsOkAndHolds(ProvisioningConsistency::kConsistent));
    for (const auto &cert_info : result.pck_certs.certs()) {
      VerifyPckCertificate(cert_info.cert(),
                           ca_type == SgxCaType::PLATFORM
                               ? platform_ca_issuer_chain_
                               : processor_ca_issuer_chain_,
                           ppid, cert_info.tcb_level(),
                           cert_info.tcbm().cpu_svn(), fmspc, platform);
    }
  }
}

TEST_P(FakeSgxPcsClientTest, GetCrlIsUnimplemented) {
  EXPECT_THAT(fake_client_->GetCrl(SgxCaType::PLATFORM),
              StatusIs(absl::StatusCode::kUnimplemented));
}

TEST_P(FakeSgxPcsClientTest, GetTcbInfoFailsOnInvalidFmspc) {
  Fmspc fmspc;
  fmspc.set_value("toolong");
  EXPECT_THAT(fake_client_->GetTcbInfo(fmspc),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(FakeSgxPcsClientTest, GetTcbInfoFailsOnFmspcNotMatchingFakeFormat) {
  Fmspc fmspc;
  fmspc.set_value("\xffstuff");
  EXPECT_THAT(fake_client_->GetTcbInfo(fmspc),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(FakeSgxPcsClientTest, GetTcbInfoFailsOnUnknownFmspc) {
  Fmspc fmspc;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      fmspc, fake_client_->CreateFmspcWithProperties(platform_properties_));
  EXPECT_THAT(fake_client_->GetTcbInfo(fmspc),
              StatusIs(absl::StatusCode::kNotFound));
}

TEST_P(FakeSgxPcsClientTest, GetTcbInfoReturnsConfiguredTcbInfoForAddedFmspc) {
  for (int tcb_info_version : {1, 2}) {
    Fmspc fmspc;
    ASYLO_ASSERT_OK_AND_ASSIGN(
        fmspc, fake_client_->CreateFmspcWithProperties(platform_properties_));
    TcbInfo expected_tcb_info = SomeTcbInfo(tcb_info_version, fmspc);
    ASSERT_THAT(fake_client_->AddFmspc(fmspc, expected_tcb_info),
                IsOkAndHolds(true));
    GetTcbInfoResult result;
    ASYLO_ASSERT_OK_AND_ASSIGN(result, fake_client_->GetTcbInfo(fmspc));
    ASSERT_NO_FATAL_FAILURE(VerifySignedTcbInfo(result.tcb_info));
    ASYLO_EXPECT_OK(ValidateCertificateChain(result.issuer_cert_chain));
    EXPECT_THAT(result.issuer_cert_chain, EqualsProto(tcb_info_issuer_chain_));

    TcbInfo actual_tcb_info;
    ASYLO_ASSERT_OK_AND_ASSIGN(
        actual_tcb_info, TcbInfoFromJson(result.tcb_info.tcb_info_json()));
    VerifyEqualsExpectedExceptDates(actual_tcb_info, expected_tcb_info);
  }
}

TEST_P(FakeSgxPcsClientTest, UpdateFmspcFailsForUnknownFmspc) {
  for (int tcb_info_version : {1, 2}) {
    Fmspc fmspc;
    ASYLO_ASSERT_OK_AND_ASSIGN(
        fmspc, fake_client_->CreateFmspcWithProperties(platform_properties_));
    EXPECT_THAT(
        fake_client_->UpdateFmspc(fmspc, SomeTcbInfo(tcb_info_version, fmspc)),
        StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST_P(FakeSgxPcsClientTest, GetTcbInfoReturnsNewTcbInfoForChangedFmspc) {
  for (int tcb_info_version : {1, 2}) {
    Fmspc fmspc;
    ASYLO_ASSERT_OK_AND_ASSIGN(
        fmspc, fake_client_->CreateFmspcWithProperties(platform_properties_));
    ASSERT_THAT(
        fake_client_->AddFmspc(fmspc, SomeTcbInfo(tcb_info_version, fmspc)),
        IsOkAndHolds(true));
    TcbInfo expected_tcb_info = OtherTcbInfo(tcb_info_version, fmspc);
    ASYLO_ASSERT_OK(fake_client_->UpdateFmspc(fmspc, expected_tcb_info));
    GetTcbInfoResult result;
    ASYLO_ASSERT_OK_AND_ASSIGN(result, fake_client_->GetTcbInfo(fmspc));
    ASSERT_NO_FATAL_FAILURE(VerifySignedTcbInfo(result.tcb_info));
    ASYLO_EXPECT_OK(ValidateCertificateChain(result.issuer_cert_chain));
    EXPECT_THAT(result.issuer_cert_chain, EqualsProto(tcb_info_issuer_chain_));

    TcbInfo actual_tcb_info;
    ASYLO_ASSERT_OK_AND_ASSIGN(
        actual_tcb_info, TcbInfoFromJson(result.tcb_info.tcb_info_json()));
    VerifyEqualsExpectedExceptDates(actual_tcb_info, expected_tcb_info);
  }
}

INSTANTIATE_TEST_SUITE_P(AllConstructors, FakeSgxPcsClientTest,
                         Values<absl::optional<std::string>>(
                             absl::nullopt,
                             absl::HexStringToBytes(kDifferentPckDerHex)));

}  // namespace
}  // namespace sgx
}  // namespace asylo
