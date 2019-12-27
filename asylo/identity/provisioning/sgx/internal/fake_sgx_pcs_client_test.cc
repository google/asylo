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

#include <memory>
#include <type_traits>
#include <utility>

#include "google/protobuf/duration.pb.h"
#include "google/protobuf/timestamp.pb.h"
#include <google/protobuf/repeated_field.h>
#include <google/protobuf/util/time_util.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/memory/memory.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "absl/types/span.h"
#include "asylo/crypto/certificate.pb.h"
#include "asylo/crypto/certificate_interface.h"
#include "asylo/crypto/certificate_util.h"
#include "asylo/crypto/ecdsa_p256_sha256_signing_key.h"
#include "asylo/crypto/signing_key.h"
#include "asylo/crypto/x509_certificate.h"
#include "asylo/identity/provisioning/sgx/internal/fake_sgx_pki.h"
#include "asylo/identity/provisioning/sgx/internal/platform_provisioning.pb.h"
#include "asylo/identity/provisioning/sgx/internal/sgx_pcs_client.h"
#include "asylo/identity/provisioning/sgx/internal/sgx_pcs_client.pb.h"
#include "asylo/identity/provisioning/sgx/internal/tcb.h"
#include "asylo/identity/provisioning/sgx/internal/tcb.pb.h"
#include "asylo/identity/provisioning/sgx/internal/tcb_info_from_json.h"
#include "asylo/identity/sgx/machine_configuration.pb.h"
#include "asylo/test/util/proto_matchers.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status.h"
#include "asylo/util/time_conversions.h"

namespace asylo {
namespace sgx {
namespace {

using ::testing::Eq;
using ::testing::Gt;
using ::testing::Le;
using ::testing::Test;

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

class FakeSgxPcsClientTest : public Test {
 protected:
  void SetUp() override {
    Certificate root_cert;
    root_cert.set_format(Certificate::X509_PEM);
    root_cert.set_data(kFakeSgxRootCa.certificate_pem.data(),
                       kFakeSgxRootCa.certificate_pem.size());

    Certificate *tcb_signing_certificate =
        tcb_info_issuer_chain_.add_certificates();
    tcb_signing_certificate->set_format(Certificate::X509_PEM);
    tcb_signing_certificate->set_data(kFakeSgxTcbSigner.certificate_pem.data(),
                                      kFakeSgxTcbSigner.certificate_pem.size());
    *tcb_info_issuer_chain_.add_certificates() = std::move(root_cert);

    std::unique_ptr<SigningKey> tcb_info_signing_key;
    ASYLO_ASSERT_OK_AND_ASSIGN(tcb_info_signing_key,
                               EcdsaP256Sha256SigningKey::CreateFromPem(
                                   kFakeSgxTcbSigner.signing_key_pem));
    ASYLO_ASSERT_OK_AND_ASSIGN(tcb_info_verifying_key_,
                               tcb_info_signing_key->GetVerifyingKey());

    platform_properties_.ca = SgxCaType::PLATFORM;
    platform_properties_.pce_id.set_value(0);
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
    EXPECT_THAT(actual_tcb_info.impl().issue_date(), Le(now));
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
      impl->set_tcb_type(0);
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
        .ValueOrDie();
  }

  // Returns the expected time-to-next-update for a TCB info structure.
  static google::protobuf::Duration TcbInfoUpdatePeriod() {
    return ConvertDuration<google::protobuf::Duration>(absl::Hours(24 * 30))
        .ValueOrDie();
  }

  CertificateChain tcb_info_issuer_chain_;
  std::unique_ptr<VerifyingKey> tcb_info_verifying_key_;
  FakeSgxPcsClient::PlatformProperties platform_properties_;
  FakeSgxPcsClient fake_client_;
};

TEST_F(FakeSgxPcsClientTest, TcbInfoCertChainCanBeVerified) {
  CertificateFactoryMap factory_map;
  factory_map.emplace(Certificate::X509_PEM, X509Certificate::Create);
  CertificateInterfaceVector certificate_vector;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      certificate_vector,
      CreateCertificateChain(factory_map, tcb_info_issuer_chain_));
  VerificationConfig verification_config = VerificationConfig();
  ASYLO_EXPECT_OK(VerifyCertificateChain(absl::MakeSpan(certificate_vector),
                                         verification_config));

  std::string subject_key_der;
  ASYLO_ASSERT_OK_AND_ASSIGN(subject_key_der,
                             certificate_vector.front()->SubjectKeyDer());
  std::unique_ptr<VerifyingKey> actual_verifying_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      actual_verifying_key,
      EcdsaP256Sha256VerifyingKey::CreateFromDer(subject_key_der));
  EXPECT_TRUE(*actual_verifying_key == *tcb_info_verifying_key_)
      << absl::StrFormat(
             "Actual key DER: %s\nExpected key DER: %s",
             absl::BytesToHexString(subject_key_der),
             absl::BytesToHexString(
                 tcb_info_verifying_key_->SerializeToDer().ValueOrDie()));
}

TEST_F(FakeSgxPcsClientTest, GetPckCertificateIsUnimplemented) {
  Ppid ppid;
  ppid.set_value("0123456789abcdef");
  CpuSvn cpu_svn;
  cpu_svn.set_value("01234567898abcdef");
  PceSvn pce_svn;
  pce_svn.set_value(7);
  PceId pce_id;
  pce_id.set_value(0);

  EXPECT_THAT(fake_client_.GetPckCertificate(ppid, cpu_svn, pce_svn, pce_id),
              StatusIs(error::GoogleError::UNIMPLEMENTED));
}

TEST_F(FakeSgxPcsClientTest, GetPckCertificatesIsUnimplemented) {
  Ppid ppid;
  ppid.set_value("0123456789abcdef");
  PceId pce_id;
  pce_id.set_value(0);

  EXPECT_THAT(fake_client_.GetPckCertificates(ppid, pce_id),
              StatusIs(error::GoogleError::UNIMPLEMENTED));
}

TEST_F(FakeSgxPcsClientTest, GetCrlIsUnimplemented) {
  EXPECT_THAT(fake_client_.GetCrl(SgxCaType::PLATFORM),
              StatusIs(error::GoogleError::UNIMPLEMENTED));
}

TEST_F(FakeSgxPcsClientTest, GetTcbInfoReturnsErrorForInvalidFmspc) {
  Fmspc fmspc;
  fmspc.set_value("toolong");
  EXPECT_THAT(fake_client_.GetTcbInfo(fmspc),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST_F(FakeSgxPcsClientTest,
       GetTcbInfoReturnsErrorForFmspcNotMatchingFakeFormat) {
  Fmspc fmspc;
  fmspc.set_value("\xffstuff");
  EXPECT_THAT(fake_client_.GetTcbInfo(fmspc),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST_F(FakeSgxPcsClientTest, GetTcbInfoReturnsErrorForUnknownFmspc) {
  Fmspc fmspc;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      fmspc, FakeSgxPcsClient::CreateFmspcWithProperties(platform_properties_));
  EXPECT_THAT(fake_client_.GetTcbInfo(fmspc),
              StatusIs(error::GoogleError::NOT_FOUND));
}

TEST_F(FakeSgxPcsClientTest, GetTcbInfoReturnsConfiguredTcbInfoForAddedFmspc) {
  for (int tcb_info_version : {1, 2}) {
    Fmspc fmspc;
    ASYLO_ASSERT_OK_AND_ASSIGN(
        fmspc,
        FakeSgxPcsClient::CreateFmspcWithProperties(platform_properties_));
    TcbInfo expected_tcb_info = SomeTcbInfo(tcb_info_version, fmspc);
    ASSERT_THAT(fake_client_.AddFmspc(fmspc, expected_tcb_info),
                IsOkAndHolds(true));
    GetTcbInfoResult result;
    ASYLO_ASSERT_OK_AND_ASSIGN(result, fake_client_.GetTcbInfo(fmspc));
    ASSERT_NO_FATAL_FAILURE(VerifySignedTcbInfo(result.tcb_info));
    ASYLO_EXPECT_OK(ValidateCertificateChain(result.issuer_cert_chain));
    EXPECT_THAT(result.issuer_cert_chain, EqualsProto(tcb_info_issuer_chain_));

    TcbInfo actual_tcb_info;
    ASYLO_ASSERT_OK_AND_ASSIGN(
        actual_tcb_info, TcbInfoFromJson(result.tcb_info.tcb_info_json()));
    VerifyEqualsExpectedExceptDates(actual_tcb_info, expected_tcb_info);
  }
}

TEST_F(FakeSgxPcsClientTest, UpdateFmspcFailsForUnknownFmspc) {
  for (int tcb_info_version : {1, 2}) {
    Fmspc fmspc;
    ASYLO_ASSERT_OK_AND_ASSIGN(
        fmspc,
        FakeSgxPcsClient::CreateFmspcWithProperties(platform_properties_));
    EXPECT_THAT(
        fake_client_.UpdateFmspc(fmspc, SomeTcbInfo(tcb_info_version, fmspc)),
        StatusIs(error::GoogleError::INVALID_ARGUMENT));
  }
}

TEST_F(FakeSgxPcsClientTest, GetTcbInfoReturnsNewTcbInfoForChangedFmspc) {
  for (int tcb_info_version : {1, 2}) {
    Fmspc fmspc;
    ASYLO_ASSERT_OK_AND_ASSIGN(
        fmspc,
        FakeSgxPcsClient::CreateFmspcWithProperties(platform_properties_));
    ASSERT_THAT(
        fake_client_.AddFmspc(fmspc, SomeTcbInfo(tcb_info_version, fmspc)),
        IsOkAndHolds(true));
    TcbInfo expected_tcb_info = OtherTcbInfo(tcb_info_version, fmspc);
    ASYLO_ASSERT_OK(fake_client_.UpdateFmspc(fmspc, expected_tcb_info));
    GetTcbInfoResult result;
    ASYLO_ASSERT_OK_AND_ASSIGN(result, fake_client_.GetTcbInfo(fmspc));
    ASSERT_NO_FATAL_FAILURE(VerifySignedTcbInfo(result.tcb_info));
    ASYLO_EXPECT_OK(ValidateCertificateChain(result.issuer_cert_chain));
    EXPECT_THAT(result.issuer_cert_chain, EqualsProto(tcb_info_issuer_chain_));

    TcbInfo actual_tcb_info;
    ASYLO_ASSERT_OK_AND_ASSIGN(
        actual_tcb_info, TcbInfoFromJson(result.tcb_info.tcb_info_json()));
    VerifyEqualsExpectedExceptDates(actual_tcb_info, expected_tcb_info);
  }
}

}  // namespace
}  // namespace sgx
}  // namespace asylo
