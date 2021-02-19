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

#include "asylo/identity/provisioning/sgx/internal/pck_certificate_util.h"

#include <algorithm>
#include <bitset>
#include <limits>
#include <memory>
#include <ostream>
#include <string>
#include <utility>
#include <vector>

#include <google/protobuf/text_format.h>
#include <google/protobuf/util/message_differencer.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/random/random.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "asylo/crypto/asn1.h"
#include "asylo/crypto/certificate.pb.h"
#include "asylo/crypto/certificate_interface.h"
#include "asylo/crypto/certificate_util.h"
#include "asylo/crypto/x509_certificate.h"
#include "asylo/util/logging.h"
#include "asylo/identity/attestation/sgx/internal/attestation_key_certificate_impl.h"
#include "asylo/identity/provisioning/sgx/internal/fake_sgx_pki.h"
#include "asylo/identity/provisioning/sgx/internal/platform_provisioning.h"
#include "asylo/identity/provisioning/sgx/internal/platform_provisioning.pb.h"
#include "asylo/identity/provisioning/sgx/internal/tcb.h"
#include "asylo/identity/provisioning/sgx/internal/tcb.pb.h"
#include "asylo/identity/provisioning/sgx/internal/pck_certificates.pb.h"
#include "asylo/test/util/proto_matchers.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/proto_enum_util.h"
#include "asylo/util/proto_parse_util.h"
#include "asylo/util/status.h"

namespace asylo {
namespace sgx {
namespace {

using ::testing::HasSubstr;

// The number of shuffles to use in a shuffling test.
constexpr int kNumShuffles = 100;

// A hex-encoded AttestationKeyCertificate binary proto.
constexpr char kAttestationKeyCertificateHex[] =
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

// Prints the text format representation of |message|.
std::string PrintMessage(const google::protobuf::Message &message) {
  std::string str;
  CHECK(google::protobuf::TextFormat::PrintToString(message, &str));
  return str;
}

// Prints a human-readable representation of |extensions|.
std::string PrintSgxExtensions(const SgxExtensions &extensions) {
  return absl::StrFormat(
      R"(
ppid { %s }
tcb { %s }
cpu_svn { %s }
pce_id { %s }
fmspc { %s }
sgx_type: %s
)",
      PrintMessage(extensions.ppid), PrintMessage(extensions.tcb),
      PrintMessage(extensions.cpu_svn), PrintMessage(extensions.pce_id),
  PrintMessage(extensions.fmspc), ProtoEnumValueName(extensions.sgx_type));
}

// Matches an SgxExtensions equal to |extensions|.
MATCHER_P(SgxExtensionsEquals, extensions,
          negation
              ? absl::StrCat("is not equal to ", PrintSgxExtensions(extensions))
              : absl::StrCat("is equal to ", PrintSgxExtensions(extensions))) {
  if (!google::protobuf::util::MessageDifferencer::Equals(arg.ppid, extensions.ppid)) {
    *result_listener << "which has a different PPID";
    return false;
  }
  if (!google::protobuf::util::MessageDifferencer::Equals(arg.tcb, extensions.tcb)) {
    *result_listener << "which has a different TCB";
    return false;
  }
  if (!google::protobuf::util::MessageDifferencer::Equals(arg.cpu_svn,
                                                extensions.cpu_svn)) {
    *result_listener << "which has a different CPUSVN";
    return false;
  }
  if (!google::protobuf::util::MessageDifferencer::Equals(arg.pce_id,
                                                extensions.pce_id)) {
    *result_listener << "which has a different PCE-ID";
    return false;
  }
  if (!google::protobuf::util::MessageDifferencer::Equals(arg.fmspc, extensions.fmspc)) {
    *result_listener << "which has a different FMSPC";
    return false;
  }
  if (arg.sgx_type != extensions.sgx_type) {
    *result_listener << "which has a different SGX Type";
    return false;
  }
  return true;
}

// Returns a valid SgxExtensions object.
SgxExtensions CreateValidSgxExtensions() {
  SgxExtensions extensions;
  extensions.ppid.set_value("PPIDPPIDPPIDPPID");
  extensions.tcb.set_components("0123456789abcdef");
  extensions.tcb.mutable_pce_svn()->set_value(7);
  extensions.cpu_svn.set_value("fedcba9876543210");
  extensions.pce_id.set_value(1);
  extensions.fmspc.set_value("FMSPC!");
  extensions.sgx_type = SgxType::STANDARD;
  return extensions;
}

// Indices of elements in the ASN.1 sequence returned by
// WriteSgxExtensions(CreateValidSgxExtenions()).
constexpr int kPpidIndex = 0;
constexpr int kTcbIndex = 1;
constexpr int kPceIdIndex = 2;
constexpr int kFmspcIndex = 3;
constexpr int kSgxTypeIndex = 4;

// Indices of elements in the TCB sequence in
// WriteSgxExtensions(CreateValidSgxExtenions()).
constexpr int kSgxTcbCompSvnBaseIndex = 0;
constexpr int kPceSvnIndex = kTcbComponentsSize;
constexpr int kCpuSvnIndex = kTcbComponentsSize + 1;

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

TEST(PckCertificateUtilTest, SgxExtensionsMustBeOidAnyPairSequences) {
  for (const auto &bad_sgx_extensions :
       {Asn1Value::CreateBoolean(true),
        Asn1Value::CreateSequenceFromStatusOrs(
            {Asn1Value::CreateBoolean(false)}),
        Asn1Value::CreateSequenceFromStatusOrs(
            {Asn1Value::CreateSequenceFromStatusOrs(
                {Asn1Value::CreateIntegerFromInt(31),
                 Asn1Value::CreateOctetString("anything")})})}) {
    Asn1Value bad_sgx_extensions_asn1;
    ASYLO_ASSERT_OK_AND_ASSIGN(bad_sgx_extensions_asn1, bad_sgx_extensions);
    EXPECT_THAT(ReadSgxExtensions(bad_sgx_extensions_asn1),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(PckCertificateUtilTest,
     SgxExtensionsWithMissingRequiredElementsCannotBeRead) {

  Asn1Value extensions_asn1;
  ASYLO_ASSERT_OK_AND_ASSIGN(extensions_asn1,
                             WriteSgxExtensions(CreateValidSgxExtensions()));
  std::vector<Asn1Value> elements;
  ASYLO_ASSERT_OK_AND_ASSIGN(elements, extensions_asn1.GetSequence());

  for (int i = 0; i < elements.size(); i++) {

    std::vector<Asn1Value> elements_copy(elements);
    elements_copy.erase(elements_copy.begin() + i);
    ASYLO_ASSERT_OK_AND_ASSIGN(extensions_asn1,
                               Asn1Value::CreateSequence(elements_copy));
    EXPECT_THAT(ReadSgxExtensions(extensions_asn1),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(PckCertificateUtilTest, SgxExtensionsWithExtraElementsCannotBeRead) {
  ObjectId oid;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      oid, ObjectId::CreateFromOidString("1.2.840.113549.2.5"));

  Asn1Value extensions_asn1;
  ASYLO_ASSERT_OK_AND_ASSIGN(extensions_asn1,
                             WriteSgxExtensions(CreateValidSgxExtensions()));
  std::vector<Asn1Value> elements;
  ASYLO_ASSERT_OK_AND_ASSIGN(elements, extensions_asn1.GetSequence());
  elements.push_back(Asn1Value());

  for (const auto &bad_element :
       {Asn1Value::CreateBoolean(false),
        Asn1Value::CreateSequenceFromStatusOrs(
            {Asn1Value::CreateObjectId(oid),
             Asn1Value::CreateOctetString("0123456789abcdef")})}) {
    ASYLO_ASSERT_OK_AND_ASSIGN(elements.back(), bad_element);
    ASYLO_ASSERT_OK_AND_ASSIGN(extensions_asn1,
                               Asn1Value::CreateSequence(elements));
    EXPECT_THAT(ReadSgxExtensions(extensions_asn1),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(PckCertificateUtilTest, SgxExtensionsWithDuplicateElementsCannotBeRead) {
  Asn1Value extensions_asn1;
  ASYLO_ASSERT_OK_AND_ASSIGN(extensions_asn1,
                             WriteSgxExtensions(CreateValidSgxExtensions()));
  std::vector<Asn1Value> elements;
  ASYLO_ASSERT_OK_AND_ASSIGN(elements, extensions_asn1.GetSequence());

  for (const auto &element : elements) {
    std::vector<Asn1Value> elements_copy(elements);
    elements_copy.push_back(element);
    ASYLO_ASSERT_OK_AND_ASSIGN(extensions_asn1,
                               Asn1Value::CreateSequence(elements_copy));
    EXPECT_THAT(ReadSgxExtensions(extensions_asn1),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(PckCertificateUtilTest, PpidsMustBeOctetStringsOfCorrectLength) {
  Asn1Value extensions_asn1;
  ASYLO_ASSERT_OK_AND_ASSIGN(extensions_asn1,
                             WriteSgxExtensions(CreateValidSgxExtensions()));
  std::vector<Asn1Value> elements;
  ASYLO_ASSERT_OK_AND_ASSIGN(elements, extensions_asn1.GetSequence());
  std::vector<Asn1Value> ppid_oid_pair;
  ASYLO_ASSERT_OK_AND_ASSIGN(ppid_oid_pair, elements[kPpidIndex].GetSequence());

  for (const auto &bad_ppid :
       {Asn1Value::CreateBoolean(true),
        Asn1Value::CreateOctetString("barelytooshort!"),
        Asn1Value::CreateOctetString("onelettertoolong!")}) {
    ASYLO_ASSERT_OK_AND_ASSIGN(
        elements[kPpidIndex],
        Asn1Value::CreateSequenceFromStatusOrs({ppid_oid_pair[0], bad_ppid}));
    ASYLO_ASSERT_OK_AND_ASSIGN(extensions_asn1,
                               Asn1Value::CreateSequence(elements));
    EXPECT_THAT(ReadSgxExtensions(extensions_asn1),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(PckCertificateUtilTest, TcbsMustBeOidAnyPairSequences) {
  Asn1Value extensions_asn1;
  ASYLO_ASSERT_OK_AND_ASSIGN(extensions_asn1,
                             WriteSgxExtensions(CreateValidSgxExtensions()));
  std::vector<Asn1Value> elements;
  ASYLO_ASSERT_OK_AND_ASSIGN(elements, extensions_asn1.GetSequence());
  std::vector<Asn1Value> tcb_oid_pair;
  ASYLO_ASSERT_OK_AND_ASSIGN(tcb_oid_pair, elements[kTcbIndex].GetSequence());

  for (const auto &bad_tcb :
       {Asn1Value::CreateBoolean(true),
        Asn1Value::CreateSequenceFromStatusOrs(
            {Asn1Value::CreateBoolean(false)}),
        Asn1Value::CreateSequenceFromStatusOrs(
            {Asn1Value::CreateSequenceFromStatusOrs(
                {Asn1Value::CreateIntegerFromInt(31),
                 Asn1Value::CreateOctetString("anything")})})}) {
    ASYLO_ASSERT_OK_AND_ASSIGN(
        elements[kTcbIndex],
        Asn1Value::CreateSequenceFromStatusOrs({tcb_oid_pair[0], bad_tcb}));
    ASYLO_ASSERT_OK_AND_ASSIGN(extensions_asn1,
                               Asn1Value::CreateSequence(elements));
    EXPECT_THAT(ReadSgxExtensions(extensions_asn1),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(PckCertificateUtilTest, TcbsWithMissingElementsCannotBeRead) {
  Asn1Value extensions_asn1;
  ASYLO_ASSERT_OK_AND_ASSIGN(extensions_asn1,
                             WriteSgxExtensions(CreateValidSgxExtensions()));
  std::vector<Asn1Value> elements;
  ASYLO_ASSERT_OK_AND_ASSIGN(elements, extensions_asn1.GetSequence());
  std::vector<Asn1Value> tcb_oid_pair;
  ASYLO_ASSERT_OK_AND_ASSIGN(tcb_oid_pair, elements[kTcbIndex].GetSequence());
  std::vector<Asn1Value> tcb_elements;
  ASYLO_ASSERT_OK_AND_ASSIGN(tcb_elements, tcb_oid_pair[1].GetSequence());

  for (int i = 0; i < tcb_elements.size(); i++) {
    std::vector<Asn1Value> tcb_elements_copy(tcb_elements);
    tcb_elements_copy.erase(tcb_elements_copy.begin() + i);
    ASYLO_ASSERT_OK_AND_ASSIGN(
        elements[kTcbIndex],
        Asn1Value::CreateSequenceFromStatusOrs(
            {tcb_oid_pair[0], Asn1Value::CreateSequence(tcb_elements_copy)}));
    ASYLO_ASSERT_OK_AND_ASSIGN(extensions_asn1,
                               Asn1Value::CreateSequence(elements));
    EXPECT_THAT(ReadSgxExtensions(extensions_asn1),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(PckCertificateUtilTest, TcbsWithExtraElementsCannotBeRead) {
  ObjectId oid;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      oid, ObjectId::CreateFromOidString("1.2.840.113549.2.5"));

  Asn1Value extensions_asn1;
  ASYLO_ASSERT_OK_AND_ASSIGN(extensions_asn1,
                             WriteSgxExtensions(CreateValidSgxExtensions()));
  std::vector<Asn1Value> elements;
  ASYLO_ASSERT_OK_AND_ASSIGN(elements, extensions_asn1.GetSequence());
  std::vector<Asn1Value> tcb_oid_pair;
  ASYLO_ASSERT_OK_AND_ASSIGN(tcb_oid_pair, elements[kTcbIndex].GetSequence());
  std::vector<Asn1Value> tcb_elements;
  ASYLO_ASSERT_OK_AND_ASSIGN(tcb_elements, tcb_oid_pair[1].GetSequence());
  tcb_elements.push_back(Asn1Value());

  for (const auto &bad_tcb_element :
       {Asn1Value::CreateBoolean(false),
        Asn1Value::CreateSequenceFromStatusOrs(
            {Asn1Value::CreateObjectId(oid),
             Asn1Value::CreateOctetString("0123456789abcdef")})}) {
    ASYLO_ASSERT_OK_AND_ASSIGN(tcb_elements.back(), bad_tcb_element);
    ASYLO_ASSERT_OK_AND_ASSIGN(
        elements[kTcbIndex],
        Asn1Value::CreateSequenceFromStatusOrs(
            {tcb_oid_pair[0], Asn1Value::CreateSequence(tcb_elements)}));
    ASYLO_ASSERT_OK_AND_ASSIGN(extensions_asn1,
                               Asn1Value::CreateSequence(elements));
    EXPECT_THAT(ReadSgxExtensions(extensions_asn1),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(PckCertificateUtilTest, TcbsWithDuplicateElementsCannotBeRead) {
  Asn1Value extensions_asn1;
  ASYLO_ASSERT_OK_AND_ASSIGN(extensions_asn1,
                             WriteSgxExtensions(CreateValidSgxExtensions()));
  std::vector<Asn1Value> elements;
  ASYLO_ASSERT_OK_AND_ASSIGN(elements, extensions_asn1.GetSequence());
  std::vector<Asn1Value> tcb_oid_pair;
  ASYLO_ASSERT_OK_AND_ASSIGN(tcb_oid_pair, elements[kTcbIndex].GetSequence());
  std::vector<Asn1Value> tcb_elements;
  ASYLO_ASSERT_OK_AND_ASSIGN(tcb_elements, tcb_oid_pair[1].GetSequence());

  for (const auto &tcb_element : tcb_elements) {
    std::vector<Asn1Value> tcb_elements_copy(tcb_elements);
    tcb_elements_copy.push_back(tcb_element);
    ASYLO_ASSERT_OK_AND_ASSIGN(
        elements[kTcbIndex],
        Asn1Value::CreateSequenceFromStatusOrs(
            {tcb_oid_pair[0], Asn1Value::CreateSequence(tcb_elements_copy)}));
    ASYLO_ASSERT_OK_AND_ASSIGN(extensions_asn1,
                               Asn1Value::CreateSequence(elements));
    EXPECT_THAT(ReadSgxExtensions(extensions_asn1),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(PckCertificateUtilTest, TcbComponentsMustBeIntegersInRange) {
  for (int i = 0; i < kTcbComponentsSize; ++i) {
    Asn1Value extensions_asn1;
    ASYLO_ASSERT_OK_AND_ASSIGN(extensions_asn1,
                               WriteSgxExtensions(CreateValidSgxExtensions()));
    std::vector<Asn1Value> elements;
    ASYLO_ASSERT_OK_AND_ASSIGN(elements, extensions_asn1.GetSequence());
    std::vector<Asn1Value> tcb_oid_pair;
    ASYLO_ASSERT_OK_AND_ASSIGN(tcb_oid_pair, elements[kTcbIndex].GetSequence());
    std::vector<Asn1Value> tcb_elements;
    ASYLO_ASSERT_OK_AND_ASSIGN(tcb_elements, tcb_oid_pair[1].GetSequence());
    std::vector<Asn1Value> tcb_component_oid_pair;
    ASYLO_ASSERT_OK_AND_ASSIGN(
        tcb_component_oid_pair,
        tcb_elements[kSgxTcbCompSvnBaseIndex + i].GetSequence());

    for (auto pair :
         {std::make_pair(Asn1Value::CreateBoolean(true),
                         absl::StatusCode::kInvalidArgument),
          std::make_pair(Asn1Value::CreateIntegerFromInt(-1),
                         absl::StatusCode::kOutOfRange),
          std::make_pair(Asn1Value::CreateIntegerFromInt(
                             std::numeric_limits<uint8_t>::max() + 1),
                         absl::StatusCode::kOutOfRange)}) {
      StatusOr<Asn1Value> bad_tcb_component;
      absl::StatusCode error_code;
      std::tie(bad_tcb_component, error_code) = std::move(pair);
      ASYLO_ASSERT_OK_AND_ASSIGN(
          tcb_elements[kSgxTcbCompSvnBaseIndex + i],
          Asn1Value::CreateSequenceFromStatusOrs(
              {tcb_component_oid_pair[0], bad_tcb_component}));
      ASYLO_ASSERT_OK_AND_ASSIGN(
          elements[kTcbIndex],
          Asn1Value::CreateSequenceFromStatusOrs(
              {tcb_oid_pair[0], Asn1Value::CreateSequence(tcb_elements)}));
      ASYLO_ASSERT_OK_AND_ASSIGN(extensions_asn1,
                                 Asn1Value::CreateSequence(elements));
      EXPECT_THAT(ReadSgxExtensions(extensions_asn1), StatusIs(error_code));
    }
  }
}

TEST(PckCertificateUtilTest, PceSvnsMustBeIntegersInRange) {
  Asn1Value extensions_asn1;
  ASYLO_ASSERT_OK_AND_ASSIGN(extensions_asn1,
                             WriteSgxExtensions(CreateValidSgxExtensions()));
  std::vector<Asn1Value> elements;
  ASYLO_ASSERT_OK_AND_ASSIGN(elements, extensions_asn1.GetSequence());
  std::vector<Asn1Value> tcb_oid_pair;
  ASYLO_ASSERT_OK_AND_ASSIGN(tcb_oid_pair, elements[kTcbIndex].GetSequence());
  std::vector<Asn1Value> tcb_elements;
  ASYLO_ASSERT_OK_AND_ASSIGN(tcb_elements, tcb_oid_pair[1].GetSequence());
  std::vector<Asn1Value> pce_svn_oid_pair;
  ASYLO_ASSERT_OK_AND_ASSIGN(pce_svn_oid_pair,
                             tcb_elements[kPceSvnIndex].GetSequence());

  for (auto pair :
       {std::make_pair(Asn1Value::CreateBoolean(true),
                       absl::StatusCode::kInvalidArgument),
        std::make_pair(Asn1Value::CreateIntegerFromInt(-1),
                       absl::StatusCode::kOutOfRange),
        std::make_pair(Asn1Value::CreateIntegerFromInt(
                           std::numeric_limits<uint16_t>::max() + 1),
                       absl::StatusCode::kOutOfRange)}) {
    StatusOr<Asn1Value> bad_pce_svn;
    absl::StatusCode error_code;
    std::tie(bad_pce_svn, error_code) = std::move(pair);
    ASYLO_ASSERT_OK_AND_ASSIGN(tcb_elements[kPceSvnIndex],
                               Asn1Value::CreateSequenceFromStatusOrs(
                                   {pce_svn_oid_pair[0], bad_pce_svn}));
    ASYLO_ASSERT_OK_AND_ASSIGN(
        elements[kTcbIndex],
        Asn1Value::CreateSequenceFromStatusOrs(
            {tcb_oid_pair[0], Asn1Value::CreateSequence(tcb_elements)}));
    ASYLO_ASSERT_OK_AND_ASSIGN(extensions_asn1,
                               Asn1Value::CreateSequence(elements));
    EXPECT_THAT(ReadSgxExtensions(extensions_asn1), StatusIs(error_code));
  }
}

TEST(PckCertificateUtilTest, CpuSvnsMustBeOctetStringsOfCorrectLength) {
  Asn1Value extensions_asn1;
  ASYLO_ASSERT_OK_AND_ASSIGN(extensions_asn1,
                             WriteSgxExtensions(CreateValidSgxExtensions()));
  std::vector<Asn1Value> elements;
  ASYLO_ASSERT_OK_AND_ASSIGN(elements, extensions_asn1.GetSequence());
  std::vector<Asn1Value> tcb_oid_pair;
  ASYLO_ASSERT_OK_AND_ASSIGN(tcb_oid_pair, elements[kTcbIndex].GetSequence());
  std::vector<Asn1Value> tcb_elements;
  ASYLO_ASSERT_OK_AND_ASSIGN(tcb_elements, tcb_oid_pair[1].GetSequence());
  std::vector<Asn1Value> cpu_svn_oid_pair;
  ASYLO_ASSERT_OK_AND_ASSIGN(cpu_svn_oid_pair,
                             tcb_elements[kCpuSvnIndex].GetSequence());

  for (const auto &bad_cpu_svn :
       {Asn1Value::CreateBoolean(true),
        Asn1Value::CreateOctetString("barelytooshort!"),
        Asn1Value::CreateOctetString("onelettertoolong!")}) {
    ASYLO_ASSERT_OK_AND_ASSIGN(tcb_elements[kCpuSvnIndex],
                               Asn1Value::CreateSequenceFromStatusOrs(
                                   {cpu_svn_oid_pair[0], bad_cpu_svn}));
    ASYLO_ASSERT_OK_AND_ASSIGN(
        elements[kTcbIndex],
        Asn1Value::CreateSequenceFromStatusOrs(
            {tcb_oid_pair[0], Asn1Value::CreateSequence(tcb_elements)}));
    ASYLO_ASSERT_OK_AND_ASSIGN(extensions_asn1,
                               Asn1Value::CreateSequence(elements));
    EXPECT_THAT(ReadSgxExtensions(extensions_asn1),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(PckCertificateUtilTest, PceIdsMustBeOctetStringsOfCorrectLength) {
  Asn1Value extensions_asn1;
  ASYLO_ASSERT_OK_AND_ASSIGN(extensions_asn1,
                             WriteSgxExtensions(CreateValidSgxExtensions()));
  std::vector<Asn1Value> elements;
  ASYLO_ASSERT_OK_AND_ASSIGN(elements, extensions_asn1.GetSequence());
  std::vector<Asn1Value> pce_id_oid_pair;
  ASYLO_ASSERT_OK_AND_ASSIGN(pce_id_oid_pair,
                             elements[kPceIdIndex].GetSequence());

  for (const auto &bad_pce_id :
       {Asn1Value::CreateBoolean(true), Asn1Value::CreateOctetString("s"),
        Asn1Value::CreateOctetString("big")}) {
    ASYLO_ASSERT_OK_AND_ASSIGN(elements[kPceIdIndex],
                               Asn1Value::CreateSequenceFromStatusOrs(
                                   {pce_id_oid_pair[0], bad_pce_id}));
    ASYLO_ASSERT_OK_AND_ASSIGN(extensions_asn1,
                               Asn1Value::CreateSequence(elements));
    EXPECT_THAT(ReadSgxExtensions(extensions_asn1),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(PckCertificateUtilTest, FmspcsMustBeOctetStringsOfCorrectLength) {
  Asn1Value extensions_asn1;
  ASYLO_ASSERT_OK_AND_ASSIGN(extensions_asn1,
                             WriteSgxExtensions(CreateValidSgxExtensions()));
  std::vector<Asn1Value> elements;
  ASYLO_ASSERT_OK_AND_ASSIGN(elements, extensions_asn1.GetSequence());
  std::vector<Asn1Value> fmspc_oid_pair;
  ASYLO_ASSERT_OK_AND_ASSIGN(fmspc_oid_pair,
                             elements[kFmspcIndex].GetSequence());

  for (const auto &bad_fmspc :
       {Asn1Value::CreateBoolean(true), Asn1Value::CreateOctetString("short"),
        Asn1Value::CreateOctetString("toolong")}) {
    ASYLO_ASSERT_OK_AND_ASSIGN(
        elements[kFmspcIndex],
        Asn1Value::CreateSequenceFromStatusOrs({fmspc_oid_pair[0], bad_fmspc}));
    ASYLO_ASSERT_OK_AND_ASSIGN(extensions_asn1,
                               Asn1Value::CreateSequence(elements));
    EXPECT_THAT(ReadSgxExtensions(extensions_asn1),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(PckCertificateUtilTest, SgxTypesMustBeEnumeratedValuesInRange) {
  Asn1Value extensions_asn1;
  ASYLO_ASSERT_OK_AND_ASSIGN(extensions_asn1,
                             WriteSgxExtensions(CreateValidSgxExtensions()));
  std::vector<Asn1Value> elements;
  ASYLO_ASSERT_OK_AND_ASSIGN(elements, extensions_asn1.GetSequence());
  std::vector<Asn1Value> sgx_type_oid_pair;
  ASYLO_ASSERT_OK_AND_ASSIGN(sgx_type_oid_pair,
                             elements[kSgxTypeIndex].GetSequence());

  for (auto pair :
       {std::make_pair(Asn1Value::CreateBoolean(true),
                       absl::StatusCode::kInvalidArgument),
        std::make_pair(Asn1Value::CreateEnumeratedFromInt(-1),
                       absl::StatusCode::kOutOfRange),
                       std::make_pair(Asn1Value::CreateEnumeratedFromInt(1),
                       absl::StatusCode::kInvalidArgument)}) {
    StatusOr<Asn1Value> bad_sgx_type;
    absl::StatusCode error_code;
    std::tie(bad_sgx_type, error_code) = std::move(pair);
    ASYLO_ASSERT_OK_AND_ASSIGN(elements[kSgxTypeIndex],
                               Asn1Value::CreateSequenceFromStatusOrs(
                                   {sgx_type_oid_pair[0], bad_sgx_type}));
    ASYLO_ASSERT_OK_AND_ASSIGN(extensions_asn1,
                               Asn1Value::CreateSequence(elements));
    EXPECT_THAT(ReadSgxExtensions(extensions_asn1), StatusIs(error_code));
  }
}

TEST(PckCertificateUtilTest, InvalidSgxExtensionsCannotBeWritten) {
  SgxExtensions extensions = CreateValidSgxExtensions();
  extensions.ppid.clear_value();
  EXPECT_THAT(WriteSgxExtensions(extensions),
              StatusIs(absl::StatusCode::kInvalidArgument));

  extensions = CreateValidSgxExtensions();
  extensions.tcb.clear_components();
  EXPECT_THAT(WriteSgxExtensions(extensions),
              StatusIs(absl::StatusCode::kInvalidArgument));

  extensions = CreateValidSgxExtensions();
  extensions.cpu_svn.clear_value();
  EXPECT_THAT(WriteSgxExtensions(extensions),
              StatusIs(absl::StatusCode::kInvalidArgument));

  extensions = CreateValidSgxExtensions();
  extensions.pce_id.clear_value();
  EXPECT_THAT(WriteSgxExtensions(extensions),
              StatusIs(absl::StatusCode::kInvalidArgument));

  extensions = CreateValidSgxExtensions();
  extensions.fmspc.clear_value();
  EXPECT_THAT(WriteSgxExtensions(extensions),
              StatusIs(absl::StatusCode::kInvalidArgument));

  extensions = CreateValidSgxExtensions();
  extensions.sgx_type = SgxType::SGX_TYPE_UNKNOWN;
  EXPECT_THAT(WriteSgxExtensions(extensions),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PckCertificateUtilTest, SgxExtensionsRoundtrip) {
  SgxExtensions extensions = CreateValidSgxExtensions();
  Asn1Value extensions_asn1;
  ASYLO_ASSERT_OK_AND_ASSIGN(extensions_asn1, WriteSgxExtensions(extensions));
  EXPECT_THAT(ReadSgxExtensions(extensions_asn1),
              IsOkAndHolds(SgxExtensionsEquals(extensions)));
}

TEST(PckCertificateUtilTest, SgxExtensionsElementsCanBeInAnyOrder) {
  SgxExtensions extensions = CreateValidSgxExtensions();
  Asn1Value extensions_asn1;
  ASYLO_ASSERT_OK_AND_ASSIGN(extensions_asn1, WriteSgxExtensions(extensions));
  std::vector<Asn1Value> elements;
  ASYLO_ASSERT_OK_AND_ASSIGN(elements, extensions_asn1.GetSequence());

  for (int i = 0; i < kNumShuffles; ++i) {
    std::shuffle(elements.begin(), elements.end(), absl::BitGen());
    ASYLO_ASSERT_OK_AND_ASSIGN(extensions_asn1,
                               Asn1Value::CreateSequence(elements));
    EXPECT_THAT(ReadSgxExtensions(extensions_asn1),
                IsOkAndHolds(SgxExtensionsEquals(extensions)));
  }
}

TEST(PckCertificateUtilTest, TcbElementsCanBeInAnyOrder) {
  SgxExtensions extensions = CreateValidSgxExtensions();
  Asn1Value extensions_asn1;
  ASYLO_ASSERT_OK_AND_ASSIGN(extensions_asn1, WriteSgxExtensions(extensions));
  std::vector<Asn1Value> elements;
  ASYLO_ASSERT_OK_AND_ASSIGN(elements, extensions_asn1.GetSequence());
  std::vector<Asn1Value> tcb_oid_pair;
  ASYLO_ASSERT_OK_AND_ASSIGN(tcb_oid_pair, elements[kTcbIndex].GetSequence());
  std::vector<Asn1Value> tcb_elements;
  ASYLO_ASSERT_OK_AND_ASSIGN(tcb_elements, tcb_oid_pair[1].GetSequence());

  for (int i = 0; i < kNumShuffles; ++i) {
    std::shuffle(tcb_elements.begin(), tcb_elements.end(), absl::BitGen());
    ASYLO_ASSERT_OK_AND_ASSIGN(
        elements[kTcbIndex],
        Asn1Value::CreateSequenceFromStatusOrs(
            {tcb_oid_pair[0], Asn1Value::CreateSequence(tcb_elements)}));
    ASYLO_ASSERT_OK_AND_ASSIGN(extensions_asn1,
                               Asn1Value::CreateSequence(elements));
    EXPECT_THAT(ReadSgxExtensions(extensions_asn1),
                IsOkAndHolds(SgxExtensionsEquals(extensions)));
  }
}

TEST(PckCertificateUtilTest, PckCertificateInfoWithoutTcbLevelIsInvalid) {
  PckCertificates pck_certificates = CreateValidPckCertificates(1);
  pck_certificates.mutable_certs(0)->clear_tcb_level();
  EXPECT_THAT(ValidatePckCertificates(pck_certificates),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PckCertificateUtilTest, PckCertificateInfoWithInvalidTcbLevelIsInvalid) {
  PckCertificates pck_certificates = CreateValidPckCertificates(1);
  pck_certificates.mutable_certs(0)->mutable_tcb_level()->set_components("");
  EXPECT_THAT(ValidatePckCertificates(pck_certificates),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PckCertificateUtilTest, PckCertificateInfoWithoutTcbmIsInvalid) {
  PckCertificates pck_certificates = CreateValidPckCertificates(1);
  pck_certificates.mutable_certs(0)->clear_tcbm();
  EXPECT_THAT(ValidatePckCertificates(pck_certificates),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PckCertificateUtilTest, PckCertificateInfoWithInvalidTcbmIsInvalid) {
  PckCertificates pck_certificates = CreateValidPckCertificates(1);
  pck_certificates.mutable_certs(0)->mutable_tcbm()->clear_cpu_svn();
  EXPECT_THAT(ValidatePckCertificates(pck_certificates),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PckCertificateUtilTest, PckCertificateInfoWithoutCertIsInvalid) {
  PckCertificates pck_certificates = CreateValidPckCertificates(1);
  pck_certificates.mutable_certs(0)->clear_cert();
  EXPECT_THAT(ValidatePckCertificates(pck_certificates),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PckCertificateUtilTest, PckCertificateInfoWithInvalidCertIsInvalid) {
  PckCertificates pck_certificates = CreateValidPckCertificates(1);
  pck_certificates.mutable_certs(0)->mutable_cert()->set_format(
      asylo::Certificate::UNKNOWN);
  EXPECT_THAT(ValidatePckCertificates(pck_certificates),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PckCertificateUtilTest, PckCertificateInfoWithDifferingPceSvnsIsInvalid) {
  PckCertificates pck_certificates = CreateValidPckCertificates(1);
  pck_certificates.mutable_certs(0)
      ->mutable_tcbm()
      ->mutable_pce_svn()
      ->set_value(29);
  EXPECT_THAT(ValidatePckCertificates(pck_certificates),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PckCertificateUtilTest,
     PckCertificatesWithDistinctEntriesWithSameTcbLevelIsInvalid) {
  PckCertificates pck_certificates = CreateValidPckCertificates(2);
  *pck_certificates.mutable_certs(1)->mutable_tcb_level() =
      pck_certificates.certs(0).tcb_level();
  EXPECT_THAT(ValidatePckCertificates(pck_certificates),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PckCertificateUtilTest,
     PckCertificatesWithDistinctEntriesWithSameTcbmIsInvalid) {
  PckCertificates pck_certificates = CreateValidPckCertificates(2);
  *pck_certificates.mutable_certs(1)->mutable_tcbm() =
      pck_certificates.certs(0).tcbm();
  EXPECT_THAT(ValidatePckCertificates(pck_certificates),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PckCertificateUtilTest, ValidPckCertificatesIsValid) {
  ASYLO_EXPECT_OK(ValidatePckCertificates(CreateValidPckCertificates(0)));
  ASYLO_EXPECT_OK(ValidatePckCertificates(CreateValidPckCertificates(1)));
  ASYLO_EXPECT_OK(ValidatePckCertificates(CreateValidPckCertificates(74)));
}

TEST(PckCertificateUtilTest, PckCertificatesWithRepeatedEntriesIsValid) {
  PckCertificates pck_certificates = CreateValidPckCertificates(1);
  *pck_certificates.add_certs() = pck_certificates.certs(0);
  ASYLO_EXPECT_OK(ValidatePckCertificates(pck_certificates));
}

TEST(PckCertificateUtilTest,
     ExtractMachineConfigurationFromPckCertWithoutSgxExtensionsFails) {
  std::unique_ptr<X509Certificate> cert;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      cert,
      X509Certificate::Create(GetFakePckCertificateChain().certificates(2)));

  ASSERT_THAT(ExtractMachineConfigurationFromPckCert(cert.get()),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("SGX extensions")));
}

TEST(PckCertificateUtilTest,
     ExtractMachineConfigurationFromPckCertFromNonX509CertFails) {
  Certificate non_x509_cert;
  non_x509_cert.set_format(Certificate::SGX_ATTESTATION_KEY_CERTIFICATE);
  non_x509_cert.set_data(absl::HexStringToBytes(kAttestationKeyCertificateHex));

  std::unique_ptr<AttestationKeyCertificateImpl> cert;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      cert, AttestationKeyCertificateImpl::Create(non_x509_cert));

  ASSERT_THAT(ExtractMachineConfigurationFromPckCert(cert.get()),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("X.509 certificate")));
}

TEST(PckCertificateUtilTest, ExtractMachineConfigurationFromPckCertSuccess) {
  std::unique_ptr<CertificateInterface> cert;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      cert, X509Certificate::Create(
                *GetFakePckCertificateChain().certificates().begin()));

  MachineConfiguration machine_configuration =
      ParseTextProtoOrDie(kFakePckMachineConfigurationTextProto);

  ASSERT_THAT(ExtractMachineConfigurationFromPckCert(cert.get()),
              IsOkAndHolds(EqualsProto(machine_configuration)));
}

TEST(PckCertificateUtilTest, ExtractSgxExtensionFromPckCertNonX509Fails) {
  Certificate non_x509_cert;
  non_x509_cert.set_format(Certificate::SGX_ATTESTATION_KEY_CERTIFICATE);
  non_x509_cert.set_data(absl::HexStringToBytes(kAttestationKeyCertificateHex));

  std::unique_ptr<CertificateInterface> cert;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      cert, AttestationKeyCertificateImpl::Create(non_x509_cert));

  EXPECT_THAT(ExtractSgxExtensionsFromPckCert(*cert),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PckCertificateUtilTest,
     ExtractSgxExtensionFromPckCertNoSgxExtensionsFails) {
  CertificateChain pck_cert_chain = GetFakePckCertificateChain();

  std::unique_ptr<CertificateInterface> cert;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      cert, X509Certificate::Create(pck_cert_chain.certificates(1)));

  EXPECT_THAT(ExtractSgxExtensionsFromPckCert(*cert),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PckCertificateUtilTest, ExtractSgxExtensionFromPckCertSuccess) {
  CertificateChain pck_cert_chain = GetFakePckCertificateChain();
  std::unique_ptr<CertificateInterface> cert;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      cert, X509Certificate::Create(pck_cert_chain.certificates(0)));

  EXPECT_THAT(
      ExtractSgxExtensionsFromPckCert(*cert),
      IsOkAndHolds(SgxExtensionsEquals(GetFakePckCertificateExtensions())));
}

TEST(PckCertificateUtilTest, ExtractCpuSvnFromPckCertNonX509Fails) {
  Certificate non_x509_cert;
  non_x509_cert.set_format(Certificate::SGX_ATTESTATION_KEY_CERTIFICATE);
  non_x509_cert.set_data(absl::HexStringToBytes(kAttestationKeyCertificateHex));

  ASSERT_THAT(ExtractCpuSvnFromPckCert(non_x509_cert),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PckCertificateUtilTest, ExtractCpuSvnFromPckCertNoSgxExtensionsFails) {
  CertificateChain pck_cert_chain = GetFakePckCertificateChain();

  ASSERT_THAT(ExtractCpuSvnFromPckCert(pck_cert_chain.certificates(1)),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PckCertificateUtilTest, ExtractCpuSvnFromPckCertSuccess) {
  CertificateChain pck_cert_chain = GetFakePckCertificateChain();

  MachineConfiguration machine_configuration =
      ParseTextProtoOrDie(kFakePckMachineConfigurationTextProto);

  ASSERT_THAT(ExtractCpuSvnFromPckCert(pck_cert_chain.certificates(0)),
              IsOkAndHolds(EqualsProto(machine_configuration.cpu_svn())));
}

TEST(PckCertificateUtilTest, ExtractPceSvnFromPckCertNonX509Fails) {
  Certificate non_x509_cert;
  non_x509_cert.set_format(Certificate::SGX_ATTESTATION_KEY_CERTIFICATE);
  non_x509_cert.set_data(absl::HexStringToBytes(kAttestationKeyCertificateHex));

  ASSERT_THAT(ExtractPceSvnFromPckCert(non_x509_cert),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PckCertificateUtilTest, ExtractPceSvnFromPckCertNoSgxExtensionsFails) {
  CertificateChain pck_cert_chain = GetFakePckCertificateChain();

  ASSERT_THAT(ExtractPceSvnFromPckCert(pck_cert_chain.certificates(1)),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PckCertificateUtilTest, ExtractPceSvnFromPckCertSuccess) {
  CertificateChain pck_cert_chain = GetFakePckCertificateChain();

  PceSvn expected_pce_svn;
  expected_pce_svn.set_value(2);

  ASSERT_THAT(ExtractPceSvnFromPckCert(pck_cert_chain.certificates(0)),
              IsOkAndHolds(EqualsProto(expected_pce_svn)));
}

}  // namespace
}  // namespace sgx
}  // namespace asylo
