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

#include <memory>
#include <string>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/memory/memory.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_split.h"
#include "absl/types/optional.h"
#include "asylo/crypto/certificate.pb.h"
#include "asylo/crypto/certificate_interface.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"

namespace asylo {
namespace {

constexpr char kRootKey[] = "f00d";
constexpr char kIntermediateKey[] = "c0ff33";
constexpr char kExtraIntermediateKey[] = "c0c0a";
constexpr char kEndUserKey[] = "fun";

// Test data for a valid FakeCertificate chain with explicit pathlengths.
constexpr char kRootCertData[] = "f00d f00d 1-t";
constexpr char kIntermediateCertData[] = "c0ff33 f00d 0-t";
constexpr char kEndCertData[] = "fun c0ff33 -";

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

// A fake certificate. It expects certificate protos with the given data
// encoding:
//
//   message Certificate {
//     format: <any>,
//     data: subject_key + " " + issuer_key + " " + [pathlength] + "-" + [ca],
//   }
//
// Verify() returns an OK Status if |issuer_certificate|.SubjectKeyDer() =
// issuer_key. SubjectKeyDer() returns subject_key. CertPathLength() returns
// pathlength, if a value is included. Key values cannot include spaces.
// Pathlength must be a valid integer. The ca value must be empty, t, or f.
class FakeCertificate : public CertificateInterface {
 public:
  FakeCertificate(absl::string_view subject_key, absl::string_view issuer_key,
                  absl::optional<int> pathlength, absl::optional<bool> is_ca)
      : subject_key_(subject_key),
        issuer_key_(issuer_key),
        pathlength_(pathlength),
        is_ca_(is_ca) {}
  static StatusOr<std::unique_ptr<FakeCertificate>> Create(
      const Certificate &certificate) {
    std::vector<std::string> split_data =
        absl::StrSplit(certificate.data(), ' ');

    if (split_data.size() != 3) {
      return Status(error::GoogleError::INVALID_ARGUMENT, "Data split failed");
    }

    std::vector<std::string> split_basic_constraints =
        absl::StrSplit(split_data[2], '-');
    if (split_basic_constraints.size() != 2) {
      return Status(
          error::GoogleError::INVALID_ARGUMENT,
          "Third value must be in the format [int] + \" - \" + [|t|f]");
    }

    absl::optional<bool> is_ca;
    if (split_basic_constraints[1] == "t") {
      is_ca = true;
    } else if (split_basic_constraints[1] == "f") {
      is_ca = false;
    } else if (split_basic_constraints[1].empty()) {
      is_ca = absl::nullopt;
    } else {
      return Status(
          error::GoogleError::INVALID_ARGUMENT,
          "Third value must be in the format [int] + \" - \" + [|t|f]");
    }

    if (split_basic_constraints[0].empty()) {
      return absl::make_unique<FakeCertificate>(split_data[0], split_data[1],
                                                absl::nullopt, is_ca);
    }

    int pathlen;
    if (!absl::SimpleAtoi(split_basic_constraints[0], &pathlen)) {
      return Status(
          error::GoogleError::INVALID_ARGUMENT,
          "Third value must be in the format [int] + \" - \" + [|t|f]");
    }
    return absl::make_unique<FakeCertificate>(split_data[0], split_data[1],
                                              pathlen, is_ca);
  }

  // From CertificateInterface.

  Status Verify(const CertificateInterface &issuer_certificate,
                const VerificationConfig &config) const override {
    std::string issuer_subject_key;
    ASYLO_ASSIGN_OR_RETURN(issuer_subject_key,
                           issuer_certificate.SubjectKeyDer());
    if (issuer_key_ != issuer_subject_key) {
      return Status(error::GoogleError::UNAUTHENTICATED, "Verification failed");
    }

    return Status::OkStatus();
  }

  StatusOr<std::string> SubjectKeyDer() const override { return subject_key_; }

  absl::optional<bool> IsCa() const override { return is_ca_; }

  absl::optional<int64_t> CertPathLength() const override {
    return pathlength_;
  }

  absl::optional<KeyUsageInformation> KeyUsage() const override {
    return absl::nullopt;
  }

 private:
  std::string subject_key_;
  std::string issuer_key_;
  absl::optional<int> pathlength_;
  absl::optional<bool> is_ca_;
};

// Returned chain:
// {
//   certificates: [
//     {
//       format: X509_PEM,
//       data: kEndCertData,
//     },
//     {
//       format: X509_DER,
//       data: kIntermediateCertData,
//     },
//     {
//       format: X509_PEM,
//       data: kRootCertData,
//     },
//   ]
// }
CertificateChain TestCertificateChain() {
  CertificateChain chain;

  Certificate end_cert;
  end_cert.set_format(Certificate::X509_PEM);
  end_cert.set_data(kEndCertData);
  *chain.add_certificates() = end_cert;

  Certificate intermediate_cert;
  intermediate_cert.set_format(Certificate::X509_DER);
  intermediate_cert.set_data(kIntermediateCertData);
  *chain.add_certificates() = intermediate_cert;

  Certificate root_cert;
  root_cert.set_format(Certificate::X509_PEM);
  root_cert.set_data(kRootCertData);
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
      kEndUserKey, kIntermediateKey, absl::nullopt, absl::nullopt));
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kIntermediateKey, kRootKey, 0, absl::nullopt));
  chain.emplace_back(
      absl::make_unique<FakeCertificate>(kRootKey, kRootKey, 1, absl::nullopt));

  VerificationConfig config(/*all_fields=*/true);
  ASYLO_EXPECT_OK(VerifyCertificateChain(absl::MakeConstSpan(chain), config));
}

TEST(CertificateUtilTest, VerifyCertificateChainSuccessWithoutPathLengths) {
  CertificateInterfaceVector chain;
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kEndUserKey, kIntermediateKey, absl::nullopt, absl::nullopt));
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kIntermediateKey, kRootKey, absl::nullopt, true));
  chain.emplace_back(absl::make_unique<FakeCertificate>(kRootKey, kRootKey,
                                                        absl::nullopt, false));

  VerificationConfig config(/*all_fields=*/true);
  ASYLO_EXPECT_OK(VerifyCertificateChain(absl::MakeConstSpan(chain), config));
}

TEST(CertificateUtilTest, VerifyCertificateChainVerificationErrorForwarded) {
  CertificateInterfaceVector chain;
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kEndUserKey, kExtraIntermediateKey, absl::nullopt, absl::nullopt));
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kIntermediateKey, kRootKey, 0, absl::nullopt));
  chain.emplace_back(
      absl::make_unique<FakeCertificate>(kRootKey, kRootKey, 1, absl::nullopt));

  VerificationConfig config(/*all_fields=*/false);
  EXPECT_THAT(VerifyCertificateChain(absl::MakeConstSpan(chain), config),
              StatusIs(error::GoogleError::UNAUTHENTICATED));
}

TEST(CertificateUtilTest, VerifyCertificateChainBadRootPathlen) {
  CertificateInterfaceVector chain;
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kEndUserKey, kIntermediateKey, absl::nullopt, absl::nullopt));
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kIntermediateKey, kRootKey, 0, absl::nullopt));
  chain.emplace_back(
      absl::make_unique<FakeCertificate>(kRootKey, kRootKey, 0, absl::nullopt));

  VerificationConfig config(/*all_fields=*/true);
  EXPECT_THAT(VerifyCertificateChain(absl::MakeConstSpan(chain), config),
              StatusIs(error::GoogleError::UNAUTHENTICATED));
}

TEST(CertificateUtilTest, VerifyCertificateChainBadIntermediatePathlen) {
  CertificateInterfaceVector chain;
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kEndUserKey, kExtraIntermediateKey, absl::nullopt, absl::nullopt));
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kExtraIntermediateKey, kIntermediateKey, 0, absl::nullopt));
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kIntermediateKey, kRootKey, 0, absl::nullopt));
  chain.emplace_back(
      absl::make_unique<FakeCertificate>(kRootKey, kRootKey, 2, absl::nullopt));

  VerificationConfig config(/*all_fields=*/true);
  EXPECT_THAT(VerifyCertificateChain(absl::MakeConstSpan(chain), config),
              StatusIs(error::GoogleError::UNAUTHENTICATED));
}

TEST(CertificateUtilTest, VerifyCertificateChainBadPathlenNoCheck) {
  CertificateInterfaceVector chain;
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kEndUserKey, kIntermediateKey, absl::nullopt, absl::nullopt));
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kIntermediateKey, kRootKey, 0, absl::nullopt));
  chain.emplace_back(
      absl::make_unique<FakeCertificate>(kRootKey, kRootKey, 0, absl::nullopt));

  VerificationConfig config(/*all_fields=*/false);
  ASYLO_EXPECT_OK(VerifyCertificateChain(absl::MakeConstSpan(chain), config));
}

TEST(CertificateUtilTest, VerifyCertificateChainCaValuesSet) {
  CertificateInterfaceVector chain;
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kEndUserKey, kExtraIntermediateKey, absl::nullopt, false));
  chain.emplace_back(absl::make_unique<FakeCertificate>(
      kExtraIntermediateKey, kIntermediateKey, absl::nullopt, false));
  chain.emplace_back(
      absl::make_unique<FakeCertificate>(kIntermediateKey, kRootKey, 0, true));
  chain.emplace_back(
      absl::make_unique<FakeCertificate>(kRootKey, kRootKey, 1, true));

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
