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

#include "asylo/crypto/certificate_chain_util.h"

#include <string>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/memory/memory.h"
#include "absl/strings/str_split.h"
#include "asylo/crypto/certificate.pb.h"
#include "asylo/crypto/certificate_util_interface.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace {

constexpr char kRootCertData[] = "f00d f00d";
constexpr char kIntermediateCertData[] = "c0ff33 f00d";
constexpr char kEndCertData[] = "c0c0a c0ff33";
constexpr char kEndSubjectKey[] = "c0c0a";
constexpr char kOtherCertData[] = "c0c0a b3375";

// A fake certificate util. It expect certificate protos with the given format:
//
//   message Certificate {
//     format: <any>,
//     data: subject_key + " " + issuer_key,
//   }
//
// VerifyCertificate will return an OK Status if |public_key_der| = issuer_key
// and ExtractSubjectKeyDer returns |public_key|. Key values cannot include
// spaces.
class FakeCertificateUtil : public CertificateUtilInterface {
 public:
  // From CertificateUtilInterface.

  Status VerifyCertificate(const Certificate &certificate,
                           ByteContainerView public_key_der) const override {
    std::vector<std::string> split_data =
        absl::StrSplit(certificate.data(), ' ');

    if (split_data.size() != 2) {
      return Status(error::GoogleError::INTERNAL, "Data split failed");
    }

    if (ByteContainerView(split_data[1]) != public_key_der) {
      return Status(error::GoogleError::UNAUTHENTICATED, "Verification failed");
    }

    return Status::OkStatus();
  }

  StatusOr<std::string> ExtractSubjectKeyDer(
      const Certificate &certificate) const override {
    std::vector<std::string> split_data =
        absl::StrSplit(certificate.data(), ' ');

    if (split_data.size() != 2) {
      return Status(error::GoogleError::INTERNAL, "Data split failed");
    }

    return split_data[0];
  }
};

CertificateChain CreateCertChain() {
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

TEST(CertificateChainUtilTest, VerifyCertificateChainSuccess) {
  CertificateChainUtil util;
  ASSERT_TRUE(util.AddCertificateUtil(
      Certificate::X509_PEM, absl::make_unique<FakeCertificateUtil>()));
  ASSERT_TRUE(util.AddCertificateUtil(
      Certificate::X509_DER, absl::make_unique<FakeCertificateUtil>()));

  ASYLO_EXPECT_OK(util.VerifyCertificateChain(CreateCertChain()));
}

TEST(CertificateChainUtilTest, VerifyCertificateChainInvalidChain) {
  CertificateChainUtil util;
  ASSERT_TRUE(util.AddCertificateUtil(
      Certificate::X509_PEM, absl::make_unique<FakeCertificateUtil>()));

  CertificateChain chain = CreateCertChain();

  chain.mutable_certificates(1)->set_format(Certificate::X509_PEM);
  chain.mutable_certificates(1)->set_data(kOtherCertData);

  EXPECT_THAT(util.VerifyCertificateChain(chain),
              StatusIs(asylo::error::GoogleError::UNAUTHENTICATED));
}

TEST(CertificateChainUtilTest, VerifyCertificateChainMissingFormat) {
  CertificateChainUtil util;
  ASSERT_TRUE(util.AddCertificateUtil(
      Certificate::X509_PEM, absl::make_unique<FakeCertificateUtil>()));

  EXPECT_THAT(util.VerifyCertificateChain(CreateCertChain()),
              StatusIs(asylo::error::GoogleError::INVALID_ARGUMENT));
}

TEST(CertificateChainUtilTest, GetEndUserSubjectKeySuccess) {
  CertificateChainUtil util;
  ASSERT_TRUE(util.AddCertificateUtil(
      Certificate::X509_PEM, absl::make_unique<FakeCertificateUtil>()));

  EXPECT_THAT(util.GetEndUserSubjectKey(CreateCertChain()),
              IsOkAndHolds(kEndSubjectKey));
}

TEST(CertificateChainUtilTest, GetEndUserSubjectKeyMissingFormat) {
  CertificateChainUtil util;
  EXPECT_THAT(util.GetEndUserSubjectKey(CreateCertChain()).status(),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

}  // namespace
}  // namespace asylo
