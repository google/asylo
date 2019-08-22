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

#include "asylo/identity/sgx/provisioning_consistency_checker.h"

#include <string>
#include <tuple>

#include <google/protobuf/text_format.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/strings/string_view.h"
#include "absl/types/span.h"

namespace asylo {
namespace sgx {
namespace {

using ::testing::Eq;
using ::testing::TestWithParam;
using ::testing::Values;

// Test provisioning information. kBaseTcbInfo and kBasePckCertificates are for
// the same TCB levels. However, kExtendedTcbInfo and kExtendedPckCertificates
// each add an extra TCB level, and the TCB levels that they add are different.
constexpr char kBaseTcbInfo[] =
    R"proto(
  impl {
    version: 1
    issue_date { seconds: 1582230020 nanos: 0 }
    next_update { seconds: 1584735620 nanos: 0 }
    fmspc { value: "\x01\x23\x45\x67\x89\xab" }
    pce_id { value: 0 }
    tcb_levels {
      tcb {
        components: "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
        pce_svn { value: 2 }
      }
      status { known_status: UP_TO_DATE }
    }
  }
    )proto";
constexpr char kExtendedTcbInfo[] =
    R"proto(
  impl {
    version: 1
    issue_date { seconds: 1583230020 nanos: 0 }
    next_update { seconds: 1585735620 nanos: 0 }
    fmspc { value: "\x01\x23\x45\x67\x89\xab" }
    pce_id { value: 0 }
    tcb_levels {
      tcb {
        components: "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
        pce_svn { value: 3 }
      }
      status { known_status: UP_TO_DATE }
    }
    tcb_levels {
      tcb {
        components: "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
        pce_svn { value: 2 }
      }
      status { known_status: OUT_OF_DATE }
    }
  }
    )proto";
constexpr char kBasePckCertificates[] =
    R"proto(
  certs {
    tcb_level {
      components: "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
      pce_svn { value: 2 }
    }
    tcbm {
      cpu_svn {
        value: "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
      }
      pce_svn { value: 2 }
    }
    cert { format: X509_PEM data: "Certificate!!!!!" }
  }
    )proto";
constexpr char kExtendedPckCertificates[] =
    R"proto(
  certs {
    tcb_level {
      components: "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
      pce_svn { value: 4 }
    }
    tcbm {
      cpu_svn {
        value: "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
      }
      pce_svn { value: 4 }
    }
    cert { format: X509_PEM data: "Another certificate!!!!!" }
  }
  certs {
    tcb_level {
      components: "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
      pce_svn { value: 2 }
    }
    tcbm {
      cpu_svn {
        value: "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
      }
      pce_svn { value: 2 }
    }
    cert { format: X509_PEM data: "Certificate!!!!!" }
  }
    )proto";

class ProvisioningConsistencyCheckerTest
    : public TestWithParam<
          std::tuple<const char *, const char *, ProvisioningConsistency>> {};

TEST_P(
    ProvisioningConsistencyCheckerTest,
    ProvisioningConsistencyCheckerIdentifiesConsistencyRelationshipsCorrectly) {
  std::string tcb_info_textproto;
  std::string pck_certificates_textproto;
  ProvisioningConsistency expected_consistency;
  std::tie(tcb_info_textproto, pck_certificates_textproto,
           expected_consistency) = GetParam();

  TcbInfo tcb_info;
  ASSERT_TRUE(
      google::protobuf::TextFormat::ParseFromString(tcb_info_textproto, &tcb_info));
  ProvisioningConsistencyChecker reader(tcb_info);

  PckCertificates pck_certificates;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(pck_certificates_textproto,
                                                  &pck_certificates));
  EXPECT_THAT(reader.GetConsistencyWith(pck_certificates),
              Eq(expected_consistency));
}

INSTANTIATE_TEST_SUITE_P(
    AllPossibleConsistencies, ProvisioningConsistencyCheckerTest,
    Values(std::make_tuple(kBaseTcbInfo, kBasePckCertificates,
                           ProvisioningConsistency::kConsistent),
           std::make_tuple(kBaseTcbInfo, kExtendedPckCertificates,
                           ProvisioningConsistency::kTcbInfoStale),
           std::make_tuple(kExtendedTcbInfo, kBasePckCertificates,
                           ProvisioningConsistency::kPckCertificatesStale),
           std::make_tuple(kExtendedTcbInfo, kExtendedPckCertificates,
                           ProvisioningConsistency::kOtherInconsistency)));

}  // namespace
}  // namespace sgx
}  // namespace asylo
