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

#include "asylo/identity/provisioning/sgx/internal/tcb_info_reader.h"

#include <string>
#include <tuple>
#include <utility>

#include <google/protobuf/text_format.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "asylo/identity/platform/sgx/internal/identity_key_management_structs.h"
#include "asylo/identity/platform/sgx/machine_configuration.pb.h"
#include "asylo/identity/provisioning/sgx/internal/platform_provisioning.pb.h"
#include "asylo/test/util/proto_matchers.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status.h"

namespace asylo {
namespace sgx {
namespace {

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

TEST(TcbInfoReaderTest, CreateFailsOnInvalidTcbInfo) {
  EXPECT_THAT(TcbInfoReader::Create(TcbInfo()),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(TcbInfoReaderTest, GetTcbInfoReturnsInputTcbInfo) {
  TcbInfo tcb_info;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(kBaseTcbInfo, &tcb_info));
  TcbInfoReader reader;
  ASYLO_ASSERT_OK_AND_ASSIGN(reader, TcbInfoReader::Create(tcb_info));
  EXPECT_THAT(reader.GetTcbInfo(), EqualsProto(tcb_info));
}

TEST(TcbInfoReaderTest, GetConfigurationIdFailsOnInvalidCpuSvn) {
  TcbInfo tcb_info;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(kBaseTcbInfo, &tcb_info));
  TcbInfoReader reader;
  ASYLO_ASSERT_OK_AND_ASSIGN(reader, TcbInfoReader::Create(tcb_info));

  EXPECT_THAT(reader.GetConfigurationId(CpuSvn()),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(TcbInfoReaderTest, GetConfigurationIdReadsCorrectConfigurationId) {
  TcbInfo tcb_info;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(kBaseTcbInfo, &tcb_info));
  TcbInfoReader reader;
  ASYLO_ASSERT_OK_AND_ASSIGN(reader, TcbInfoReader::Create(tcb_info));

  CpuSvn cpu_svn;
  cpu_svn.set_value(std::string(kCpusvnSize, 0));
  ConfigurationId expected_config_id;
  expected_config_id.set_value(0);
  EXPECT_THAT(reader.GetConfigurationId(cpu_svn),
              IsOkAndHolds(EqualsProto(expected_config_id)));

  (*cpu_svn.mutable_value())[6] = 12;
  expected_config_id.set_value(12);
  EXPECT_THAT(reader.GetConfigurationId(cpu_svn),
              IsOkAndHolds(EqualsProto(expected_config_id)));
}

TEST(TcbInfoReaderTest, GetConsistencyWithFailsOnInvalidPckCertificates) {
  TcbInfo tcb_info;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(kBaseTcbInfo, &tcb_info));
  TcbInfoReader reader;
  ASYLO_ASSERT_OK_AND_ASSIGN(reader, TcbInfoReader::Create(tcb_info));

  PckCertificates pck_certificates;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(kBasePckCertificates,
                                                  &pck_certificates));
  pck_certificates.mutable_certs(0)->clear_cert();
  EXPECT_THAT(reader.GetConsistencyWith(pck_certificates),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

class TcbInfoReaderGetConsistencyWithTest
    : public TestWithParam<
          std::tuple<const char *, const char *, ProvisioningConsistency>> {};

TEST_P(TcbInfoReaderGetConsistencyWithTest,
       IdentifiesConsistencyRelationshipsCorrectly) {
  std::string tcb_info_textproto;
  std::string pck_certificates_textproto;
  ProvisioningConsistency expected_consistency;
  std::tie(tcb_info_textproto, pck_certificates_textproto,
           expected_consistency) = GetParam();

  TcbInfo tcb_info;
  ASSERT_TRUE(
      google::protobuf::TextFormat::ParseFromString(tcb_info_textproto, &tcb_info));
  TcbInfoReader reader;
  ASYLO_ASSERT_OK_AND_ASSIGN(reader, TcbInfoReader::Create(tcb_info));

  PckCertificates pck_certificates;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(pck_certificates_textproto,
                                                  &pck_certificates));
  EXPECT_THAT(reader.GetConsistencyWith(pck_certificates),
              IsOkAndHolds(expected_consistency));
}

INSTANTIATE_TEST_SUITE_P(
    AllPossibleConsistencies, TcbInfoReaderGetConsistencyWithTest,
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
