/*
 *
 * Copyright 2018 Asylo authors
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

#include "asylo/util/remote/remote_proxy_config.h"

#include <memory>
#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "asylo/platform/primitives/remote/util/grpc_credential_builder.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/remote/provision.h"

namespace asylo {
namespace {

using ::testing::Eq;
using ::testing::IsNull;
using ::testing::Not;
using ::testing::Return;
using ::testing::StrEq;

constexpr char kViewNameRoot[] = "test_root";
constexpr char kHostAddress[] = "[1234:abcd:5678:f12::ab]:1234";
constexpr char kLocalAddress[] = "[::]";

class MockProvision : public RemoteProvision {
 public:
  MOCK_METHOD(StatusOr<std::string>, Provision,
              (int32_t client_port, absl::string_view enclave_path),
              (override));
  MOCK_METHOD(void, Finalize, (), (override));
};

TEST(RemoteProxyClientConfigTest, DefaultsAreAsExpected) {
  std::unique_ptr<RemoteProxyClientConfig> config;
  ASYLO_ASSERT_OK_AND_ASSIGN(config,
                             RemoteProxyClientConfig::DefaultsWithProvision(
                                 absl::make_unique<MockProvision>()));

  EXPECT_THAT(config->channel_creds(), Not(IsNull()));
  EXPECT_THAT(config->server_creds(), Not(IsNull()));
}

TEST(RemoteProxyClientConfigTest, FinalizeRunsCorrectly) {
  static constexpr char kSourceEnclave[] = "source_path";
  static constexpr char kProvisionedEnclave[] = "provisioned_path";
  auto provision = absl::make_unique<MockProvision>();
  auto raw_provision = provision.get();
  std::unique_ptr<RemoteProxyClientConfig> config;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      config,
      RemoteProxyClientConfig::DefaultsWithProvision(std::move(provision)));
  EXPECT_CALL(*raw_provision,
              Provision(1234, absl::string_view(kSourceEnclave)))
      .WillOnce(Return(kProvisionedEnclave));
  std::string provisioned_path;
  ASYLO_ASSERT_OK_AND_ASSIGN(provisioned_path,
                             config->RunProvision(1234, kSourceEnclave));
  EXPECT_THAT(provisioned_path, StrEq(kProvisionedEnclave));
  EXPECT_CALL(*raw_provision, Finalize()).WillOnce(Return());
  config->RunFinalize();
}

TEST(RemoteProxyClientConfigTest, OpenCensusMetricsConfigAddedCorrectly) {
  const absl::Duration granularity = absl::Seconds(1);

  std::unique_ptr<RemoteProxyClientConfig> config;
  ASYLO_ASSERT_OK_AND_ASSIGN(config,
                             RemoteProxyClientConfig::DefaultsWithProvision(
                                 absl::make_unique<MockProvision>()));
  EXPECT_THAT(config->HasOpenCensusMetricsConfig(), Eq(false));
  EXPECT_THAT(config->GetOpenCensusMetricsConfig(),
              StatusIs(absl::StatusCode::kFailedPrecondition));

  config->EnableOpenCensusMetricsCollection(granularity, kViewNameRoot);
  EXPECT_THAT(config->HasOpenCensusMetricsConfig(), Eq(true));

  StatusOr<const OpenCensusClientConfig> config_result =
      config->GetOpenCensusMetricsConfig();

  EXPECT_THAT(config_result, IsOk());
  EXPECT_THAT(config_result.value().granularity, Eq(granularity));
  EXPECT_THAT(config_result.value().view_name_root, StrEq(kViewNameRoot));
}

TEST(RemoteProxyServerConfigTest, DefaultsAreAsExpected) {
  std::unique_ptr<RemoteProxyServerConfig> config;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      config, RemoteProxyServerConfig::DefaultsWithHostAddress(kHostAddress));
  EXPECT_THAT(config->host_address(), StrEq(kHostAddress));
  EXPECT_THAT(config->local_address(), StrEq(kLocalAddress));
  EXPECT_THAT(config->channel_creds(), Not(IsNull()));
  EXPECT_THAT(config->server_creds(), Not(IsNull()));
}

}  // namespace
}  // namespace asylo
