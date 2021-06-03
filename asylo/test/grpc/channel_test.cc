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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/memory/memory.h"
#include "absl/time/time.h"
#include "asylo/util/logging.h"
#include "asylo/grpc/auth/enclave_channel_credentials.h"
#include "asylo/grpc/auth/enclave_server_credentials.h"
#include "asylo/grpc/auth/null_credentials_options.h"
#include "asylo/grpc/util/grpc_server_launcher.h"
#include "asylo/identity/enclave_assertion_authority_config.pb.h"
#include "asylo/identity/init.h"
#include "asylo/test/grpc/messenger_client_impl.h"
#include "asylo/test/grpc/messenger_server_impl.h"
#include "asylo/test/util/enclave_assertion_authority_configs.h"
#include "asylo/test/util/status_matchers.h"

namespace asylo {
namespace {

constexpr char kInput[] = "foobar";
constexpr char kAddress[] = "[::1]";
const int64_t kDeadlineMicros = absl::Seconds(10) / absl::Microseconds(1);

struct CredentialsConfig {
  std::shared_ptr<::grpc::ChannelCredentials> channel_credentials;
  std::shared_ptr<::grpc::ServerCredentials> server_credentials;
};

struct InsecureCredentialsConfig : public CredentialsConfig {
  InsecureCredentialsConfig() {
    channel_credentials = ::grpc::InsecureChannelCredentials();
    server_credentials = ::grpc::InsecureServerCredentials();
  }
};

struct EnclaveCredentialsConfig : public CredentialsConfig {
  EnclaveCredentialsConfig() {
    channel_credentials = EnclaveChannelCredentials(
        BidirectionalNullCredentialsOptions());
    server_credentials = EnclaveServerCredentials(
        BidirectionalNullCredentialsOptions());
  }
};

// A test fixture is required for typed tests.
template <typename ConfigT>
class ChannelTest : public ::testing::Test {
 public:
  void SetUp() override {
    // Set up assertion authority configs.
    std::vector<EnclaveAssertionAuthorityConfig> authority_configs = {
      GetNullAssertionAuthorityTestConfig()
    };

    // Explicitly initialize the null assertion authorities.
    ASSERT_THAT(InitializeEnclaveAssertionAuthorities(
                    authority_configs.cbegin(), authority_configs.cend()),
                IsOk());
  }
};

using TestTypes =
    ::testing::Types<InsecureCredentialsConfig, EnclaveCredentialsConfig>;
TYPED_TEST_SUITE(ChannelTest, TestTypes);

TYPED_TEST(ChannelTest, EndToEnd) {
  GrpcServerLauncher launcher("ChannelTest");
  TypeParam config = TypeParam();
  int port = 0;
  std::string server_address = absl::StrCat(kAddress, ":", port);

  // Start a server that hosts one service inside the enclave.
  ASSERT_THAT(
      launcher.RegisterService(absl::make_unique<test::MessengerServer1>()),
      IsOk());
  ASSERT_THAT(launcher.AddListeningPort(server_address,
                                        config.server_credentials, &port),
              IsOk());
  ASSERT_THAT(launcher.Start(), IsOk());
  ASSERT_NE(port, 0);

  // Update the server address with the auto-selected port.
  server_address = absl::StrCat(kAddress, ":", port);

  // Connect a client from inside the enclave to the server.
  std::shared_ptr<::grpc::Channel> channel =
      ::grpc::CreateChannel(server_address, config.channel_credentials);
  gpr_timespec absolute_deadline =
      gpr_time_add(gpr_now(GPR_CLOCK_REALTIME),
                   gpr_time_from_micros(kDeadlineMicros, GPR_TIMESPAN));
  ASSERT_TRUE(channel->WaitForConnected(absolute_deadline));

  // Make an RPC.
  test::MessengerClient1 client(channel);
  StatusOr<std::string> result = client.Hello(kInput);
  ASSERT_THAT(result, IsOk());
  EXPECT_EQ(result.value(), test::MessengerServer1::ResponseString(kInput));

  // Shut down the server.
  ASSERT_THAT(launcher.Shutdown(), IsOk());
}

}  // namespace
}  // namespace asylo
