/*
 *
 * Copyright 2017 Asylo authors
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

#include <cstdint>
#include <thread>
#include <vector>

#include <gtest/gtest.h>
#include "absl/strings/str_cat.h"
#include "asylo/grpc/auth/enclave_channel_credentials.h"
#include "asylo/grpc/auth/null_credentials_options.h"
#include "asylo/grpc/util/enclave_server.pb.h"
#include "asylo/identity/init.h"
#include "asylo/test/grpc/messenger_client_impl.h"
#include "asylo/test/grpc/messenger_server_impl.h"
#include "asylo/test/util/enclave_assertion_authority_configs.h"
#include "asylo/test/util/enclave_test.h"
#include "asylo/test/util/status_matchers.h"
#include "include/grpcpp/channel.h"
#include "include/grpcpp/create_channel.h"
#include "include/grpcpp/security/credentials.h"

namespace asylo {
namespace test {
namespace {

using ::testing::Not;

constexpr char kName[] = "test";

constexpr const char kAddress[] = "[::1]";

// A simple end-to-end test for enclave gRPC security.
class EnclaveSecureGrpcTest : public EnclaveTest {
 protected:
  void SetUp() override {
    // Add config to initialize null assertion authorities in the enclave.
    *config_.add_enclave_assertion_authority_configs() =
        GetNullAssertionAuthorityTestConfig();

    // Use the same configs to initialize null assertion authorities on the
    // host.
    ASSERT_THAT(InitializeEnclaveAssertionAuthorities(
                    config_.enclave_assertion_authority_configs().cbegin(),
                    config_.enclave_assertion_authority_configs().cend()),
                IsOk());

    // Set server's address and port configuration.
    ServerConfig *config = config_.MutableExtension(server_input_config);
    config->set_host(kAddress);
    // Use a port of 0 for port auto-selection.
    config->set_port(0);
    address_ = absl::StrCat(config->host(), ":", config->port());

    EnclaveTest::SetUp();
  }

  std::string address_;
};

// Starts a gRPC server in an enclave and calls this server with an untrusted
// gRPC client. Client and server use null-assertion-based enclave credentials.
TEST_F(EnclaveSecureGrpcTest, SimpleEnd2EndTest) {
  // The gRPC server was launched during initialization of the enclave.
  // Get the gRPC server's address through the enclave's Run() entry-point.
  EnclaveOutput output;
  ASSERT_THAT(client_->EnterAndRun(/*input=*/{}, &output), IsOk());
  ASSERT_TRUE(output.HasExtension(server_output_config));
  const ServerConfig &config = output.GetExtension(server_output_config);
  ASSERT_NE(config.port(), 0);
  address_ = absl::StrCat(config.host(), ":", config.port());

  // Create an EnclaveChannelCredentials object to configure the underlying
  // security mechanism for the channel.
  std::shared_ptr<::grpc::ChannelCredentials> channel_credentials =
      EnclaveChannelCredentials(BidirectionalNullCredentialsOptions());

  // Create a channel using the secure credentials and wait 30 seconds for the
  // channel to connect to the server.
  auto channel = ::grpc::CreateChannel(address_, channel_credentials);
  gpr_timespec absolute_deadline = gpr_time_add(
      gpr_now(GPR_CLOCK_REALTIME),
      gpr_time_from_micros(static_cast<int64_t>(30 * 1e6), GPR_TIMESPAN));
  EXPECT_TRUE(channel->WaitForConnected(absolute_deadline));

  MessengerClient1 client(channel);

  StatusOr<std::string> response = client.Hello(kName);
  ASSERT_THAT(response, IsOk());
  EXPECT_EQ(response.value(), MessengerServer1::ResponseString(kName));

  response = client.Hello("");
  EXPECT_THAT(response, Not(IsOk()));
}

}  // namespace
}  // namespace test
}  // namespace asylo
