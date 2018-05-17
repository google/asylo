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

#include <gtest/gtest.h>
#include "absl/strings/str_cat.h"
#include "asylo/grpc/util/enclave_server.pb.h"
#include "asylo/test/grpc/messenger_client_impl.h"
#include "asylo/test/grpc/messenger_server_impl.h"
#include "asylo/test/util/enclave_test.h"
#include "asylo/test/util/status_matchers.h"
#include "include/grpcpp/channel.h"
#include "include/grpcpp/create_channel.h"
#include "include/grpcpp/security/credentials.h"
#include "test/core/util/port.h"

namespace asylo {
namespace test {
namespace {

using ::testing::Not;

constexpr char kName[] = "test";

constexpr const char kAddress[] = "[::1]:";

class EnclaveServerTest : public EnclaveTest {
 protected:
  void SetUp() override {
    ServerConfig *config = config_.MutableExtension(server_config);
    address_ = ::absl::StrCat(kAddress, grpc_pick_unused_port_or_die());
    config->set_address(address_);
    EnclaveTest::SetUp();
  }

  std::string address_;
};

TEST_F(EnclaveServerTest, SimpleEnd2EndTest) {
  std::thread grpc_thread(
      [this]() { EXPECT_THAT(client_->EnterAndRun({}, nullptr), IsOk()); });
  grpc_thread.detach();

  auto channel =
      ::grpc::CreateChannel(address_, ::grpc::InsecureChannelCredentials());

  // Wait 30 seconds for channel to connect to server.
  gpr_timespec absolute_deadline = gpr_time_add(
      gpr_now(GPR_CLOCK_REALTIME),
      gpr_time_from_micros(static_cast<int64_t>(30 * 1e6), GPR_TIMESPAN));
  EXPECT_TRUE(channel->WaitForConnected(absolute_deadline));

  MessengerClient1 client(channel);

  StatusOr<std::string> response = client.Hello(kName);
  ASSERT_THAT(response, IsOk());
  EXPECT_EQ(response.ValueOrDie(), MessengerServer1::ResponseString(kName));

  response = client.Hello("");
  EXPECT_THAT(response, Not(IsOk()));
}

}  // namespace
}  // namespace test
}  // namespace asylo
