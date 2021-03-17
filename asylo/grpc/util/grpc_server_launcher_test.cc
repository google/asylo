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

#include "asylo/grpc/util/grpc_server_launcher.h"

#include <thread>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/time/time.h"
#include "asylo/test/grpc/messenger_client_impl.h"
#include "asylo/test/grpc/messenger_server_impl.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"
#include "include/grpcpp/grpcpp.h"
#include "include/grpcpp/impl/codegen/service_type.h"
#include "include/grpcpp/security/credentials.h"

namespace asylo {
namespace {

using ::testing::Not;

constexpr char kMessengerClientName[] = "GrpcServerLauncherTest";
constexpr char kLocalhostAddress[] = "[::1]";

// Deadline for connecting to the server.
const int64_t kDeadlineMicros = absl::Seconds(10) / absl::Microseconds(1);

// Duration to wait before calling Shutdown() method of the GrpcServerLauncher.
constexpr absl::Duration kPreShutdownWait = absl::Milliseconds(250);

// AsyncDelayedShutdownInvoker invokes the Shutdown() method of a
// GrpcServerLauncher from a separate thread after kPreShutdownWait duration.
class AsyncDelayedShutdownInvoker {
 public:
  // Creates an AsyncDelayedShutdownInvoker associated with |launcher|. A thread
  // is spawned off which waits kPreShutdownWait duration and then calls the
  // |launcher|'s Shutdown() method.
  // Note that the constructed object does not take ownership of |launcher|. It
  // is the responsibility of the caller to keep |launcher_| valid until after
  // this object is destroyed.
  explicit AsyncDelayedShutdownInvoker(GrpcServerLauncher *launcher)
      : thread_(&DelayedShutdown, launcher) {}

  ~AsyncDelayedShutdownInvoker() { thread_.join(); }

 private:
  static void DelayedShutdown(GrpcServerLauncher *launcher) {
    absl::SleepFor(kPreShutdownWait);
    EXPECT_THAT(launcher->Shutdown(), IsOk());
  }

  std::thread thread_;
};

// A test fixture is used to provide a common set of methods that communicate
// through test-fixture member variables.
class GrpcServerLauncherTest : public ::testing::Test {
 protected:
  GrpcServerLauncherTest()
      : launcher_(::testing::UnitTest::GetInstance()
                      ->current_test_info()
                      ->test_case_name()),
        server_address_(absl::StrCat(kLocalhostAddress, ":", 0)) {}

  ~GrpcServerLauncherTest() override {
    // Ensure that the server is shutdown, if it has started.
    launcher_.Shutdown();
  }

  // Registers Messenger1 and Messenger2 services with launcher_, adds a free
  // localhost listening port to the launcher, and launches the server. Stores
  // the final server address in server_address_.
  Status LaunchServer() {
    ASYLO_RETURN_IF_ERROR(
        launcher_.RegisterService(absl::make_unique<test::MessengerServer1>()));
    ASYLO_RETURN_IF_ERROR(
        launcher_.RegisterService(absl::make_unique<test::MessengerServer2>()));

    int port;
    ASYLO_RETURN_IF_ERROR(launcher_.AddListeningPort(
        server_address_, ::grpc::InsecureServerCredentials(), &port));
    ASYLO_RETURN_IF_ERROR(launcher_.Start());

    // Only overwrite |server_address_| if a port was bound successfully.
    server_address_ = absl::StrCat(kLocalhostAddress, ":", port);

    return absl::OkStatus();
  }

  // Connects channel_ to the server listening on server_address_.
  bool ConnectChannel() {
    channel_ = ::grpc::CreateChannel(server_address_,
                                     ::grpc::InsecureChannelCredentials());
    gpr_timespec absolute_deadline =
        gpr_time_add(gpr_now(GPR_CLOCK_REALTIME),
                     gpr_time_from_micros(kDeadlineMicros, GPR_TIMESPAN));
    return channel_->WaitForConnected(absolute_deadline);
  }

  // Checks Messenger1 and Messenger2 services.
  Status CallServices() {
    test::MessengerClient1 messenger_client1(channel_);
    std::string response;
    ASYLO_ASSIGN_OR_RETURN(response,
                           messenger_client1.Hello(kMessengerClientName));
    EXPECT_EQ(response,
              test::MessengerServer1::ResponseString(kMessengerClientName));

    test::MessengerClient2 messenger_client2(channel_);
    ASYLO_ASSIGN_OR_RETURN(response,
                           messenger_client2.Hello(kMessengerClientName));
    EXPECT_EQ(response,
              test::MessengerServer2::ResponseString(kMessengerClientName));
    return absl::OkStatus();
  }

  GrpcServerLauncher launcher_;
  std::string server_address_;
  std::shared_ptr<::grpc::Channel> channel_;
};

// Verifies that test::MessengerServer1 and test::MessengerServer2 can be
// started correctly using the GrpcServerLauncher class.
TEST_F(GrpcServerLauncherTest, TwoServiceSanityTest) {
  ASSERT_THAT(LaunchServer(), IsOk());
  ASSERT_EQ(launcher_.GetState(), GrpcServerLauncher::State::LAUNCHED);
  ASSERT_TRUE(ConnectChannel());

  EXPECT_THAT(CallServices(), IsOk());

  // Schedule a shutdown of the server, and wait for the server to shutdown.
  AsyncDelayedShutdownInvoker shutdown_invoker(&launcher_);
  ASSERT_EQ(launcher_.GetState(), GrpcServerLauncher::State::LAUNCHED);
  EXPECT_THAT(launcher_.Wait(), IsOk());
  ASSERT_EQ(launcher_.GetState(), GrpcServerLauncher::State::TERMINATED);
}

// Verifies that any attempt to register a service or to add a listening port to
// a GrpcServerLauncher fails once the server has started.
TEST_F(GrpcServerLauncherTest, ModifyAfterStart) {
  ASSERT_THAT(LaunchServer(), IsOk());
  ASSERT_TRUE(ConnectChannel());

  EXPECT_THAT(CallServices(), IsOk());

  // Try registering a service. This should fail.
  EXPECT_THAT(
      launcher_.RegisterService(absl::make_unique<test::MessengerServer3>()),
      Not(IsOk()));

  const std::string server_address = absl::StrCat(kLocalhostAddress, ":", 0);

  // Try adding a listening port. This should fail.
  EXPECT_THAT(launcher_.AddListeningPort(server_address,
                                         ::grpc::InsecureServerCredentials()),
              Not(IsOk()));

  AsyncDelayedShutdownInvoker shutdown_invoker(&launcher_);
  EXPECT_THAT(launcher_.Wait(), IsOk());
}

// Verifies the pre-launch state of the server launcher.
TEST_F(GrpcServerLauncherTest, PreLaunchState) {
  GrpcServerLauncher launcher("PreLaunchState");
  ASSERT_EQ(launcher.GetState(), GrpcServerLauncher::State::NOT_LAUNCHED);
}

// Verifies that any attempt to shutdown a server that is not started fails.
TEST_F(GrpcServerLauncherTest, ShutdownBeforeStart) {
  GrpcServerLauncher launcher("ShutdownBeforeStart");
  EXPECT_THAT(launcher.Shutdown(), Not(IsOk()));
}

// Verifies that any attempt to wait on a server that is not started fails.
TEST_F(GrpcServerLauncherTest, WaitBeforeStart) {
  GrpcServerLauncher launcher("WaitBeforeStart");
  EXPECT_THAT(launcher.Wait(), Not(IsOk()));
}

// Ensures that two attempts to shut down the same server fail.
TEST_F(GrpcServerLauncherTest, DoubleShutdown) {
  ASSERT_THAT(LaunchServer(), IsOk());
  ASSERT_TRUE(ConnectChannel());

  EXPECT_THAT(CallServices(), IsOk());

  AsyncDelayedShutdownInvoker shutdown_invoker(&launcher_);
  EXPECT_THAT(launcher_.Wait(), IsOk());
  EXPECT_THAT(launcher_.Shutdown(), Not(IsOk()));
}

// Ensures that two attempts to wait on the same server fail.
TEST_F(GrpcServerLauncherTest, DoubleWait) {
  ASSERT_THAT(LaunchServer(), IsOk());
  ASSERT_TRUE(ConnectChannel());

  EXPECT_THAT(CallServices(), IsOk());

  AsyncDelayedShutdownInvoker shutdown_invoker(&launcher_);
  EXPECT_THAT(launcher_.Wait(), IsOk());
  EXPECT_THAT(launcher_.Wait(), Not(IsOk()));
}

// Ensures that an attempt to launch a server after shutdown fails.
TEST_F(GrpcServerLauncherTest, LaunchAfterShutdown) {
  ASSERT_THAT(LaunchServer(), IsOk());
  ASSERT_TRUE(ConnectChannel());

  EXPECT_THAT(CallServices(), IsOk());

  AsyncDelayedShutdownInvoker shutdown_invoker(&launcher_);
  EXPECT_THAT(launcher_.Wait(), IsOk());
  EXPECT_THAT(launcher_.Start(), Not(IsOk()));
}

}  // namespace
}  // namespace asylo
