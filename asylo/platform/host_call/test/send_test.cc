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

#include <fcntl.h>
#include <sys/file.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/flags/flag.h"
#include "absl/strings/str_cat.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "asylo/enclave_manager.h"
#include "asylo/platform/host_call/test/enclave_test_selectors.h"
#include "asylo/platform/host_call/untrusted/host_call_handlers_initializer.h"
#include "asylo/platform/primitives/extent.h"
#include "asylo/platform/primitives/test/test_backend.h"
#include "asylo/platform/primitives/untrusted_primitives.h"
#include "asylo/platform/primitives/util/message.h"
#include "asylo/platform/storage/utils/fd_closer.h"
#include "asylo/platform/system_call/type_conversions/types_functions.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/test/util/test_flags.h"

using ::testing::Eq;
using ::testing::Gt;
using ::testing::Not;
using ::testing::SizeIs;
using ::testing::StrEq;

namespace asylo {
namespace host_call {
namespace {

class HostCallTest : public ::testing::Test {
 protected:
  // Loads the enclave. The function uses the factory method
  // |primitives::test::TestBackend::Get()| for loading the enclave, and the
  // type of backend (sim, remote, sgx etc.) loaded depends upon the type of
  // library included with the build that implements the abstract factory class
  // |TestBackend|.
  std::shared_ptr<primitives::Client> LoadTestEnclaveOrDie(
      StatusOr<std::unique_ptr<primitives::Client::ExitCallProvider>>
          exit_call_provider = GetHostCallHandlersMapping()) {
    ASYLO_EXPECT_OK(exit_call_provider);
    const auto client =
        primitives::test::TestBackend::Get()->LoadTestEnclaveOrDie(
            /*enclave_name=*/"host_call_test_enclave",
            std::move(exit_call_provider.ValueOrDie()));

    return client;
  }

  void SetUp() override {
    EnclaveManager::Configure(EnclaveManagerOptions());
    client_ = LoadTestEnclaveOrDie();
    ASSERT_FALSE(client_->IsClosed());
  }

  void TearDown() override {
    client_->Destroy();
    EXPECT_TRUE(client_->IsClosed());
  }

  std::shared_ptr<primitives::Client> client_;
};

TEST_F(HostCallTest, TestSend) {
  // Create a local socket and ensure that it is valid (fd > 0).
  int socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  EXPECT_THAT(socket_fd, Gt(0));

  std::string sockpath =
      absl::StrCat("/tmp/", absl::ToUnixNanos(absl::Now()), ".sock");

  // Create a local socket address and bind the socket to it.
  sockaddr_un sa = {};
  sa.sun_family = AF_UNIX;
  strncpy(&sa.sun_path[0], sockpath.c_str(), sizeof(sa.sun_path) - 1);
  ASSERT_THAT(
      bind(socket_fd, reinterpret_cast<struct sockaddr *>(&sa), sizeof(sa)),
      Not(Eq(-1)));

  ASSERT_THAT(listen(socket_fd, 8), Not(Eq(-1)));

  // Create another local socket and ensures that it is valid (fd > 0).
  int client_sock = socket(AF_UNIX, SOCK_STREAM, 0);
  EXPECT_THAT(client_sock, Gt(0));

  // Attempt to connect the new socket to the local address. This call
  // will only succeed if the listen is successful.
  ASSERT_THAT(connect(client_sock, reinterpret_cast<struct sockaddr *>(&sa),
                      sizeof(sa)),
              Not(Eq(-1)));

  int connection_socket = accept(socket_fd, nullptr, nullptr);

  std::string msg = "Hello world!";

  primitives::MessageWriter in;
  in.Push<int>(/*value=sockfd=*/connection_socket);
  in.Push(/*value=buf*/ msg);
  in.Push<size_t>(/*value=len*/ msg.length());
  in.Push<int>(/*value=flags*/ 0);
  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestSend, &in, &out));
  ASSERT_THAT(out, SizeIs(1));
  EXPECT_THAT(out.next<int>(), Eq(msg.length()));

  close(socket_fd);
  close(client_sock);
  close(connection_socket);
}

}  // namespace
}  // namespace host_call
}  // namespace asylo
