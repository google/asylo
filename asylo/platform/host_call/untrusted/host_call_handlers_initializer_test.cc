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

#include "asylo/platform/host_call/untrusted/host_call_handlers_initializer.h"

#include <gtest/gtest.h>
#include "absl/status/status.h"
#include "asylo/util/logging.h"
#include "asylo/platform/host_call/exit_handler_constants.h"
#include "asylo/platform/primitives/untrusted_primitives.h"
#include "asylo/platform/primitives/util/message.h"
#include "asylo/test/util/status_matchers.h"

namespace asylo {
namespace host_call {

class MockedEnclaveClient : public primitives::Client {
 public:
  MockedEnclaveClient(
      const absl::string_view name,
      std::unique_ptr<primitives::Client::ExitCallProvider> dispatch_table)
      : primitives::Client(name, std::move(dispatch_table)) {}

  // Virtual methods not used in this test.
  bool IsClosed() const override {
    LOG(FATAL);
    return false;
  }

  Status Destroy() override {
    LOG(FATAL);
    return absl::OkStatus();
  }

  Status EnclaveCallInternal(uint64_t selector, primitives::MessageWriter *in,
                             primitives::MessageReader *out) override {
    LOG(FATAL);
    return absl::OkStatus();
  }
};

// Verify that host call handlers are correctly registered as exit handlers.
TEST(HostCallHandlersInitializerTest, RegisterHostCallHandlersTest) {
  const auto client = std::make_shared<MockedEnclaveClient>(
      /*name=*/"mock_enclave",
      /*dispatch_table=*/absl::make_unique<primitives::DispatchTable>());
  ASYLO_EXPECT_OK(
      AddHostCallHandlersToExitCallProvider(client->exit_call_provider()));

  // Verify that |kSystemCallHandler| is in use by attempting to re-register the
  // handler.
  EXPECT_THAT(client->exit_call_provider()->RegisterExitHandler(
                  kSystemCallHandler, primitives::ExitHandler{nullptr}),
              StatusIs(absl::StatusCode::kAlreadyExists));

  // Verify that |kSystemCallHandler| points to |SystemCallHandler| by making a
  // call with an empty request.
  primitives::MessageReader input;
  primitives::MessageWriter output;
  EXPECT_THAT(client->exit_call_provider()->InvokeExitHandler(
                  kSystemCallHandler, &input, &output, client.get()),
              StatusIs(absl::StatusCode::kInvalidArgument));

  EXPECT_THAT(client->exit_call_provider()->RegisterExitHandler(
                  kIsAttyHandler, primitives::ExitHandler{nullptr}),
              StatusIs(absl::StatusCode::kAlreadyExists));
  EXPECT_THAT(client->exit_call_provider()->InvokeExitHandler(
                  kIsAttyHandler, &input, &output, client.get()),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(client->exit_call_provider()->RegisterExitHandler(
                  kUSleepHandler, primitives::ExitHandler{nullptr}),
              StatusIs(absl::StatusCode::kAlreadyExists));
  EXPECT_THAT(client->exit_call_provider()->InvokeExitHandler(
                  kUSleepHandler, &input, &output, client.get()),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(client->exit_call_provider()->RegisterExitHandler(
                  kSysconfHandler, primitives::ExitHandler{nullptr}),
              StatusIs(absl::StatusCode::kAlreadyExists));
  EXPECT_THAT(client->exit_call_provider()->InvokeExitHandler(
                  kSysconfHandler, &input, &output, client.get()),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(client->exit_call_provider()->RegisterExitHandler(
                  kReallocHandler, primitives::ExitHandler{nullptr}),
              StatusIs(absl::StatusCode::kAlreadyExists));
  EXPECT_THAT(client->exit_call_provider()->InvokeExitHandler(
                  kReallocHandler, &input, &output, client.get()),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(client->exit_call_provider()->RegisterExitHandler(
                  kSleepHandler, primitives::ExitHandler{nullptr}),
              StatusIs(absl::StatusCode::kAlreadyExists));
  EXPECT_THAT(client->exit_call_provider()->InvokeExitHandler(
                  kSleepHandler, &input, &output, client.get()),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(client->exit_call_provider()->RegisterExitHandler(
                  kGetSocknameHandler, primitives::ExitHandler{nullptr}),
              StatusIs(absl::StatusCode::kAlreadyExists));
  EXPECT_THAT(client->exit_call_provider()->InvokeExitHandler(
                  kGetSocknameHandler, &input, &output, client.get()),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(client->exit_call_provider()->RegisterExitHandler(
                  kAcceptHandler, primitives::ExitHandler{nullptr}),
              StatusIs(absl::StatusCode::kAlreadyExists));
  EXPECT_THAT(client->exit_call_provider()->InvokeExitHandler(
                  kAcceptHandler, &input, &output, client.get()),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(client->exit_call_provider()->RegisterExitHandler(
                  kGetPeernameHandler, primitives::ExitHandler{nullptr}),
              StatusIs(absl::StatusCode::kAlreadyExists));
  EXPECT_THAT(client->exit_call_provider()->InvokeExitHandler(
                  kGetPeernameHandler, &input, &output, client.get()),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(client->exit_call_provider()->RegisterExitHandler(
                  kRecvFromHandler, primitives::ExitHandler{nullptr}),
              StatusIs(absl::StatusCode::kAlreadyExists));
  EXPECT_THAT(client->exit_call_provider()->InvokeExitHandler(
                  kRecvFromHandler, &input, &output, client.get()),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace host_call
}  // namespace asylo
