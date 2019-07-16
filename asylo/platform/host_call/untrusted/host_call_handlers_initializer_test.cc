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
    return Status::OkStatus();
  }

  Status EnclaveCallInternal(uint64_t selector, primitives::MessageWriter *in,
                             primitives::MessageReader *out) override {
    LOG(FATAL);
    return Status::OkStatus();
  }
};

// Verify that the result of GetHostCallHandlersMapping() can be used to
// initialize an enclave client, and |SystemCallHandler| is correctly registered
// as an exit handler.
TEST(HostCallHandlersInitializerTest, RegisterHostCallHandlersTest) {
  StatusOr<std::unique_ptr<primitives::Client::ExitCallProvider>>
      dispatch_table = GetHostCallHandlersMapping();

  ASSERT_THAT(dispatch_table.status(), IsOk());

  const auto client = std::make_shared<MockedEnclaveClient>(
      /*name=*/"mock_enclave", std::move(dispatch_table.ValueOrDie()));

  // Verify that |kSystemCallHandler| is in use by attempting to re-register the
  // handler.
  EXPECT_THAT(client->exit_call_provider()->RegisterExitHandler(
                  kSystemCallHandler, primitives::ExitHandler{nullptr}),
              StatusIs(error::GoogleError::ALREADY_EXISTS));

  // Verify that |kSystemCallHandler| points to |SystemCallHandler| by making a
  // call with an empty request.
  primitives::NativeParameterStack params;
  EXPECT_THAT(client->exit_call_provider()->InvokeExitHandler(
                  kSystemCallHandler, &params, client.get()),
              StatusIs(error::GoogleError::FAILED_PRECONDITION));

  // Verify that |kIsAttyHandler| is in use by attempting to re-register the
  // handler.
  EXPECT_THAT(client->exit_call_provider()->RegisterExitHandler(
                  kIsAttyHandler, primitives::ExitHandler{nullptr}),
              StatusIs(error::GoogleError::ALREADY_EXISTS));

  // Verify that |kIsAttyHandler| points to |IsAttyHandler| by making a
  // call with an empty request.
  EXPECT_THAT(client->exit_call_provider()->InvokeExitHandler(
                  kIsAttyHandler, &params, client.get()),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));

  // Verify that |kUSleepHandler| is in use by attempting to re-register the
  // handler.
  EXPECT_THAT(client->exit_call_provider()->RegisterExitHandler(
                  kUSleepHandler, primitives::ExitHandler{nullptr}),
              StatusIs(error::GoogleError::ALREADY_EXISTS));

  // Verify that |kUSleepHandler| points to |USleepHandler| by making a
  // call with an empty request.
  EXPECT_THAT(client->exit_call_provider()->InvokeExitHandler(
                  kUSleepHandler, &params, client.get()),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

}  // namespace host_call
}  // namespace asylo
