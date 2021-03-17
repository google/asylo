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

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>
#include <utility>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/debugging/leak_check.h"
#include "absl/flags/flag.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "asylo/util/logging.h"
#include "asylo/platform/primitives/extent.h"
#include "asylo/platform/primitives/long_living_test/long_living_test_selectors.h"
#include "asylo/platform/primitives/primitive_status.h"
#include "asylo/platform/primitives/test/test_backend.h"
#include "asylo/platform/primitives/trusted_primitives.h"
#include "asylo/platform/primitives/untrusted_primitives.h"
#include "asylo/platform/primitives/util/dispatch_table.h"
#include "asylo/platform/primitives/util/message.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status.h"

ABSL_FLAG(std::string, sleep_time, "15 sec",
          "How long will Enclave call sleep before returning.");

namespace asylo {
namespace primitives {
namespace {

class LongLivingTest : public ::testing::Test {
 protected:
  std::shared_ptr<Client> LoadTestEnclaveOrDie() {
    auto client = test::TestBackend::Get()->LoadTestEnclaveOrDie(
        /*enclave_name=*/"long_living_test_enclave",
        absl::make_unique<DispatchTable>());
    // Register SleepFor and CurrentTime exit handler to perform actual actions
    // delegated to untrusted code.
    ExitHandler::Callback sleep_for_handler =
        [&](std::shared_ptr<Client> client, void *context, MessageReader *in,
            MessageWriter *out) -> Status {
      ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 1);
      auto delay = in->next<absl::Duration>();
      LOG(ERROR) << "SleepFor exit call, delay=" << delay;
      absl::SleepFor(delay);
      return absl::OkStatus();
    };
    ASYLO_EXPECT_OK(client->exit_call_provider()->RegisterExitHandler(
        kSleepForExitCall, ExitHandler{sleep_for_handler}));
    ExitHandler::Callback current_time_handler =
        [&](std::shared_ptr<Client> client, void *context, MessageReader *in,
            MessageWriter *out) -> Status {
      ASYLO_RETURN_IF_READER_NOT_EMPTY(*in);
      out->Push(absl::Now());
      return absl::OkStatus();
    };
    ASYLO_EXPECT_OK(client->exit_call_provider()->RegisterExitHandler(
        kCurrentTimeExitCall, ExitHandler{current_time_handler}));
    return client;
  }

  static void TearDownTestSuite() { delete test::TestBackend::Get(); }
};

// Run long living enclave call with potential pings.
TEST_F(LongLivingTest, RunLongLivingCall) {
  auto client = LoadTestEnclaveOrDie();
  EXPECT_FALSE(client->IsClosed());

  // Make an enclave call.
  MessageWriter input;
  absl::Duration duration;
  ASSERT_TRUE(absl::ParseDuration(absl::GetFlag(FLAGS_sleep_time), &duration));
  input.Push(duration);
  LOG(ERROR) << "Start long entry call, duration=" << duration;
  MessageReader output;
  auto status = client->EnclaveCall(kLongCall, &input, &output);
  LOG(ERROR) << "Finished long entry call, status=" << status;
  ASYLO_EXPECT_OK(status);
  ASSERT_THAT(output, ::testing::SizeIs(1));
  LOG(ERROR) << "Spent " << output.next<absl::Duration>()
             << " in the enclave call.";

  // Close the enclave.
  client->Destroy();
  EXPECT_TRUE(client->IsClosed());
}

}  // namespace
}  // namespace primitives
}  // namespace asylo
