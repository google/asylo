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

#include "asylo/platform/primitives/util/dispatch_table.h"

#include <cstdlib>
#include <memory>
#include <random>
#include <thread>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "asylo/platform/primitives/untrusted_primitives.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status.h"
#include "asylo/util/thread.h"

using ::testing::_;
using ::testing::Eq;
using ::testing::MockFunction;

namespace asylo {
namespace primitives {
namespace {

class MockedEnclaveClient : public Client {
 public:
  using MockExitHandlerCallback =
      MockFunction<Status(std::shared_ptr<class Client> enclave, void *,
                          MessageReader *in, MessageWriter *out)>;

  MockedEnclaveClient()
      : Client(
            /*name=*/"mock_enclave", absl::make_unique<DispatchTable>()) {}

  // Virtual methods not used in this test.
  bool IsClosed() const override { return false; }
  Status Destroy() override { return absl::OkStatus(); }
  Status EnclaveCallInternal(uint64_t selector, MessageWriter *in,
                             MessageReader *out) override {
    return absl::OkStatus();
  }
};

TEST(DispatchTableTest, HandlersRegistration) {
  DispatchTable dispatch_table;
  MockedEnclaveClient::MockExitHandlerCallback callback;
  ASSERT_THAT(dispatch_table.RegisterExitHandler(
                  0, ExitHandler{callback.AsStdFunction()}),
              IsOk());
  ASSERT_THAT(dispatch_table.RegisterExitHandler(
                  10, ExitHandler{callback.AsStdFunction()}),
              IsOk());
  ASSERT_THAT(dispatch_table.RegisterExitHandler(
                  0, ExitHandler{callback.AsStdFunction()}),
              StatusIs(absl::StatusCode::kAlreadyExists));
  ASSERT_THAT(dispatch_table.RegisterExitHandler(
                  10, ExitHandler{callback.AsStdFunction()}),
              StatusIs(absl::StatusCode::kAlreadyExists));
  ASSERT_THAT(dispatch_table.RegisterExitHandler(
                  20, ExitHandler{callback.AsStdFunction()}),
              IsOk());
}

TEST(DispatchTableTest, HandlersInvocation) {
  const auto client = std::make_shared<MockedEnclaveClient>();
  MockedEnclaveClient::MockExitHandlerCallback callbacks[3];
  EXPECT_CALL(callbacks[0], Call(Eq(client), _, _, _)).Times(2);
  EXPECT_CALL(callbacks[1], Call(Eq(client), _, _, _)).Times(1);
  EXPECT_CALL(callbacks[2], Call(Eq(client), _, _, _)).Times(0);
  ASSERT_THAT(client->exit_call_provider()->RegisterExitHandler(
                  0, ExitHandler{callbacks[0].AsStdFunction()}),
              IsOk());
  ASSERT_THAT(client->exit_call_provider()->RegisterExitHandler(
                  10, ExitHandler{callbacks[1].AsStdFunction()}),
              IsOk());
  ASSERT_THAT(client->exit_call_provider()->RegisterExitHandler(
                  20, ExitHandler{callbacks[2].AsStdFunction()}),
              IsOk());
  MessageWriter out;
  EXPECT_THAT(client->exit_call_provider()->InvokeExitHandler(0, nullptr, &out,
                                                              client.get()),
              IsOk());
  EXPECT_THAT(client->exit_call_provider()->InvokeExitHandler(10, nullptr, &out,
                                                              client.get()),
              IsOk());
  EXPECT_THAT(client->exit_call_provider()->InvokeExitHandler(0, nullptr, &out,
                                                              client.get()),
              IsOk());
  EXPECT_THAT(client->exit_call_provider()->InvokeExitHandler(30, nullptr, &out,
                                                              client.get()),
              StatusIs(absl::StatusCode::kOutOfRange));
}

TEST(DispatchTableTest, HandlersInMultipleThreads) {
  const size_t kThreads = 64;
  const size_t kCount = 256;
  const auto client = std::make_shared<MockedEnclaveClient>();
  MockedEnclaveClient::MockExitHandlerCallback callbacks[kThreads];
  for (size_t i = 0; i < kThreads; ++i) {
    EXPECT_CALL(callbacks[i], Call(Eq(client), _, _, _)).Times(kCount);
  }
  std::vector<Thread> threads;
  threads.reserve(kThreads);
  for (size_t i = 0; i < kThreads; ++i) {
    threads.emplace_back([i, &client, &callbacks] {
      std::mt19937 rand_engine;
      std::uniform_int_distribution<uint64_t> rand_gen(10, 100);
      absl::SleepFor(absl::Milliseconds(rand_gen(rand_engine)));
      ASSERT_THAT(client->exit_call_provider()->RegisterExitHandler(
                      i, ExitHandler{callbacks[i].AsStdFunction()}),
                  IsOk());
      for (size_t c = 0; c < kCount; ++c) {
        absl::SleepFor(absl::Milliseconds(rand_gen(rand_engine)));
        MessageWriter out;
        EXPECT_THAT(client->exit_call_provider()->InvokeExitHandler(
                        i, nullptr, &out, client.get()),
                    IsOk());
      }
    });
  }
  for (auto &thread : threads) {
    thread.Join();
  }
}

}  // namespace
}  // namespace primitives
}  // namespace asylo
