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
#include <thread>
#include <utility>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/debugging/leak_check.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "asylo/platform/primitives/extent.h"
#include "asylo/platform/primitives/primitive_status.h"
#include "asylo/platform/primitives/test/test_backend.h"
#include "asylo/platform/primitives/test/test_selectors.h"
#include "asylo/platform/primitives/trusted_primitives.h"
#include "asylo/platform/primitives/untrusted_primitives.h"
#include "asylo/platform/primitives/util/dispatch_table.h"
#include "asylo/platform/primitives/util/message.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status.h"
#include "asylo/util/thread.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Invoke;
using ::testing::MockFunction;
using ::testing::Not;
using ::testing::NotNull;
using ::testing::Return;
using ::testing::SizeIs;
using ::testing::StrEq;
using ::testing::WithArgs;

namespace asylo {
namespace primitives {
namespace {

class PrimitivesTest : public ::testing::Test {
 protected:
  // Loads the enclave. When 'reload' is false, the enclave is indeed loaded,
  // and initialization is expected to happen.
  std::shared_ptr<Client> LoadTestEnclaveOrDie(bool reload) {
    auto exit_call_provider = absl::make_unique<DispatchTable>();
    // Register init exit call invoked during test_enclave.cc initialization.
    MockFunction<Status(std::shared_ptr<class Client> enclave, void *context,
                        MessageReader *in, MessageWriter *out)>
        mock_init_handler;

    if (reload) {
      EXPECT_CALL(mock_init_handler, Call(NotNull(), _, _, _))
          .WillRepeatedly(DoAll(WithArgs<2, 3>(Invoke(CopyInOut)),
                                Return(absl::OkStatus())));
    } else {
      EXPECT_CALL(mock_init_handler, Call(NotNull(), _, _, _))
          .WillOnce(DoAll(WithArgs<2, 3>(Invoke(CopyInOut)),
                          Return(absl::OkStatus())));
    }
    ASYLO_EXPECT_OK(exit_call_provider->RegisterExitHandler(
        kUntrustedInit, ExitHandler{mock_init_handler.AsStdFunction()}));
    return test::TestBackend::Get()->LoadTestEnclaveOrDie(
        /*enclave_name=*/"primitives_test", std::move(exit_call_provider));
  }

  static void TearDownTestSuite() {
    // Clean up the backend.
    delete test::TestBackend::Get();
  }

 private:
  static void CopyInOut(MessageReader *in, MessageWriter *out) {
    while (in->hasNext()) {
      out->PushByCopy(in->next());
    }
  }
};

// Enter an instance of the test enclave and multiply a number by two, aborting
// on failure.
int32_t MultiplyByTwoOrDie(const std::shared_ptr<Client> &client,
                           int32_t value) {
  MessageWriter in;
  in.Push(value);
  MessageReader out;
  ASYLO_EXPECT_OK(client->EnclaveCall(kTimesTwoSelector, &in, &out));
  EXPECT_THAT(out, SizeIs(1));
  const auto res = out.next<int32_t>();
  EXPECT_FALSE(out.hasNext());
  return res;
}

// Enter an instance of the test enclave with a number and get back with the
// running average, aborting on failure.
int64_t AveragePerThreadOrDie(const std::shared_ptr<Client> &client,
                              int64_t value) {
  MessageWriter in;
  in.Push(value);
  MessageReader out;
  ASYLO_EXPECT_OK(client->EnclaveCall(kAveragePerThreadSelector, &in, &out));
  EXPECT_THAT(out, SizeIs(1));
  const auto res = out.next<int64_t>();
  EXPECT_FALSE(out.hasNext());
  return res;
}

uint64_t StressMallocsOrDie(const std::shared_ptr<Client> &client,
                            uint64_t malloc_count, uint64_t malloc_size) {
  MessageWriter in;
  in.Push(malloc_size);
  in.Push(malloc_count);
  MessageReader out;
  ASYLO_EXPECT_OK(client->EnclaveCall(kStressMallocs, &in, &out));
  EXPECT_THAT(out, SizeIs(1));
  const auto res = out.next<uint64_t>();
  EXPECT_FALSE(out.hasNext());
  return res;
}

// Ensure making an invalid call into an enclave returns an appropriate failure
// status.
TEST_F(PrimitivesTest, BadCall) {
  auto client = LoadTestEnclaveOrDie(/*reload=*/false);

  // Enter the enclave with an invalid selector.
  MessageWriter in;
  in.Push(4096);
  MessageReader out;
  Status status = client->EnclaveCall(kNotRegisteredSelector, &in, &out);
  EXPECT_THAT(status, Not(IsOk()));

  // Invoke a selector with invalid number of arguments.
  MessageWriter in_0_arg;
  MessageReader out_0_arg;
  status = client->EnclaveCall(kTimesTwoSelector, &in_0_arg, &out_0_arg);
  EXPECT_THAT(status, Not(IsOk()));
  MessageWriter in_2_arg;
  in_2_arg.Push(4096);
  in_2_arg.Push(4096);
  MessageReader out_2_arg;
  status = client->EnclaveCall(kTimesTwoSelector, &in_2_arg, &out_2_arg);
  EXPECT_THAT(status, Not(IsOk()));
}

TEST_F(PrimitivesTest, EnclaveLifetime) {
  // Ensure that an enclave is not closed before its clients leave scope.
  auto client = LoadTestEnclaveOrDie(/*reload=*/false);
  auto first_copy = client;
  auto second_copy = client;

  first_copy.reset();
  EXPECT_FALSE(client->IsClosed());
  second_copy.reset();
  EXPECT_FALSE(client->IsClosed());

  // Ensure that destroying an enclave is immediately reflected in all clients.
  first_copy = client;
  second_copy = client;
  EXPECT_FALSE(first_copy->IsClosed());
  EXPECT_FALSE(second_copy->IsClosed());
  client->Destroy();
  EXPECT_TRUE(client->IsClosed());
  EXPECT_TRUE(first_copy->IsClosed());
  EXPECT_TRUE(second_copy->IsClosed());

  // Ensure that multiple instances of the same enclave are independent.
  auto first_instance = LoadTestEnclaveOrDie(/*reload=*/false);
  auto second_instance = LoadTestEnclaveOrDie(/*reload=*/true);

  EXPECT_FALSE(first_instance->IsClosed());
  EXPECT_THAT(MultiplyByTwoOrDie(first_instance, 1), Eq(2));
  EXPECT_FALSE(second_instance->IsClosed());
  EXPECT_THAT(MultiplyByTwoOrDie(second_instance, 2), Eq(4));

  first_instance->Destroy();
  EXPECT_TRUE(first_instance->IsClosed());
  EXPECT_FALSE(second_instance->IsClosed());
  EXPECT_THAT(MultiplyByTwoOrDie(second_instance, 3), Eq(6));

  second_instance->Destroy();
  EXPECT_TRUE(first_instance->IsClosed());
  EXPECT_TRUE(second_instance->IsClosed());
}

// Test basic enclave load, send message, and destroy.
TEST_F(PrimitivesTest, LoadEnclave) {
  auto client = LoadTestEnclaveOrDie(/*reload=*/false);
  EXPECT_FALSE(client->IsClosed());

  // Make an enclave call.
  EXPECT_THAT(MultiplyByTwoOrDie(client, 1), Eq(2));

  // Close the enclave.
  client->Destroy();
  EXPECT_TRUE(client->IsClosed());

  // Ensure a call to a destroyed enclave fails.
  MessageWriter in;
  in.Push<int32_t>(1);
  MessageReader out;
  auto status = client->EnclaveCall(kTimesTwoSelector, &in, &out);
  EXPECT_THAT(status, Not(IsOk()));
}

// Ensure that an aborted enclave cannot be reentered.
TEST_F(PrimitivesTest, AbortEnclave) {
  // If the enclave is aborted, then the call to the finalizer routine and
  // memory allocated by it will never be freed.
  const std::unique_ptr<absl::LeakCheckDisabler> ignore_leak_check(
      test::TestBackend::Get()->LeaksMemoryOnAbort()
          ? new absl::LeakCheckDisabler()
          : nullptr);

  auto client = LoadTestEnclaveOrDie(/*reload=*/false);
  std::shared_ptr<Client> client_copy = client;

  // Make an enclave call.
  EXPECT_THAT(MultiplyByTwoOrDie(client, 1), Eq(2));

  // Abort the enclave.
  MessageWriter abort_in;
  MessageReader about_out;
  ASYLO_EXPECT_OK(
      client->EnclaveCall(kAbortEnclaveSelector, &abort_in, &about_out));

  // Check that we can't enter the enclave again.
  MessageWriter in;
  in.Push<int32_t>(10);
  MessageReader out;
  auto status = client->EnclaveCall(kTimesTwoSelector, &in, &out);
  EXPECT_THAT(status, Not(IsOk()));

  // Check that we can't enter through a copy of the client.
  status = client_copy->EnclaveCall(kTimesTwoSelector, &in, &out);
  EXPECT_THAT(status, Not(IsOk()));
}

// Test control flow passing in and out of an enclave.
TEST_F(PrimitivesTest, CallChain) {
  auto client = LoadTestEnclaveOrDie(/*reload=*/false);

  auto trusted_fibonacci = [&client](int32_t n) -> int32_t {
    MessageWriter in;
    in.Push(n);
    MessageReader out;
    ASYLO_EXPECT_OK(client->EnclaveCall(kTrustedFibonacci, &in, &out));
    EXPECT_THAT(out, SizeIs(1));
    const int32_t res = out.next<int32_t>();
    EXPECT_FALSE(out.hasNext());
    return res;
  };

  // An exit handler to compute a Fibonacci number, calling back into the
  // enclave recursively.
  ExitHandler::Callback fibonacci_handler =
      [&](std::shared_ptr<Client> client, void *context, MessageReader *in,
          MessageWriter *out) -> Status {
    ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 1);
    const auto n = in->next<int32_t>();
    if (n >= 50) {
      return absl::InvalidArgumentError(
          "UntrustedFibonacci called with invalid argument.");
    }
    out->Push(n < 2 ? n : trusted_fibonacci(n - 1) + trusted_fibonacci(n - 2));
    return absl::OkStatus();
  };

  // Register the Fibonacci exit handler.
  ASYLO_EXPECT_OK(client->exit_call_provider()->RegisterExitHandler(
      kUntrustedFibonacci, ExitHandler{fibonacci_handler}));
  EXPECT_THAT(trusted_fibonacci(20), Eq(6765));
}

// Ensure many threads can attempt enter the enclave simultaneously.
TEST_F(PrimitivesTest, ThreadedTest) {
  constexpr int kNumThreads = 64;
  auto client = LoadTestEnclaveOrDie(/*reload=*/false);
  for (int i = 0; i < 32; i++) {
    std::vector<Thread> threads;
    for (int j = 0; j < kNumThreads; j++) {
      threads.emplace_back([&client, j]() {
        auto result = MultiplyByTwoOrDie(client, j);
        EXPECT_THAT(result, Eq(2 * j));
      });
    }
    for (auto &thread : threads) {
      thread.Join();
    }
  }
}

TEST_F(PrimitivesTest, ThreadedStressMallocsTest) {
  constexpr int kNumThreads = 64;
  constexpr uint64_t kMallocCount = 64;
  constexpr uint64_t kMallocSize = 16;
  auto client = LoadTestEnclaveOrDie(/*reload=*/false);
  for (int i = 0; i < 32; i++) {
    std::vector<Thread> threads;
    for (int j = 0; j < kNumThreads; j++) {
      threads.emplace_back([&client]() {
        auto result = StressMallocsOrDie(client, kMallocCount, kMallocSize);
        EXPECT_THAT(result, Eq(0));
      });
    }
    for (auto &thread : threads) {
      thread.Join();
    }
  }
}

// Ensure thread_local works properly in the Enclave threads.
TEST_F(PrimitivesTest, ThreadLocalStorageTest) {
  constexpr int kNumCount = 256;
  constexpr int kNumThreads = 64;
  auto client = LoadTestEnclaveOrDie(/*reload=*/false);
  std::vector<Thread> threads;
  for (int64_t thread_index = 0; thread_index < kNumThreads; thread_index++) {
    threads.emplace_back([&client, thread_index]() {
      int64_t sum = 0;
      int64_t count = 0;
      for (int64_t i = 0; i < kNumCount; i++) {
        int num = thread_index * kNumThreads + i;
        sum += num;
        ++count;
        auto result = AveragePerThreadOrDie(client, num);
        EXPECT_THAT(result, Eq(sum / count)) << thread_index << " " << i;
      }
    });
  }
  for (auto &thread : threads) {
    thread.Join();
  }
}

// Ensure the buffers returned by trusted malloc satisfy
// TrustedPrimitives::IsInsideEnclave().
TEST_F(PrimitivesTest, TrustedMalloc) {
  auto client = LoadTestEnclaveOrDie(/*reload=*/false);
  MessageReader out;
  ASYLO_EXPECT_OK(client->EnclaveCall(kTrustedMallocTest, nullptr, &out));
  EXPECT_THAT(out, SizeIs(1));
  EXPECT_TRUE(out.next<bool>());
  EXPECT_FALSE(out.hasNext());
}

// Ensure the buffers returned by untrusted alloc do not satisfy
// TrustedPrimitives::IsInsideEnclave().
TEST_F(PrimitivesTest, UntrustedAlloc) {
  auto client = LoadTestEnclaveOrDie(/*reload=*/false);
  MessageReader out;
  ASYLO_EXPECT_OK(client->EnclaveCall(kUntrustedLocalAllocTest, nullptr, &out));
  EXPECT_THAT(out, SizeIs(1));
  EXPECT_TRUE(out.next<bool>());
  EXPECT_FALSE(out.hasNext());
}

// Ensure multiple parameters are passed back and forth.
TEST_F(PrimitivesTest, CopyMultipleParams) {
  auto client = LoadTestEnclaveOrDie(/*reload=*/false);
  const std::string in1 = "Param1";
  const uint64_t in2 = 12345;
  const char in3[] = "Param3";
  MessageWriter in;
  in.PushString(in1);
  in.Push(in2);
  in.PushByReference({in3, strlen(in3) + 1});
  MessageReader out;
  ASYLO_ASSERT_OK(client->EnclaveCall(kCopyMultipleParamsSelector, &in, &out));
  EXPECT_THAT(out, SizeIs(4));
  {
    auto outp1 = out.next();
    ASSERT_THAT(outp1.size(), in1.size() + 1);
    const std::string out1s(outp1.As<char>());
    EXPECT_THAT(out1s, StrEq(in1));
  }
  EXPECT_THAT(out.next<uint64_t>(), Eq(in2));
  {
    auto outp3 = out.next();
    const std::string out3s(outp3.As<char>());
    EXPECT_THAT(out3s, StrEq(in3));
  }
  {
    auto outp4 = out.next();
    const std::string out4s(outp4.As<char>(), outp4.size());
    EXPECT_THAT(out4s, StrEq("Foo"));
  }
  EXPECT_FALSE(out.hasNext());
}

// Ensure that IsInsideEnclave and IsOutsideEnclave return the expected values.
TEST_F(PrimitivesTest, InsideOutsideEnclaveTest) {
  auto client = LoadTestEnclaveOrDie(/*reload=*/false);
  MessageReader out;
  ASYLO_EXPECT_OK(client->EnclaveCall(kInsideOutsideTest, nullptr, &out));
  EXPECT_THAT(out, SizeIs(1));
  auto result = out.next();
  EXPECT_THAT(std::string(result.As<char>(), result.size() - 1), StrEq("pass"));
  EXPECT_FALSE(out.hasNext());
}

}  // namespace
}  // namespace primitives
}  // namespace asylo
