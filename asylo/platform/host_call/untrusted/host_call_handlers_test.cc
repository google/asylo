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

#include "asylo/platform/host_call/untrusted/host_call_handlers.h"

#include <sys/syscall.h>

#include <functional>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "asylo/platform/primitives/util/message.h"
#include "asylo/platform/primitives/util/status_conversions.h"
#include "asylo/platform/system_call/message.h"
#include "asylo/platform/system_call/serialize.h"
#include "asylo/test/util/status_matchers.h"

using ::asylo::primitives::MessageReader;
using ::asylo::primitives::MessageWriter;
using ::testing::IsEmpty;
using ::testing::SizeIs;

namespace asylo {
namespace host_call {
namespace {

void FillInput(const std::function<void(MessageWriter *params)> &filler,
               MessageReader *input) {
  MessageWriter params;
  filler(&params);
  const auto buffer_size = params.MessageSize();
  const auto buffer = absl::make_unique<char[]>(buffer_size);
  params.Serialize(buffer.get());
  input->Deserialize(buffer.get(), buffer_size);
}

void VerifyOutput(const std::function<void(MessageReader *result)> &verifier,
                  MessageWriter *output) {
  const auto buffer_size = output->MessageSize();
  const auto buffer = absl::make_unique<char[]>(buffer_size);
  output->Serialize(buffer.get());
  MessageReader result;
  result.Deserialize(buffer.get(), buffer_size);
  verifier(&result);
}

TEST(HostCallHandlersTest, SyscallHandlerEmptyMessageTest) {
  MessageReader empty_input;
  MessageWriter empty_output;
  EXPECT_THAT(SystemCallHandler(nullptr, nullptr, &empty_input, &empty_output),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       "1 item(s) expected on the MessageReader."));
}

TEST(HostCallHandlersTest, SyscallHandlerMoreThanOneRequestTest) {
  MessageReader input;
  FillInput(
      [](MessageWriter *params) {
        params->Push(1);  // request 1
        params->Push(2);  // request 2
      },
      &input);
  MessageWriter output;
  EXPECT_THAT(SystemCallHandler(nullptr, nullptr, &input, &output),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       "1 item(s) expected on the MessageReader."));
}

// Invokes a host call for a valid serialized request. We only verify that the
// system call was made successfully, i.e. without serialization or other
// errors. We do not verify the validity of the response itself obtained by the
// syscall.
TEST(HostCallHandlersTest, SyscallHandlerValidRequestTest) {
  std::array<uint64_t, system_call::kParameterMax> request_params;
  primitives::Extent request;  // To be allocated by Serialize.
  ASYLO_ASSERT_OK(primitives::MakeStatus(
      system_call::SerializeRequest(SYS_getpid, request_params, &request)));
  MessageReader input;
  FillInput(
      [&request](MessageWriter *params) {
        params->PushByCopy(request);
        free(request.data());
      },
      &input);
  MessageWriter output;
  ASSERT_THAT(SystemCallHandler(nullptr, nullptr, &input, &output),
              StatusIs(absl::StatusCode::kOk));
  EXPECT_THAT(output, SizeIs(1));  // Contains the response.
}

// Invokes a host call for a corrupt serialized request. The behavior of the
// system_call library (implemented by untrusted_invoke) is to always
// attempt a system call for any non-zero sized request, even if the sysno
// interpreted from the request is illegal. Check if the syscall was made
// and it returned appropriate google error code for the illegal sysno.
TEST(HostCallHandlersTest, SyscallHandlerInvalidRequestTest) {
  MessageReader input;
  FillInput(
      [](MessageWriter *params) {
        std::array<uint64_t, system_call::kParameterMax> request_params;
        primitives::Extent request;

        // Instead of calling system_call::SerializeRequest we build the writer
        // manually in order to pass an invalid syscall.
        auto writer =
            system_call::MessageWriter::RequestWriter(-1, request_params);
        size_t size = writer.MessageSize();
        request = {reinterpret_cast<uint8_t *>(malloc(size)), size};
        writer.Write(&request);
        params->PushByCopy(request);
        free(request.data());
      },
      &input);
  MessageWriter output;
  const auto status = SystemCallHandler(nullptr, nullptr, &input, &output);
  ASSERT_THAT(status, StatusIs(absl::StatusCode::kInvalidArgument));
  // There should be no response populated on the stack for illegal requests.
  EXPECT_THAT(output, IsEmpty());
}

// Invokes an IsAtty hostcall for an invalid request. It tests that the correct
// error is returned for an empty input or for an input with more than one item.
TEST(HostCallHandlersTest, IsAttyIncorrectSizeTest) {
  MessageReader input;
  MessageWriter output;
  EXPECT_THAT(IsAttyHandler(nullptr, nullptr, &input, &output),
              StatusIs(absl::StatusCode::kInvalidArgument));

  FillInput(
      [](MessageWriter *params) {
        params->Push(1);
        params->Push(2);
      },
      &input);
  EXPECT_THAT(IsAttyHandler(nullptr, nullptr, &input, &output),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

// Invokes an IsAtty hostcall for a valid request, and verifies that an ok
// response code is returned, and that the correct response is included on
// the output MessageWriter.
TEST(HostCallHandlersTest, IsAttyValidRequestTest) {
  MessageReader input;
  FillInput([](MessageWriter *params) { params->Push(0); }, &input);
  MessageWriter output;
  ASSERT_THAT(IsAttyHandler(nullptr, nullptr, &input, &output), IsOk());
  ASSERT_THAT(output, SizeIs(2));
  VerifyOutput(
      [](MessageReader *results) {
        ASSERT_THAT(*results, SizeIs(2));
        EXPECT_EQ(results->next<int>(), 0);       // Check return value.
        EXPECT_EQ(results->next<int>(), ENOTTY);  // Check errno.
      },
      &output);
}

// Invokes an USleep hostcall for an invalid request. It tests that the correct
// error is returned for an empty input or for an input with more than one item.
TEST(HostCallHandlersTest, USleepIncorrectSizeTest) {
  MessageReader input;
  MessageWriter output;
  EXPECT_THAT(USleepHandler(nullptr, nullptr, &input, &output),
              StatusIs(absl::StatusCode::kInvalidArgument));

  FillInput(
      [](MessageWriter *params) {
        params->Push(1);
        params->Push(2);
      },
      &input);
  EXPECT_THAT(USleepHandler(nullptr, nullptr, &input, &output),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

// Invokes an USleep hostcall for a valid request, and verifies that an ok
// response code is returned, and that the correct response is included on
// the output MessageWriter.
TEST(HostCallHandlersTest, USleepValidRequestTest) {
  MessageReader input;
  FillInput([](MessageWriter *params) { params->Push(0); }, &input);
  MessageWriter output;
  ASSERT_THAT(USleepHandler(nullptr, nullptr, &input, &output),
              StatusIs(absl::StatusCode::kOk));
  ASSERT_THAT(output, SizeIs(2));
  VerifyOutput(
      [](MessageReader *results) {
        ASSERT_THAT(*results, SizeIs(2));
        EXPECT_EQ(results->next<int>(), 0);
      },
      &output);
}

}  // namespace

}  // namespace host_call
}  // namespace asylo
