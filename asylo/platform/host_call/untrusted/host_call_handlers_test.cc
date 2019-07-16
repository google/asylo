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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/platform/primitives/util/message.h"
#include "asylo/platform/primitives/util/status_conversions.h"
#include "asylo/platform/system_call/serialize.h"
#include "asylo/test/util/status_matchers.h"

using ::testing::Eq;
using ::testing::IsEmpty;
using ::testing::SizeIs;

namespace asylo {
namespace host_call {
namespace {

TEST(HostCallHandlersTest, SyscallHandlerEmptyParameterStackTest) {
  primitives::MessageReader empty_input;
  primitives::MessageWriter empty_output;
  EXPECT_THAT(SystemCallHandler(nullptr, nullptr, &empty_input, &empty_output),
              StatusIs(error::GoogleError::INVALID_ARGUMENT,
                       "1 item(s) expected on the MessageReader."));
}

TEST(HostCallHandlersTest, SyscallHandlerMoreThanOneRequestOnStackTest) {
  primitives::NativeParameterStack params;
  params.PushByCopy(1);  // request 1
  params.PushByCopy(1);  // request 2
  primitives::MessageReader input;
  input.Deserialize(&params);
  primitives::MessageWriter output;
  EXPECT_THAT(SystemCallHandler(nullptr, nullptr, &input, &output),
              StatusIs(error::GoogleError::INVALID_ARGUMENT,
                       "1 item(s) expected on the MessageReader."));
}

// Invokes a host call for a valid serialized request. We only verify that the
// system call was made successfully, i.e. without serialization or other
// errors. We do not verify the validity of the response itself obtained by the
// syscall.
TEST(HostCallHandlersTest, SyscallHandlerValidRequestOnParameterStackTest) {
  std::array<uint64_t, system_call::kParameterMax> request_params;
  primitives::Extent request;  // To be allocated by Serialize.
  ASYLO_ASSERT_OK(primitives::MakeStatus(
      system_call::SerializeRequest(SYS_getpid, request_params, &request)));
  primitives::NativeParameterStack params;
  params.PushByCopy(request);
  free(request.data());
  primitives::MessageReader input;
  input.Deserialize(&params);
  primitives::MessageWriter output;
  ASSERT_THAT(SystemCallHandler(nullptr, nullptr, &input, &output),
              StatusIs(error::GoogleError::OK));
  EXPECT_THAT(output, SizeIs(1));  // Contains the response.
}

// Invokes a host call for a corrupt serialized request. The behavior of the
// system_call library (implemented by untrusted_invoke) is to always
// attempt a system call for any non-zero sized request, even if the sysno
// interpreted from the request is illegal. Check if the syscall was made
// and it returned appropriate google error code for the illegal sysno.
TEST(HostCallHandlersTest, SyscallHandlerInvalidRequestOnParameterStackTest) {
  primitives::NativeParameterStack params;
  char request_str[] = "illegal_request";
  params.PushByCopy(primitives::Extent{request_str, strlen(request_str)});
  primitives::MessageReader input;
  input.Deserialize(&params);
  primitives::MessageWriter output;
  const auto status = SystemCallHandler(nullptr, nullptr, &input, &output);
  ASSERT_THAT(status, StatusIs(error::GoogleError::INVALID_ARGUMENT));
  // There should be no response populated on the stack for illegal requests.
  EXPECT_THAT(output, IsEmpty());
}

// Invokes an IsAtty hostcall for an invalid request. It tests that the correct
// error is returned for an empty parameter stack or for a parameter
// stack with more than one item.
TEST(HostCallHandlersTest, IsAttyIncorrectParameterStackSizeTest) {
  primitives::MessageReader input;
  primitives::MessageWriter output;
  EXPECT_THAT(IsAttyHandler(nullptr, nullptr, &input, &output),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));

  primitives::NativeParameterStack params;
  params.PushByCopy(1);
  params.PushByCopy(2);
  input.Deserialize(&params);
  EXPECT_THAT(IsAttyHandler(nullptr, nullptr, &input, &output),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

// Invokes an IsAtty hostcall for a valid request, and verifies that an ok
// response code is returned, and that the correct response is included on
// the parameter stack.
TEST(HostCallHandlersTest, IsAttyValidRequestTest) {
  primitives::NativeParameterStack params;
  params.PushByCopy(0);
  primitives::MessageReader input;
  input.Deserialize(&params);
  primitives::MessageWriter output;
  ASSERT_THAT(IsAttyHandler(nullptr, nullptr, &input, &output), IsOk());
  ASSERT_THAT(output, SizeIs(1));
  output.Serialize(&params);
  int result = params.Pop<int>();
  EXPECT_EQ(result, 0);
}

// Invokes an USleep hostcall for an invalid request. It tests that the correct
// error is returned for an empty parameter stack or for a parameter
// stack with more than one item.
TEST(HostCallHandlersTest, USleepIncorrectParameterStackSizeTest) {
  primitives::MessageReader input;
  primitives::MessageWriter output;
  EXPECT_THAT(USleepHandler(nullptr, nullptr, &input, &output),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));

  primitives::NativeParameterStack params;
  params.PushByCopy(1);
  params.PushByCopy(2);
  input.Deserialize(&params);
  EXPECT_THAT(USleepHandler(nullptr, nullptr, &input, &output),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

// Invokes an USleep hostcall for a valid request, and verifies that an ok
// response code is returned, and that the correct response is included on
// the parameter stack.
TEST(HostCallHandlersTest, USleepValidRequestTest) {
  primitives::NativeParameterStack params;
  params.PushByCopy(0);
  primitives::MessageReader input;
  input.Deserialize(&params);
  primitives::MessageWriter output;
  ASSERT_THAT(USleepHandler(nullptr, nullptr, &input, &output),
              StatusIs(error::GoogleError::OK));
  ASSERT_THAT(output, SizeIs(1));
  output.Serialize(&params);
  int result = params.Pop<int>();
  EXPECT_EQ(result, 0);
}

}  // namespace

}  // namespace host_call
}  // namespace asylo
