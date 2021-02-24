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

#include "asylo/platform/system_call/message.h"

#include <sys/socket.h>
#include <sys/syscall.h>

#include <array>
#include <cstdint>
#include <string>
#include <type_traits>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/base/casts.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "asylo/platform/primitives/primitive_status.h"

namespace asylo {
namespace system_call {
namespace {

using testing::Eq;
using testing::StrEq;

// Casts a generic value to an unsigned 64-bit integer.
template <typename T>
uint64_t CastToWord(T *value) {
  return reinterpret_cast<uint64_t>(value);
}

// Casts a generic value to an unsigned 64-bit integer.
template <typename T>
uint64_t CastToWord(T value) {
  return static_cast<uint64_t>(value);
}

// Casts a generic value to an unsigned 64-bit integer.
uint64_t CastToWord(std::nullptr_t value) { return 0; }

// Collects a variable length argument list into an array of 64-bit words.
void CollectParameters(uint64_t *parameters) {}

// Collects a variable length argument list into an array of 64-bit words.
template <typename T, typename... Args>
void CollectParameters(uint64_t *parameters, T first, Args &&...rest) {
  *parameters = CastToWord(first);
  CollectParameters(parameters + 1, rest...);
}

// Builds a system call request message and formats it as a string.
template <typename... Args>
std::string FormatRequest(int sysno, Args &&...args) {
  std::array<uint64_t, 6> parameters;
  CollectParameters(&parameters[0], args...);
  auto writer = MessageWriter::RequestWriter(sysno, parameters);
  std::vector<uint8_t> buffer(writer.MessageSize());
  primitives::Extent message{buffer.data(), buffer.size()};
  writer.Write(&message);
  return FormatMessage(message);
}

// Builds a system call response message and formats it as a string.
template <typename... Args>
std::string FormatResponse(int sysno, uint64_t result, uint64_t error_number,
                           Args &&...args) {
  std::array<uint64_t, 6> parameters;
  CollectParameters(&parameters[0], args...);
  auto writer =
      MessageWriter::ResponseWriter(sysno, result, error_number, parameters);
  std::vector<uint8_t> buffer(writer.MessageSize());
  primitives::Extent message{buffer.data(), buffer.size()};
  writer.Write(&message);
  return FormatMessage(message);
}

TEST(MessageTest, ZeroParameterTest) {
  EXPECT_THAT(FormatRequest(SYS_getpid), StrEq("request: getpid()"));
  EXPECT_THAT(FormatResponse(SYS_getpid, 1234, 0),
              StrEq("response: getpid [returns: 1234]  [errno: 0] ()"));
}

TEST(MessageTest, ScalarInTest) {
  EXPECT_THAT(FormatRequest(SYS_close, 1234),
              StrEq("request: close(0: fd [scalar 1234])"));
  EXPECT_THAT(FormatResponse(SYS_close, 1, 0),
              StrEq("response: close [returns: 1]  [errno: 0] ()"));
}

TEST(MessageTest, StringInTest) {
  EXPECT_THAT(FormatRequest(SYS_open, "foobar", 0, 0),
              StrEq("request: open(0: filename [string \"foobar\"], 1: flags "
                    "[scalar 0], 2: mode [scalar 0])"));
}

TEST(MessageTest, NullPointerTest) {
  EXPECT_THAT(FormatRequest(SYS_open, nullptr, 0, 0),
              StrEq("request: open(0: filename [nullptr], 1: flags "
                    "[scalar 0], 2: mode [scalar 0])"));
  EXPECT_THAT(
      FormatResponse(SYS_getcwd, 0, 0, nullptr, 0),
      StrEq("response: getcwd [returns: 0]  [errno: 0] (0: buf [nullptr])"));
  EXPECT_THAT(FormatRequest(SYS_write, 0, nullptr, 0),
              StrEq("request: write(0: fd [scalar 0], 1: buf [nullptr], "
                    "2: count [scalar 0])"));
  EXPECT_THAT(
      FormatResponse(SYS_read, 0, 0, 0, nullptr, 0),
      StrEq("response: read [returns: 0]  [errno: 0] (1: buf [nullptr])"));
}

TEST(MessageTest, StringOutTest) {
  EXPECT_THAT(
      FormatResponse(SYS_getcwd, 0, 0, "foobar", 7),
      StrEq("response: getcwd [returns: 0]  [errno: 0] (0: buf [bounded 7])"));
}

TEST(MessageTest, FixedTest) {
  struct stat buf;
  EXPECT_THAT(FormatRequest(SYS_stat, "/tmp/foo", &buf),
              StrEq("request: stat(0: filename [string \"/tmp/foo\"])"));
  EXPECT_THAT(
      FormatResponse(SYS_stat, 0, 0, "/tmp/foo", &buf),
      StrEq(
          "response: stat [returns: 0]  [errno: 0] (1: statbuf [fixed 144])"));
}

TEST(MessageTest, BoundedInTest) {
  char buf[1024];
  EXPECT_THAT(FormatRequest(SYS_write, 0, buf, sizeof(buf)),
              StrEq("request: write(0: fd [scalar 0], 1: buf [bounded 1024], "
                    "2: count [scalar 1024])"));
}

TEST(MessageTest, BoundedOutTest) {
  char buf[1024];
  EXPECT_THAT(
      FormatResponse(SYS_read, 0, 0, 0, buf, sizeof(buf)),
      StrEq("response: read [returns: 0]  [errno: 0] (1: buf [bounded 1024])"));
}

TEST(MessageTest, MessageHeaderNotCompleteTest) {
  uint8_t *response_buffer = nullptr;
  MessageReader reader({response_buffer, 0});
  primitives::PrimitiveStatus status = reader.Validate();
  EXPECT_THAT(status.error_code(),
              Eq(primitives::AbslStatusCode::kInvalidArgument));
  EXPECT_THAT(status.error_message(),
              StrEq("Message malformed: no completed header present"));
}

TEST(MessageTest, MessageMagicNumberMisMatchTest) {
  char buf[1024] = "abc";
  std::array<uint64_t, 6> parameters;
  CollectParameters(&parameters[0], 0, buf, sizeof(buf));
  auto writer = MessageWriter::ResponseWriter(SYS_read, 0, 0, parameters);
  std::vector<uint8_t> buffer(writer.MessageSize());
  primitives::Extent message{buffer.data(), buffer.size()};
  writer.Write(&message);
  reinterpret_cast<MessageHeader *>(message.data())->magic = -1;
  MessageReader reader(message);
  primitives::PrimitiveStatus status = reader.Validate();
  EXPECT_THAT(status.error_code(),
              Eq(primitives::AbslStatusCode::kInvalidArgument));
  EXPECT_THAT(status.error_message(),
              StrEq("Message malformed: magic number mismatched"));
}

TEST(MessageTest, MessageFlagBothRequestResponseTest) {
  char buf[1024] = "abc";
  std::array<uint64_t, 6> parameters;
  CollectParameters(&parameters[0], 0, buf, sizeof(buf));
  auto writer = MessageWriter::ResponseWriter(SYS_read, 0, 0, parameters);
  std::vector<uint8_t> buffer(writer.MessageSize());
  primitives::Extent message{buffer.data(), buffer.size()};
  writer.Write(&message);
  reinterpret_cast<MessageHeader *>(message.data())->flags = 0xFFFFFFFF;
  MessageReader reader(message);
  primitives::PrimitiveStatus status = reader.Validate();
  EXPECT_THAT(status.error_code(),
              Eq(primitives::AbslStatusCode::kInvalidArgument));
  EXPECT_THAT(status.error_message(),
              StrEq("Message malformed: should be either a request or a "
                    "response"));
}

TEST(MessageTest, MessageSystemCallNumberInvalidTest) {
  char buf[1024] = "abc";
  std::array<uint64_t, 6> parameters;
  CollectParameters(&parameters[0], 0, buf, sizeof(buf));
  auto writer = MessageWriter::ResponseWriter(SYS_read, 0, 0, parameters);
  std::vector<uint8_t> buffer(writer.MessageSize());
  primitives::Extent message{buffer.data(), buffer.size()};
  writer.Write(&message);
  reinterpret_cast<MessageHeader *>(message.data())->sysno = -1;
  MessageReader reader(message);
  primitives::PrimitiveStatus status = reader.Validate();
  EXPECT_THAT(status.error_code(),
              Eq(primitives::AbslStatusCode::kInvalidArgument));
  EXPECT_THAT(
      status.error_message(),
      StrEq(absl::StrCat("Message malformed: sysno ", -1, " is invalid")));
}

TEST(MessageTest, FixedDataSizeMisMatchTest) {
  struct sockaddr *usockaddr = nullptr;
  int usockaddr_len[1] = {0};
  std::array<uint64_t, 6> parameters;
  CollectParameters(&parameters[0], 0, usockaddr, usockaddr_len);
  auto writer =
      MessageWriter::ResponseWriter(SYS_getsockname, 0, 0, parameters);
  std::vector<uint8_t> buffer(writer.MessageSize());
  primitives::Extent message(buffer.data(), buffer.size());
  writer.Write(&message);
  MessageReader reader(message);
  primitives::PrimitiveStatus status = reader.Validate();
  EXPECT_THAT(status.error_code(),
              Eq(primitives::AbslStatusCode::kInvalidArgument));
  // 2nd parameter is kFixed and have mismatched size.
  EXPECT_THAT(status.error_message(),
              StrEq(absl::StrCat("Message malformed: parameter under index ",
                                 "1 size mismatched")));
}

TEST(MessageTest, ScalarDataSizeMisMatchTest) {
  cpu_set_t *user_mask = nullptr;

  std::array<uint64_t, 6> parameters;
  CollectParameters(&parameters[0], 0, 0, user_mask);

  auto writer =
      MessageWriter::ResponseWriter(SYS_sched_getaffinity, 0, 0, parameters);
  std::vector<uint8_t> buffer(writer.MessageSize());
  primitives::Extent message(buffer.data(), buffer.size());
  writer.Write(&message);
  reinterpret_cast<MessageHeader *>(message.data())->size[1] = 1;
  MessageReader reader(message);
  primitives::PrimitiveStatus status = reader.Validate();
  EXPECT_THAT(status.error_code(),
              Eq(primitives::AbslStatusCode::kInvalidArgument));
  // 2nd parameter is kScalar and have mismatched size.
  EXPECT_THAT(status.error_message(),
              StrEq(absl::StrCat("Message malformed: parameter under index ",
                                 "2 size mismatched")));
}

TEST(MessageTest, StringDataSizeMisMatchTest) {
  const char *path = "abc\0";
  int length = 3;
  std::array<uint64_t, 6> parameters;
  CollectParameters(&parameters[0], path, length);
  auto writer = MessageWriter::RequestWriter(SYS_truncate, parameters);
  std::vector<uint8_t> buffer(writer.MessageSize());
  primitives::Extent message(buffer.data(), buffer.size());
  writer.Write(&message);
  reinterpret_cast<MessageHeader *>(message.data())->size[0] = 5;
  MessageReader reader(message);
  primitives::PrimitiveStatus status = reader.Validate();
  EXPECT_THAT(status.error_code(),
              Eq(primitives::AbslStatusCode::kInvalidArgument));
  // 1st parameter is kString and have mismatched size.
  EXPECT_THAT(status.error_message(),
              StrEq(absl::StrCat("Message malformed: parameter under index ",
                                 "0 size mismatched")));
}

TEST(MessageTest, NonNullTerminatedStringParameterTest) {
  const char *path = "abc";
  int length = 3;
  std::array<uint64_t, 6> parameters;
  CollectParameters(&parameters[0], path, length);
  auto writer = MessageWriter::RequestWriter(SYS_truncate, parameters);
  std::vector<uint8_t> buffer(writer.MessageSize());
  primitives::Extent message(buffer.data(), buffer.size());
  writer.Write(&message);
  reinterpret_cast<MessageHeader *>(message.data())->size[0] = 2;
  MessageReader reader(message);
  primitives::PrimitiveStatus status = reader.Validate();
  EXPECT_THAT(status.error_code(),
              Eq(primitives::AbslStatusCode::kInvalidArgument));
  // 1st parameter is kString and not null terminated.
  EXPECT_THAT(status.error_message(),
              StrEq(absl::StrCat("Message malformed: parameter under index ",
                                 "0 size mismatched")));
}

TEST(MessageTest, NegativeSizeTest) {
  char buf[1024] = "abc";
  std::array<uint64_t, 6> parameters;
  CollectParameters(&parameters[0], 0, buf, 0);
  auto writer = MessageWriter::ResponseWriter(SYS_read, 0, 0, parameters);
  std::vector<uint8_t> buffer(writer.MessageSize());
  primitives::Extent message{buffer.data(), buffer.size()};
  writer.Write(&message);
  MessageReader reader(message);
  primitives::PrimitiveStatus status = reader.Validate();
  EXPECT_THAT(status.error_code(), Eq(primitives::AbslStatusCode::kOk));
}

TEST(MessageTest, OffsetDriftTest) {
  char buf[1024] = "abc";
  std::array<uint64_t, 6> parameters;
  CollectParameters(&parameters[0], 0, buf, sizeof(buf));
  auto writer = MessageWriter::ResponseWriter(SYS_read, 0, 0, parameters);
  std::vector<uint8_t> buffer(writer.MessageSize());
  primitives::Extent message{buffer.data(), buffer.size()};
  writer.Write(&message);
  // there are three parameters: path, buf and size. buf is the only output.
  reinterpret_cast<MessageHeader *>(message.data())->offset[1] = 0;
  MessageReader reader(message);
  primitives::PrimitiveStatus status = reader.Validate();
  EXPECT_THAT(status.error_code(),
              Eq(primitives::AbslStatusCode::kInvalidArgument));
  EXPECT_THAT(status.error_message(),
              StrEq(absl::StrCat("Message malformed: parameter under index ", 1,
                                 " has drifted offset")));
}

TEST(MessageTest, OffsetOverflowTest) {
  char buf[1024] = "abc";
  std::array<uint64_t, 6> parameters;
  CollectParameters(&parameters[0], 0, buf, sizeof(buf));
  auto writer = MessageWriter::ResponseWriter(SYS_read, 0, 0, parameters);
  std::vector<uint8_t> buffer(writer.MessageSize());
  primitives::Extent message{buffer.data(), buffer.size() - 1};
  writer.Write(&message);
  MessageReader reader(message);
  primitives::PrimitiveStatus status = reader.Validate();
  EXPECT_THAT(status.error_code(),
              Eq(primitives::AbslStatusCode::kInvalidArgument));
  // there are three parameters: path, buf and size. buf is the only output.
  EXPECT_THAT(status.error_message(),
              StrEq(absl::StrCat("Message malformed: parameter under index ", 1,
                                 " overflowed from buffer memory")));
}

TEST(MessageTest, OffsetOverflowFromUint64Test) {
  char buf[1024] = "abc";
  std::array<uint64_t, 6> parameters;
  CollectParameters(&parameters[0], 0, buf, sizeof(buf));
  auto writer = MessageWriter::ResponseWriter(SYS_read, 0, 0, parameters);
  std::vector<uint8_t> buffer(writer.MessageSize());
  primitives::Extent message{buffer.data(), buffer.size()};
  writer.Write(&message);
  // there are three parameters: path, buf and size. buf is the only output.
  reinterpret_cast<MessageHeader *>(message.data())->size[1] = SIZE_MAX;
  MessageReader reader(message);
  primitives::PrimitiveStatus status = reader.Validate();
  EXPECT_THAT(status.error_code(),
              Eq(primitives::AbslStatusCode::kInvalidArgument));
  EXPECT_THAT(status.error_message(),
              StrEq(absl::StrCat("Message malformed: parameter under index ", 1,
                                 " resides above max offset")));
}

}  // namespace
}  // namespace system_call
}  // namespace asylo
