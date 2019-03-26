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

#include <sys/syscall.h>

#include <array>
#include <cstdint>
#include <string>
#include <type_traits>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "absl/base/casts.h"
#include "asylo/platform/system_call/message.h"

namespace asylo {
namespace system_call {
namespace {

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
void CollectParameters(uint64_t *parameters, T first, Args &&... rest) {
  *parameters = CastToWord(first);
  CollectParameters(parameters + 1, rest...);
}

// Builds a system call request message and formats it as a string.
template <typename... Args>
std::string FormatRequest(int sysno, Args &&... args) {
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
std::string FormatResponse(int sysno, uint64_t result, Args &&... args) {
  std::array<uint64_t, 6> parameters;
  CollectParameters(&parameters[0], args...);
  auto writer = MessageWriter::ResponseWriter(sysno, result, parameters);
  std::vector<uint8_t> buffer(writer.MessageSize());
  primitives::Extent message{buffer.data(), buffer.size()};
  writer.Write(&message);
  return FormatMessage(message);
}

TEST(MessageTest, ZeroParameterTest) {
  EXPECT_THAT(FormatRequest(SYS_getpid), StrEq("request: getpid()"));
  EXPECT_THAT(FormatResponse(SYS_getpid, 1234),
              StrEq("response: getpid [returns: 1234] ()"));
}

TEST(MessageTest, ScalarInTest) {
  EXPECT_THAT(FormatRequest(SYS_close, 1234),
              StrEq("request: close(0: fd [scalar 1234])"));
  EXPECT_THAT(FormatResponse(SYS_close, 1),
              StrEq("response: close [returns: 1] ()"));
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
  EXPECT_THAT(FormatResponse(SYS_getcwd, 0, nullptr, 0),
              StrEq("response: getcwd [returns: 0] (0: buf [nullptr])"));
  EXPECT_THAT(FormatRequest(SYS_write, 0, nullptr, 0),
              StrEq("request: write(0: fd [scalar 0], 1: buf [nullptr], "
                    "2: count [scalar 0])"));
  EXPECT_THAT(FormatResponse(SYS_read, 0, 0, nullptr, 0),
              StrEq("response: read [returns: 0] (1: buf [nullptr])"));
}

TEST(MessageTest, StringOutTest) {
  EXPECT_THAT(FormatResponse(SYS_getcwd, 0, "foobar", 7),
              StrEq("response: getcwd [returns: 0] (0: buf [bounded 7])"));
}

TEST(MessageTest, FixedTest) {
  struct stat buf;
  EXPECT_THAT(FormatRequest(SYS_stat, "/tmp/foo", &buf),
              StrEq("request: stat(0: filename [string \"/tmp/foo\"])"));
  EXPECT_THAT(FormatResponse(SYS_stat, 0, "/tmp/foo", &buf),
              StrEq("response: stat [returns: 0] (1: statbuf [fixed 144])"));
}

TEST(MessageTest, BoundedInTest) {
  char buf[1024];
  EXPECT_THAT(FormatRequest(SYS_write, 0, buf, sizeof(buf)),
              StrEq("request: write(0: fd [scalar 0], 1: buf [bounded 1024], "
                    "2: count [scalar 1024])"));
}

TEST(MessageTest, BoundedOutTest) {
  char buf[1024];
  EXPECT_THAT(FormatResponse(SYS_read, 0, 0, buf, sizeof(buf)),
              StrEq("response: read [returns: 0] (1: buf [bounded 1024])"));
}

}  // namespace
}  // namespace system_call
}  // namespace asylo
