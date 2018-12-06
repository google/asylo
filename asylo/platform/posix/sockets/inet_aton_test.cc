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

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <cstdlib>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/strings/str_format.h"
#include "asylo/util/logging.h"

namespace asylo {
namespace {

// Parses an address with inet_aton, returning the result as a 4-byte value in
// network byte order, or check fail if parsing failed.
uint32_t ParseAddress(const std::string &str) {
  struct in_addr addr;
  CHECK_NE(inet_aton(str.c_str(), &addr), 0) << "Could not parse: " << str;
  return addr.s_addr;
}

TEST(InetAtonTest, OneChunk) {
  EXPECT_EQ(ParseAddress("0"), 0);
  EXPECT_EQ(ParseAddress("1734575198"), 1585734503);
  EXPECT_EQ(ParseAddress("1973594324"), 3567821429);
  EXPECT_EQ(ParseAddress("149798315"), 2881350920);
  EXPECT_EQ(ParseAddress("2038664370"), 2995553145);
  EXPECT_EQ(ParseAddress("1129566413"), 3452982083);
}

TEST(InetAtonTest, TwoChunks) {
  EXPECT_EQ(ParseAddress("0.0"), 0);
  EXPECT_EQ(ParseAddress("61.2996848"), 1891249469);
  EXPECT_EQ(ParseAddress("82.7418056"), 3358617938);
  EXPECT_EQ(ParseAddress("213.7102824"), 1751215317);
  EXPECT_EQ(ParseAddress("74.3846456"), 951138890);
  EXPECT_EQ(ParseAddress("142.4434044"), 2091402126);
}

TEST(InetAtonTest, ThreeChunks) {
  EXPECT_EQ(ParseAddress("0.0.0"), 0);
  EXPECT_EQ(ParseAddress("39.87.2303"), 4278736679);
  EXPECT_EQ(ParseAddress("212.5.9092"), 2216887764);
  EXPECT_EQ(ParseAddress("130.82.32848"), 1350587010);
  EXPECT_EQ(ParseAddress("27.117.1649"), 1896248603);
  EXPECT_EQ(ParseAddress("237.74.33558"), 377703149);
}

TEST(InetAtonTest, FourChunks) {
  EXPECT_EQ(ParseAddress("0.0.0.0"), 0);
  EXPECT_EQ(ParseAddress("83.85.162.151"), 2543998291);
  EXPECT_EQ(ParseAddress("249.252.241.190"), 3203529977);
  EXPECT_EQ(ParseAddress("20.82.107.121"), 2037076500);
  EXPECT_EQ(ParseAddress("45.226.233.19"), 334094893);
  EXPECT_EQ(ParseAddress("86.31.142.81"), 1368268630);

  EXPECT_EQ(ParseAddress("86.31.142.81"), 1368268630);

  // Try a hexadecimal example.
  EXPECT_EQ(ParseAddress("0x56.0x1f.0x8e.0x51"), 1368268630);

  // Try an octal example.
  EXPECT_EQ(ParseAddress("0126.0037.0216.0121"), 1368268630);

  // Try a mixed example.
  EXPECT_EQ(ParseAddress("86.0x1f.0216.81"), 1368268630);
}

TEST(InetAtonTest, BadAddress) {
  struct in_addr addr;
// The native implementation of inet_aton crashes if it is passed a null
// pointer, so we only test this condition in the enclave case.
#ifdef __ASYLO__
  EXPECT_EQ(inet_aton(nullptr, &addr), 0);
#endif  // __ASYLO__
  EXPECT_EQ(inet_aton("", &addr), 0);
  EXPECT_EQ(inet_aton("hello world", &addr), 0);
  EXPECT_EQ(inet_aton("256.1.1.1", &addr), 0);
  EXPECT_EQ(inet_aton("255.1.1.1.1", &addr), 0);
  EXPECT_EQ(inet_aton("1000.1", &addr), 0);
  EXPECT_EQ(inet_aton("1000.1!", &addr), 0);
  EXPECT_EQ(inet_aton("-255.1.1.1", &addr), 0);
  EXPECT_EQ(inet_aton("+255.1.1.1", &addr), 0);
}

TEST(InetAtonTest, EnumerateMany) {
  constexpr size_t kStepSize = 0xFEFE;
  for (uint32_t i = 0; UINT32_MAX - i > kStepSize; i += kStepSize) {
    const std::string address = absl::StrFormat(
        "%u.%u.%u.%u", i >> 24 & 0xFF, i >> 16 & 0xFF, i >> 8 & 0xFF, i & 0xFF);
    EXPECT_EQ(htonl(i), ParseAddress(address));
  }
}

}  // namespace
}  // namespace asylo
