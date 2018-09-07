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
#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace {
// Case "a" -- this number is a representation of 127.0.0.1 as uint32_t.
const char *kOneChunk = "2130706433";
// Case "a.b"
const char *kTwoChunks = "127.1";
// Case "a.b.c"
const char *kThreeChunks = "127.0.1";
// Case "a.b.c.d"
const char *kFourChunks = "127.0.0.1";
// Quartet bytes
const uint8_t bytes[4] = {127, 0, 0, 1};

void VerifyAddress(struct in_addr addr) {
  uint8_t *addr_arr = reinterpret_cast<uint8_t *>(&addr.s_addr);
  for (size_t i = 0; i < sizeof(in_addr_t); ++i) {
    EXPECT_EQ(addr_arr[i], bytes[i]);
  }
}

TEST(InetAtonTest, OneChunk) {
  struct in_addr addr;
  EXPECT_EQ(inet_aton(kOneChunk, &addr), 1);
  VerifyAddress(addr);
}

TEST(InetAtonTest, TwoChunks) {
  struct in_addr addr;
  EXPECT_EQ(inet_aton(kTwoChunks, &addr), 1);
  VerifyAddress(addr);
}

TEST(InetAtonTest, ThreeChunks) {
  struct in_addr addr;
  EXPECT_EQ(inet_aton(kThreeChunks, &addr), 1);
  VerifyAddress(addr);
}

TEST(InetAtonTest, FourChunks) {
  struct in_addr addr;
  EXPECT_EQ(inet_aton(kFourChunks, &addr), 1);
  VerifyAddress(addr);
}

}  // namespace
