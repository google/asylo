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

const uint8_t localhost_ipv4_bytes[4] = {127, 0, 0, 1};
const uint8_t localhost_ipv6_bytes[16] = {0, 0, 0, 0, 0, 0, 0, 0,
                                          0, 0, 0, 0, 0, 0, 0, 1};
TEST(InetPtonTest, IPv4) {
  struct in_addr addr;
  EXPECT_EQ(inet_pton(AF_INET, "127.0.0.1", &addr), 1);
  uint8_t *addr_arr = reinterpret_cast<uint8_t *>(&addr.s_addr);
  for (int i = 0; i < sizeof(in_addr_t); ++i) {
    EXPECT_EQ(addr_arr[i], localhost_ipv4_bytes[i]);
  }
}

TEST(InetPtonTest, IPv6) {
  struct in6_addr addr;
  EXPECT_EQ(inet_pton(AF_INET6, "::1", &addr), 1);
  for (int i = 0; i < sizeof(struct in6_addr); ++i) {
    EXPECT_EQ(addr.s6_addr[i], localhost_ipv6_bytes[i]);
  }
}

}  // namespace
