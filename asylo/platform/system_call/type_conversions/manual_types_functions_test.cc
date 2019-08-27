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

#include "asylo/platform/system_call/type_conversions/manual_types_functions.h"

#include <netinet/in.h>
#include <sys/un.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using ::testing::Eq;
using ::testing::StrEq;

namespace asylo {
namespace system_call {
namespace {

TEST(ManualTypesFunctionsTest, SocketTypeTest) {
  std::vector<int> from_bits = {kLinux_SOCK_STREAM,    kLinux_SOCK_DGRAM,
                                kLinux_SOCK_SEQPACKET, kLinux_SOCK_RAW,
                                kLinux_SOCK_RDM,       kLinux_SOCK_PACKET,
                                kLinux_SOCK_NONBLOCK,  kLinux_SOCK_CLOEXEC};

  std::vector<int> to_bits = {SOCK_STREAM,   SOCK_DGRAM,  SOCK_SEQPACKET,
                              SOCK_RAW,      SOCK_RDM,    SOCK_PACKET,
                              SOCK_NONBLOCK, SOCK_CLOEXEC};

  for (int i = 0; i < from_bits.size(); i++) {
    int output;
    TokLinuxSocketType(&to_bits[i], &output);
    EXPECT_THAT(output, Eq(from_bits[i]));
    FromkLinuxSocketType(&from_bits[i], &output);
    EXPECT_THAT(output, Eq(to_bits[i]));

    int from = kLinux_SOCK_CLOEXEC | kLinux_SOCK_NONBLOCK | from_bits[i];
    int to = SOCK_CLOEXEC | SOCK_NONBLOCK | to_bits[i];
    TokLinuxSocketType(&to, &output);
    EXPECT_THAT(output, Eq(from));
    FromkLinuxSocketType(&from, &output);
    EXPECT_THAT(output, Eq(to));

    from = kLinux_SOCK_CLOEXEC | from_bits[i];
    to = SOCK_CLOEXEC | to_bits[i];
    TokLinuxSocketType(&to, &output);
    EXPECT_THAT(output, Eq(from));
    FromkLinuxSocketType(&from, &output);
    EXPECT_THAT(output, Eq(to));

    from = kLinux_SOCK_NONBLOCK | from_bits[i];
    to = SOCK_NONBLOCK | to_bits[i];
    TokLinuxSocketType(&to, &output);
    EXPECT_THAT(output, Eq(from));
    FromkLinuxSocketType(&from, &output);
    EXPECT_THAT(output, Eq(to));
  }
}

TEST(ManualTypesFunctionsTest, SockaddrTokLinuxSockaddrUnTest) {
  std::string sockpath = "/some/path";

  struct sockaddr_un sock_un;
  memset(&sock_un, 0, sizeof(struct sockaddr_un));
  sock_un.sun_family = AF_UNIX;
  strncpy(sock_un.sun_path, sockpath.c_str(), sizeof(sock_un.sun_path) - 1);

  struct klinux_sockaddr_un klinux_sock_un;
  SockaddrTokLinuxSockaddrUn(reinterpret_cast<sockaddr *>(&sock_un),
                             sizeof(struct sockaddr_un), &klinux_sock_un);
  EXPECT_THAT(klinux_sock_un.klinux_sun_family, Eq(kLinux_AF_UNIX));
  EXPECT_THAT(klinux_sock_un.klinux_sun_path, StrEq(sockpath));
}

TEST(ManualTypesFunctionsTest, SockaddrTokLinuxSockaddrInTest) {
  struct in_addr in_addr_in;
  in_addr_in.s_addr = 123;

  struct sockaddr_in sock_in;
  memset(&sock_in, 0, sizeof(struct sockaddr_in));
  sock_in.sin_family = AF_INET;
  sock_in.sin_port = 12;
  sock_in.sin_addr = in_addr_in;

  struct klinux_sockaddr_in klinux_sock_in;
  SockaddrTokLinuxSockaddrIn(reinterpret_cast<sockaddr *>(&sock_in),
                             sizeof(struct sockaddr_in), &klinux_sock_in);
  EXPECT_THAT(klinux_sock_in.klinux_sin_family, Eq(kLinux_AF_INET));
  EXPECT_THAT(klinux_sock_in.klinux_sin_port, Eq(12));
  EXPECT_THAT(klinux_sock_in.klinux_sin_addr.klinux_s_addr, Eq(123));
}

TEST(ManualTypesFunctionsTest, SockaddrTokLinuxSockaddrIn6Test) {
  struct sockaddr_in6 sock_in6;
  memset(&sock_in6, 0, sizeof(struct sockaddr_in6));
  sock_in6.sin6_family = AF_INET6;
  sock_in6.sin6_port = 1;
  sock_in6.sin6_scope_id = 12;
  sock_in6.sin6_flowinfo = 123;
  sock_in6.sin6_addr = in6addr_loopback;

  struct klinux_sockaddr_in6 klinux_sock_in6;
  SockaddrTokLinuxSockaddrIn6(reinterpret_cast<sockaddr *>(&sock_in6),
                              sizeof(struct sockaddr_in6), &klinux_sock_in6);
  EXPECT_THAT(klinux_sock_in6.klinux_sin6_family, Eq(kLinux_AF_INET6));
  EXPECT_THAT(klinux_sock_in6.klinux_sin6_port, Eq(1));
  EXPECT_THAT(klinux_sock_in6.klinux_sin6_scope_id, Eq(12));
  EXPECT_THAT(klinux_sock_in6.klinux_sin6_flowinfo, Eq(123));
  EXPECT_THAT(
      reinterpret_cast<char *>(klinux_sock_in6.klinux_sin6_addr.klinux_s6_addr),
      StrEq(reinterpret_cast<const char *>(in6addr_loopback.s6_addr)));
}

TEST(ManualTypesFunctionsTest, FromkLinuxSockAddrToSockAddrUnTest) {
  std::string sockpath = "/some/path";

  struct klinux_sockaddr_un klinux_sock_un;
  memset(&klinux_sock_un, 0, sizeof(struct klinux_sockaddr_un));
  klinux_sock_un.klinux_sun_family = kLinux_AF_UNIX;
  strncpy(klinux_sock_un.klinux_sun_path, sockpath.c_str(),
          sizeof(klinux_sock_un.klinux_sun_path) - 1);

  struct sockaddr_un sock_un;
  socklen_t sock_un_len = sizeof(sock_un);
  FromkLinuxSockAddr(reinterpret_cast<klinux_sockaddr *>(&klinux_sock_un),
                     sizeof(klinux_sock_un),
                     reinterpret_cast<sockaddr *>(&sock_un), &sock_un_len,
                     nullptr);
  EXPECT_THAT(sock_un.sun_family, Eq(AF_UNIX));
  EXPECT_THAT(sock_un.sun_path, StrEq(sockpath));
  EXPECT_THAT(sock_un_len, Eq(sizeof(struct sockaddr_un)));
}

TEST(ManualTypesFunctionsTest, FromkLinuxSockAddrToSockAddrUnTruncateTest) {
  std::string sockpath = "/some/path";
  std::string truncated_path = "/some";

  klinux_sockaddr_un klinux_sock_un = {};
  memset(&klinux_sock_un, 0, sizeof(struct klinux_sockaddr_un));
  klinux_sock_un.klinux_sun_family = kLinux_AF_UNIX;
  strncpy(klinux_sock_un.klinux_sun_path, sockpath.c_str(),
          sizeof(klinux_sock_un.klinux_sun_path) - 1);

  sockaddr sock = {};
  socklen_t sock_len = sizeof(sa_family_t) + truncated_path.length();
  FromkLinuxSockAddr(reinterpret_cast<klinux_sockaddr *>(&klinux_sock_un),
                     sizeof(klinux_sock_un),
                     reinterpret_cast<sockaddr *>(&sock), &sock_len, nullptr);
  auto sock_un = reinterpret_cast<sockaddr_un *>(&sock);
  EXPECT_THAT(sock_un->sun_family, Eq(AF_UNIX));
  EXPECT_THAT(sock_un->sun_path, StrEq(truncated_path));
}

}  // namespace
}  // namespace system_call
}  // namespace asylo
