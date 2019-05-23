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

#include "asylo/platform/system_call/type_conversions/generated_types_functions.h"

#include <functional>
#include <vector>

#include <gtest/gtest.h>
#include "asylo/test/util/finite_domain_fuzz.h"

namespace asylo {
namespace system_call {
namespace {

using ::testing::Eq;

// These tests only validate the behavior and correctness of the generated types
// conversion functions. It does not test the internal implementation of the
// types conversions generator itself.

// Arbitrarily chosen number of iterations.
constexpr int kIterationCount = 6000;

class GeneratedTypesFunctionsTest : public ::testing::Test {
 public:

  void TestMultiValuedEnums(
      const std::vector<int>& from_bits, const std::vector<int>& to_bits,
      const std::function<void(const int*, int*)>& from_function,
      const std::function<void(const int*, int*)>& to_function) {
    auto from_test_function = [&](int input) {
      int output;
      from_function(&input, &output);
      return output;
    };
    auto to_test_function = [&](int input) {
      int output;
      to_function(&input, &output);
      return output;
    };

    auto from_matcher = IsFiniteRestrictionOf<int, int>(from_test_function);
    auto to_matcher = IsFiniteRestrictionOf<int, int>(to_test_function);
    EXPECT_THAT(
        FuzzBitsetTranslationFunction(from_bits, to_bits, kIterationCount),
        from_matcher);
    EXPECT_THAT(
        FuzzBitsetTranslationFunction(to_bits, from_bits, kIterationCount),
        to_matcher);
  }
};

TEST_F(GeneratedTypesFunctionsTest, FileStatusFlagTest) {
  std::vector<int> from_bits = {
      kLinux_O_RDONLY, kLinux_O_WRONLY, kLinux_O_RDWR,  kLinux_O_CREAT,
      kLinux_O_APPEND, kLinux_O_EXCL,   kLinux_O_TRUNC, kLinux_O_NONBLOCK,
      kLinux_O_DIRECT, kLinux_O_CLOEXEC};
  std::vector<int> to_bits = {O_RDONLY, O_WRONLY, O_RDWR,  O_CREAT,
                              O_APPEND, O_EXCL,   O_TRUNC, O_NONBLOCK,
                              O_DIRECT, O_CLOEXEC};

  TestMultiValuedEnums(from_bits, to_bits, FromkLinuxFileStatusFlag,
                       TokLinuxFileStatusFlag);
}

TEST_F(GeneratedTypesFunctionsTest, FcntlCommandTest) {
  std::vector<int> from_consts = {kLinux_F_GETFD,      kLinux_F_SETFD,
                                  kLinux_F_GETFL,      kLinux_F_SETFL,
                                  kLinux_F_GETPIPE_SZ, kLinux_F_SETPIPE_SZ};
  std::vector<int> to_consts = {F_GETFD, F_SETFD,      F_GETFL,
                                F_SETFL, F_GETPIPE_SZ, F_SETPIPE_SZ};

  auto from_matcher = IsFiniteRestrictionOf<int, int>([&](int input) {
    int output;
    FromkLinuxFcntlCommand(&input, &output);
    return output;
  });
  EXPECT_THAT(FuzzFiniteFunctionWithFallback(from_consts, to_consts, -1,
                                             kIterationCount),
              from_matcher);
  auto to_matcher = IsFiniteRestrictionOf<int, int>([&](int input) {
    int output;
    TokLinuxFcntlCommand(&input, &output);
    return output;
  });
  EXPECT_THAT(FuzzFiniteFunctionWithFallback(from_consts, to_consts, -1,
                                             kIterationCount),
              to_matcher);
}

TEST_F(GeneratedTypesFunctionsTest, AfFamilyTest) {
  std::vector<int> from_bits = {
      kLinux_AF_UNIX,      kLinux_AF_LOCAL,  kLinux_AF_INET,
      kLinux_AF_AX25,      kLinux_AF_IPX,    kLinux_AF_APPLETALK,
      kLinux_AF_X25,       kLinux_AF_ATMPVC, kLinux_AF_INET6,
      kLinux_AF_DECnet,    kLinux_AF_KEY,    kLinux_AF_NETLINK,
      kLinux_AF_PACKET,    kLinux_AF_RDS,    kLinux_AF_PPPOX,
      kLinux_AF_LLC,       kLinux_AF_CAN,    kLinux_AF_TIPC,
      kLinux_AF_BLUETOOTH, kLinux_AF_ALG,    kLinux_AF_VSOCK,
      kLinux_AF_UNSPEC};
  std::vector<int> to_bits = {
      AF_UNIX,      AF_LOCAL,  AF_INET,  AF_AX25,   AF_IPX, AF_APPLETALK,
      AF_X25,       AF_ATMPVC, AF_INET6, AF_DECnet, AF_KEY, AF_NETLINK,
      AF_PACKET,    AF_RDS,    AF_PPPOX, AF_LLC,    AF_CAN, AF_TIPC,
      AF_BLUETOOTH, AF_ALG,    AF_VSOCK, AF_UNSPEC};

  // We do not use FiniteDomain matcher here because the domain does not map
  // exactly to a predefined range. AF_UNIX and AF_LOCAL here may map to the
  // same value depending on the host platform.
  for (int i = 0; i < from_bits.size(); i++) {
    int result;
    TokLinuxAfFamily(&to_bits[i], &result);
    EXPECT_THAT(result, Eq(from_bits[i]));
    FromkLinuxAfFamily(&from_bits[i], &result);
    EXPECT_THAT(result, Eq(to_bits[i]));
  }
}

TEST_F(GeneratedTypesFunctionsTest, FDFlagTest) {
  std::vector<int> from_bits = {kLinux_FD_CLOEXEC};
  std::vector<int> to_bits = {FD_CLOEXEC};
  TestMultiValuedEnums(from_bits, to_bits, FromkLinuxFDFlag, TokLinuxFDFlag);
}

TEST_F(GeneratedTypesFunctionsTest, TcpOptionNameTest) {
  std::vector<int> from_consts = {kLinux_TCP_NODELAY, kLinux_TCP_KEEPIDLE,
                                  kLinux_TCP_KEEPINTVL, kLinux_TCP_KEEPCNT};
  std::vector<int> to_consts = {TCP_NODELAY, TCP_KEEPIDLE, TCP_KEEPINTVL,
                                TCP_KEEPCNT};
  auto from_matcher = IsFiniteRestrictionOf<int, int>([&](int input) {
    int output;
    FromkLinuxTcpOptionName(&input, &output);
    return output;
  });
  EXPECT_THAT(FuzzFiniteFunctionWithFallback(from_consts, to_consts, -1,
                                             kIterationCount),
              from_matcher);
  auto to_matcher = IsFiniteRestrictionOf<int, int>([&](int input) {
    int output;
    TokLinuxTcpOptionName(&input, &output);
    return output;
  });
  EXPECT_THAT(FuzzFiniteFunctionWithFallback(to_consts, from_consts, -1,
                                             kIterationCount),
              to_matcher);
}

TEST_F(GeneratedTypesFunctionsTest, IpV6OptionNameTest) {
  std::vector<int> from_consts = {
      kLinux_IPV6_V6ONLY,      kLinux_IPV6_RECVPKTINFO,
      kLinux_IPV6_PKTINFO,     kLinux_IPV6_RECVHOPLIMIT,
      kLinux_IPV6_HOPLIMIT,    kLinux_IPV6_RECVHOPOPTS,
      kLinux_IPV6_HOPOPTS,     kLinux_IPV6_RTHDRDSTOPTS,
      kLinux_IPV6_RECVRTHDR,   kLinux_IPV6_RTHDR,
      kLinux_IPV6_RECVDSTOPTS, kLinux_IPV6_DSTOPTS};
  std::vector<int> to_consts = {
      IPV6_V6ONLY,    IPV6_RECVPKTINFO, IPV6_PKTINFO,     IPV6_RECVHOPLIMIT,
      IPV6_HOPLIMIT,  IPV6_RECVHOPOPTS, IPV6_HOPOPTS,     IPV6_RTHDRDSTOPTS,
      IPV6_RECVRTHDR, IPV6_RTHDR,       IPV6_RECVDSTOPTS, IPV6_DSTOPTS};
  auto from_matcher = IsFiniteRestrictionOf<int, int>([&](int input) {
    int output;
    FromkLinuxIpV6OptionName(&input, &output);
    return output;
  });
  EXPECT_THAT(FuzzFiniteFunctionWithFallback(from_consts, to_consts, -1,
                                             kIterationCount),
              from_matcher);
  auto to_matcher = IsFiniteRestrictionOf<int, int>([&](int input) {
    int output;
    TokLinuxIpV6OptionName(&input, &output);
    return output;
  });
  EXPECT_THAT(FuzzFiniteFunctionWithFallback(to_consts, from_consts, -1,
                                             kIterationCount),
              to_matcher);
}

TEST_F(GeneratedTypesFunctionsTest, SocketOptionNameTest) {
  std::vector<int> from_consts = {
      kLinux_SO_DEBUG,       kLinux_SO_REUSEADDR, kLinux_SO_TYPE,
      kLinux_SO_ERROR,       kLinux_SO_DONTROUTE, kLinux_SO_BROADCAST,
      kLinux_SO_SNDBUF,      kLinux_SO_RCVBUF,    kLinux_SO_SNDBUFFORCE,
      kLinux_SO_RCVBUFFORCE, kLinux_SO_KEEPALIVE, kLinux_SO_OOBINLINE,
      kLinux_SO_NO_CHECK,    kLinux_SO_PRIORITY,  kLinux_SO_LINGER,
      kLinux_SO_BSDCOMPAT,   kLinux_SO_REUSEPORT, kLinux_SO_RCVTIMEO,
      kLinux_SO_SNDTIMEO};
  std::vector<int> to_consts = {
      SO_DEBUG,     SO_REUSEADDR, SO_TYPE,     SO_ERROR,       SO_DONTROUTE,
      SO_BROADCAST, SO_SNDBUF,    SO_RCVBUF,   SO_SNDBUFFORCE, SO_RCVBUFFORCE,
      SO_KEEPALIVE, SO_OOBINLINE, SO_NO_CHECK, SO_PRIORITY,    SO_LINGER,
      SO_BSDCOMPAT, SO_REUSEPORT, SO_RCVTIMEO, SO_SNDTIMEO};
  auto from_matcher = IsFiniteRestrictionOf<int, int>([&](int input) {
    int output;
    FromkLinuxSocketOptionName(&input, &output);
    return output;
  });
  EXPECT_THAT(FuzzFiniteFunctionWithFallback(from_consts, to_consts, -1,
                                             kIterationCount),
              from_matcher);
  auto to_matcher = IsFiniteRestrictionOf<int, int>([&](int input) {
    int output;
    TokLinuxSocketOptionName(&input, &output);
    return output;
  });
  EXPECT_THAT(FuzzFiniteFunctionWithFallback(to_consts, from_consts, -1,
                                             kIterationCount),
              to_matcher);
}

TEST_F(GeneratedTypesFunctionsTest, FlockOperationTest) {
  std::vector<int> from_bits = {kLinux_LOCK_SH, kLinux_LOCK_EX, kLinux_LOCK_NB,
                                kLinux_LOCK_UN};
  std::vector<int> to_bits = {LOCK_SH, LOCK_EX, LOCK_NB, LOCK_UN};
  TestMultiValuedEnums(from_bits, to_bits, FromkLinuxFLockOperation,
                       TokLinuxFLockOperation);
}

TEST_F(GeneratedTypesFunctionsTest, InotifyFlagsTest) {
  std::vector<int> from_bits = {kLinux_IN_NONBLOCK, kLinux_IN_CLOEXEC};
  std::vector<int> to_bits = {IN_NONBLOCK, IN_CLOEXEC};
  TestMultiValuedEnums(from_bits, to_bits, FromkLinuxInotifyFlag,
                       TokLinuxInotifyFlag);
}

TEST_F(GeneratedTypesFunctionsTest, InotifyEventMaskTest) {
  std::vector<int> from_bits = {
      kLinux_IN_ACCESS,      kLinux_IN_MODIFY,        kLinux_IN_ATTRIB,
      kLinux_IN_CLOSE_WRITE, kLinux_IN_CLOSE_NOWRITE, kLinux_IN_OPEN,
      kLinux_IN_MOVED_FROM,  kLinux_IN_MOVED_TO,      kLinux_IN_CREATE,
      kLinux_IN_DELETE,      kLinux_IN_DELETE_SELF,   kLinux_IN_MOVE_SELF,
      kLinux_IN_UNMOUNT,     kLinux_IN_Q_OVERFLOW,    kLinux_IN_IGNORED};
  std::vector<int> to_bits = {IN_ACCESS,      IN_MODIFY,        IN_ATTRIB,
                              IN_CLOSE_WRITE, IN_CLOSE_NOWRITE, IN_OPEN,
                              IN_MOVED_FROM,  IN_MOVED_TO,      IN_CREATE,
                              IN_DELETE,      IN_DELETE_SELF,   IN_MOVE_SELF,
                              IN_UNMOUNT,     IN_Q_OVERFLOW,    IN_IGNORED};
  TestMultiValuedEnums(from_bits, to_bits, FromkLinuxInotifyEventMask,
                       TokLinuxInotifyEventMask);
}

}  // namespace
}  // namespace system_call
}  // namespace asylo
