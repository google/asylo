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

#include "asylo/platform/common/bridge_functions.h"

#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <syslog.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/platform/common/bridge_types.h"
#include "asylo/test/util/finite_domain_fuzz.h"

namespace asylo {
namespace {

// Arbitrarily chosen number of iterations.
const int ITER_BOUND = 6000;

class BridgeTest : public ::testing::Test {
 public:
};

using intvec = std::vector<int>;

TEST_F(BridgeTest, BridgeFLockOperationTest) {
  intvec from_bits = {BRIDGE_LOCK_SH, BRIDGE_LOCK_EX, BRIDGE_LOCK_NB,
                      BRIDGE_LOCK_UN};
  intvec to_bits = {LOCK_SH, LOCK_EX, LOCK_NB, LOCK_UN};
  EXPECT_EQ(from_bits.size(), to_bits.size());
  auto from_matcher = IsFiniteRestrictionOf<int, int>(FromBridgeFLockOperation);
  EXPECT_THAT(FuzzBitsetTranslationFunction(from_bits, to_bits, ITER_BOUND),
              from_matcher);
  auto to_matcher = IsFiniteRestrictionOf<int, int>(ToBridgeFLockOperation);
  EXPECT_THAT(FuzzBitsetTranslationFunction(to_bits, from_bits, ITER_BOUND),
              to_matcher);
}

TEST_F(BridgeTest, BridgeSysconfConstantsTest) {
  std::vector<enum SysconfConstants> from_consts = {BRIDGE_SC_NPROCESSORS_CONF,
                                                    BRIDGE_SC_NPROCESSORS_ONLN,
                                                    BRIDGE_SC_UNKNOWN};
  intvec to_consts = {_SC_NPROCESSORS_CONF, _SC_NPROCESSORS_ONLN, -1};
  auto to_matcher = IsFiniteRestrictionOf<int, enum SysconfConstants>(
      ToBridgeSysconfConstants);
  EXPECT_THAT(FuzzFiniteFunctionWithFallback(to_consts, from_consts,
                                             BRIDGE_SC_UNKNOWN, ITER_BOUND),
              to_matcher);
  auto from_matcher = IsFiniteRestrictionOf<enum SysconfConstants, int>(
      FromBridgeSysconfConstants);
  EXPECT_THAT(zip(from_consts, to_consts), from_matcher);
}

TEST_F(BridgeTest, BridgeTimerTypeTest) {
  std::vector<enum TimerType> from_consts = {
      BRIDGE_ITIMER_REAL,
      BRIDGE_ITIMER_VIRTUAL,
      BRIDGE_ITIMER_PROF,
      BRIDGE_ITIMER_UNKNOWN,
  };
  intvec to_consts = {ITIMER_REAL, ITIMER_VIRTUAL, ITIMER_PROF, -1};
  auto from_matcher =
      IsFiniteRestrictionOf<enum TimerType, int>(FromBridgeTimerType);
  EXPECT_THAT(zip(from_consts, to_consts), from_matcher);
  auto to_matcher =
      IsFiniteRestrictionOf<int, enum TimerType>(ToBridgeTimerType);
  EXPECT_THAT(FuzzFiniteFunctionWithFallback(to_consts, from_consts,
                                             BRIDGE_ITIMER_UNKNOWN, ITER_BOUND),
              to_matcher);
}

TEST_F(BridgeTest, BridgeWaitOptionsTest) {
  intvec from_consts = {BRIDGE_WNOHANG};
  intvec to_consts = {WNOHANG};
  auto from_matcher = IsFiniteRestrictionOf<int, int>(FromBridgeWaitOptions);
  EXPECT_THAT(FuzzBitsetTranslationFunction(from_consts, to_consts, ITER_BOUND),
              from_matcher);
  auto to_matcher = IsFiniteRestrictionOf<int, int>(ToBridgeWaitOptions);
  EXPECT_THAT(FuzzBitsetTranslationFunction(to_consts, from_consts, ITER_BOUND),
              to_matcher);
}

TEST_F(BridgeTest, BridgeRUsageTargetTest) {
  std::vector<enum RUsageTarget> from_consts = {
      BRIDGE_RUSAGE_SELF,
      BRIDGE_RUSAGE_CHILDREN,
  };
  intvec to_consts = {RUSAGE_SELF, RUSAGE_CHILDREN};
  auto from_matcher =
      IsFiniteRestrictionOf<enum RUsageTarget, int>(FromBridgeRUsageTarget);
  EXPECT_THAT(zip(from_consts, to_consts), from_matcher);
  auto to_matcher =
      IsFiniteRestrictionOf<int, enum RUsageTarget>(ToBridgeRUsageTarget);
  EXPECT_THAT(FuzzFiniteFunctionWithFallback(to_consts, from_consts,
                                             BRIDGE_RUSAGE_UNKNOWN, ITER_BOUND),
              to_matcher);
}

TEST_F(BridgeTest, BridgeSigMaskActionTest) {
  intvec from_consts = {BRIDGE_SIG_BLOCK, BRIDGE_SIG_UNBLOCK,
                        BRIDGE_SIG_SETMASK};
  intvec to_consts = {SIG_BLOCK, SIG_UNBLOCK, SIG_SETMASK};
  auto from_matcher = IsFiniteRestrictionOf<int, int>(FromBridgeSigMaskAction);
  EXPECT_THAT(
      FuzzFiniteFunctionWithFallback(from_consts, to_consts, -1, ITER_BOUND),
      from_matcher);
  auto to_matcher = IsFiniteRestrictionOf<int, int>(ToBridgeSigMaskAction);
  EXPECT_THAT(
      FuzzFiniteFunctionWithFallback(to_consts, from_consts, -1, ITER_BOUND),
      to_matcher);
}

TEST_F(BridgeTest, BridgeSignalCodeTest) {
  intvec from_consts = {BRIDGE_SI_USER, BRIDGE_SI_QUEUE, BRIDGE_SI_TIMER,
                        BRIDGE_SI_ASYNCIO, BRIDGE_SI_MESGQ};
  intvec to_consts = {SI_USER, SI_QUEUE, SI_TIMER, SI_ASYNCIO, SI_MESGQ};
  auto from_matcher = IsFiniteRestrictionOf<int, int>(FromBridgeSignalCode);
  EXPECT_THAT(
      FuzzFiniteFunctionWithFallback(from_consts, to_consts, -1, ITER_BOUND),
      from_matcher);
  auto to_matcher = IsFiniteRestrictionOf<int, int>(ToBridgeSignalCode);
  EXPECT_THAT(
      FuzzFiniteFunctionWithFallback(to_consts, from_consts, -1, ITER_BOUND),
      to_matcher);
}

TEST_F(BridgeTest, BridgeSigInfoTest) {
}

TEST_F(BridgeTest, BridgeAddressInfoFlagsTest) {
  intvec from_bits = {BRIDGE_AI_CANONNAME,
                      BRIDGE_AI_NUMERICHOST,
                      BRIDGE_AI_V4MAPPED,
                      BRIDGE_AI_ADDRCONFIG,
                      BRIDGE_AI_ALL,
                      BRIDGE_AI_PASSIVE,
                      BRIDGE_AI_NUMERICSERV,
                      BRIDGE_AI_IDN,
                      BRIDGE_AI_CANONIDN,
                      BRIDGE_AI_IDN_ALLOW_UNASSIGNED,
                      BRIDGE_AI_IDN_USE_STD3_ASCII_RULES};
  intvec to_bits = {AI_CANONNAME,
                    AI_NUMERICHOST,
                    AI_V4MAPPED,
                    AI_ADDRCONFIG,
                    AI_ALL,
                    AI_PASSIVE,
                    AI_NUMERICSERV,
                    AI_IDN,
                    AI_CANONIDN,
                    AI_IDN_ALLOW_UNASSIGNED,
                    AI_IDN_USE_STD3_ASCII_RULES};
  auto from_matcher =
      IsFiniteRestrictionOf<int, int>(FromBridgeAddressInfoFlags);
  EXPECT_THAT(FuzzBitsetTranslationFunction(from_bits, to_bits, ITER_BOUND),
              from_matcher);
  auto to_matcher = IsFiniteRestrictionOf<int, int>(ToBridgeAddressInfoFlags);
  EXPECT_THAT(FuzzBitsetTranslationFunction(to_bits, from_bits, ITER_BOUND),
              to_matcher);
}

TEST_F(BridgeTest, BridgeSysLogOptionTest) {
  intvec from_bits = {BRIDGE_LOG_PID,    BRIDGE_LOG_CONS,   BRIDGE_LOG_ODELAY,
                      BRIDGE_LOG_NDELAY, BRIDGE_LOG_NOWAIT, BRIDGE_LOG_PERROR};
  intvec to_bits = {LOG_PID,    LOG_CONS,   LOG_ODELAY,
                    LOG_NDELAY, LOG_NOWAIT, LOG_PERROR};
  auto from_matcher = IsFiniteRestrictionOf<int, int>(FromBridgeSysLogOption);
  EXPECT_THAT(FuzzBitsetTranslationFunction(from_bits, to_bits, ITER_BOUND),
              from_matcher);
  auto to_matcher = IsFiniteRestrictionOf<int, int>(ToBridgeSysLogOption);
  EXPECT_THAT(FuzzBitsetTranslationFunction(to_bits, from_bits, ITER_BOUND),
              to_matcher);
}

TEST_F(BridgeTest, BridgeSysLogFacilityTest) {
  intvec from_consts = {BRIDGE_LOG_USER,   BRIDGE_LOG_LOCAL0,
                        BRIDGE_LOG_LOCAL1, BRIDGE_LOG_LOCAL2,
                        BRIDGE_LOG_LOCAL3, BRIDGE_LOG_LOCAL4,
                        BRIDGE_LOG_LOCAL5, BRIDGE_LOG_LOCAL6,
                        BRIDGE_LOG_LOCAL7, 0};
  intvec to_consts = {LOG_USER,   LOG_LOCAL0, LOG_LOCAL1, LOG_LOCAL2,
                      LOG_LOCAL3, LOG_LOCAL4, LOG_LOCAL5, LOG_LOCAL6,
                      LOG_LOCAL7, 0};
  auto from_matcher = IsFiniteRestrictionOf<int, int>(FromBridgeSysLogFacility);
  EXPECT_THAT(
      FuzzFiniteFunctionWithFallback(from_consts, to_consts, 0, ITER_BOUND),
      from_matcher);
  auto to_matcher = IsFiniteRestrictionOf<int, int>(ToBridgeSysLogFacility);
  EXPECT_THAT(
      FuzzFiniteFunctionWithFallback(to_consts, from_consts, 0, ITER_BOUND),
      to_matcher);
}

TEST_F(BridgeTest, BridgeSysLogPriorityTest) {
  intvec high_from_consts = {BRIDGE_LOG_USER,   BRIDGE_LOG_LOCAL0,
                             BRIDGE_LOG_LOCAL1, BRIDGE_LOG_LOCAL2,
                             BRIDGE_LOG_LOCAL3, BRIDGE_LOG_LOCAL4,
                             BRIDGE_LOG_LOCAL5, BRIDGE_LOG_LOCAL6,
                             BRIDGE_LOG_LOCAL7, 0};
  intvec low_from_consts = {
      BRIDGE_LOG_EMERG,   BRIDGE_LOG_ALERT,  BRIDGE_LOG_CRIT, BRIDGE_LOG_ERR,
      BRIDGE_LOG_WARNING, BRIDGE_LOG_NOTICE, BRIDGE_LOG_INFO, BRIDGE_LOG_DEBUG};
  intvec high_to_consts = {LOG_USER,   LOG_LOCAL0, LOG_LOCAL1, LOG_LOCAL2,
                           LOG_LOCAL3, LOG_LOCAL4, LOG_LOCAL5, LOG_LOCAL6,
                           LOG_LOCAL7, 0};
  intvec low_to_consts = {LOG_EMERG,   LOG_ALERT,  LOG_CRIT, LOG_ERR,
                          LOG_WARNING, LOG_NOTICE, LOG_INFO, LOG_DEBUG};

  for (int i = 0; i < high_from_consts.size(); i++) {
    for (int j = 0; j < low_from_consts.size(); j++) {
      int from = high_from_consts[i] | low_from_consts[j];
      int to = high_to_consts[i] | low_to_consts[j];
      EXPECT_EQ(FromBridgeSysLogPriority(from), to);
      EXPECT_EQ(ToBridgeSysLogPriority(to), from);
    }
  }
}

TEST_F(BridgeTest, BridgeFileFlagsTest) {
  intvec from_bits = {RDONLY, WRONLY, RDWR,  CREAT,
                      APPEND, EXCL,   TRUNC, NONBLOCK};
  intvec to_bits = {O_RDONLY, O_WRONLY, O_RDWR,  O_CREAT,
                    O_APPEND, O_EXCL,   O_TRUNC, O_NONBLOCK};
  auto from_matcher = IsFiniteRestrictionOf<int, int>(FromBridgeFileFlags);
  EXPECT_THAT(FuzzBitsetTranslationFunction(from_bits, to_bits, ITER_BOUND),
              from_matcher);
  auto to_matcher = IsFiniteRestrictionOf<int, int>(ToBridgeFileFlags);
  EXPECT_THAT(FuzzBitsetTranslationFunction(to_bits, from_bits, ITER_BOUND),
              to_matcher);
}

TEST_F(BridgeTest, BridgeFDFlagsTest) {
  intvec from_consts = {CLOEXEC};
  intvec to_consts = {FD_CLOEXEC};
  auto from_matcher = IsFiniteRestrictionOf<int, int>(FromBridgeFDFlags);
  EXPECT_THAT(FuzzBitsetTranslationFunction(from_consts, to_consts, ITER_BOUND),
              from_matcher);
  auto to_matcher = IsFiniteRestrictionOf<int, int>(ToBridgeFDFlags);
  EXPECT_THAT(FuzzBitsetTranslationFunction(to_consts, from_consts, ITER_BOUND),
              to_matcher);
}

TEST_F(BridgeTest, BridgeOptionNameTest) {
  intvec levels = {IPPROTO_TCP, IPPROTO_IPV6, SOL_SOCKET, -1};
  std::vector<intvec> from_consts = {
      {BRIDGE_TCP_NODELAY, BRIDGE_TCP_KEEPIDLE, BRIDGE_TCP_KEEPINTVL,
       BRIDGE_TCP_KEEPCNT},
      {BRIDGE_IPV6_V6ONLY},
      {BRIDGE_SO_DEBUG, BRIDGE_SO_REUSEADDR, BRIDGE_SO_TYPE, BRIDGE_SO_ERROR,
       BRIDGE_SO_DONTROUTE, BRIDGE_SO_BROADCAST, BRIDGE_SO_SNDBUF,
       BRIDGE_SO_RCVBUF, BRIDGE_SO_SNDTIMEO, BRIDGE_SO_RCVTIMEO,
       BRIDGE_SO_SNDBUFFORCE, BRIDGE_SO_RCVBUFFORCE, BRIDGE_SO_KEEPALIVE,
       BRIDGE_SO_OOBINLINE, BRIDGE_SO_NO_CHECK, BRIDGE_SO_PRIORITY,
       BRIDGE_SO_LINGER, BRIDGE_SO_BSDCOMPAT, BRIDGE_SO_REUSEPORT},
      {-1}};
  std::vector<intvec> to_consts = {
      {TCP_NODELAY, TCP_KEEPIDLE, TCP_KEEPINTVL, TCP_KEEPCNT},
      {IPV6_V6ONLY},
      {SO_DEBUG, SO_REUSEADDR, SO_TYPE, SO_ERROR, SO_DONTROUTE, SO_BROADCAST,
       SO_SNDBUF, SO_RCVBUF, SO_SNDTIMEO, SO_RCVTIMEO, SO_SNDBUFFORCE,
       SO_RCVBUFFORCE, SO_KEEPALIVE, SO_OOBINLINE, SO_NO_CHECK, SO_PRIORITY,
       SO_LINGER, SO_BSDCOMPAT, SO_REUSEPORT},
      {-1}};
  for (int i = 0; i < levels.size(); i++) {
    std::function<int(int)> from_close = [levels, i](int option) {
      return FromBridgeOptionName(levels[i], option);
    };
    std::function<int(int)> to_close = [levels, i](int option) {
      return ToBridgeOptionName(levels[i], option);
    };
    auto from_matcher = IsFiniteRestrictionOf<int, int>(from_close);
    EXPECT_THAT(FuzzFiniteFunctionWithFallback(from_consts[i], to_consts[i], -1,
                                               ITER_BOUND),
                from_matcher);
    auto to_matcher = IsFiniteRestrictionOf<int, int>(to_close);
    EXPECT_THAT(FuzzFiniteFunctionWithFallback(to_consts[i], from_consts[i], -1,
                                               ITER_BOUND),
                to_matcher);
  }
}

TEST_F(BridgeTest, BridgeAfFamilyTest) {
  std::vector<AfFamily> from_consts = {
      BRIDGE_AF_UNIX,   BRIDGE_AF_INET,      BRIDGE_AF_INET6,  BRIDGE_AF_UNSPEC,
      BRIDGE_AF_IPX,    BRIDGE_AF_NETLINK,   BRIDGE_AF_X25,    BRIDGE_AF_AX25,
      BRIDGE_AF_ATMPVC, BRIDGE_AF_APPLETALK, BRIDGE_AF_PACKET, BRIDGE_AF_ALG};
  intvec to_consts = {AF_UNIX,   AF_INET,      AF_INET6,  AF_UNSPEC,
                      AF_IPX,    AF_NETLINK,   AF_X25,    AF_AX25,
                      AF_ATMPVC, AF_APPLETALK, AF_PACKET, AF_ALG};
  intvec from_ints = {BRIDGE_AF_UNIX,      BRIDGE_AF_INET,   BRIDGE_AF_INET6,
                      BRIDGE_AF_UNSPEC,    BRIDGE_AF_IPX,    BRIDGE_AF_NETLINK,
                      BRIDGE_AF_X25,       BRIDGE_AF_AX25,   BRIDGE_AF_ATMPVC,
                      BRIDGE_AF_APPLETALK, BRIDGE_AF_PACKET, BRIDGE_AF_ALG};

  if (BRIDGE_AF_UNIX != BRIDGE_AF_LOCAL && AF_UNIX != AF_LOCAL) {
    from_consts.push_back(BRIDGE_AF_LOCAL);
    to_consts.push_back(AF_LOCAL);
    from_ints.push_back(BRIDGE_AF_LOCAL);
  }

  auto from_matcher = IsFiniteRestrictionOf<int, int>(FromBridgeAfFamily);
  EXPECT_THAT(zip(from_ints, to_consts), from_matcher);
  auto to_matcher = IsFiniteRestrictionOf<int, AfFamily>(ToBridgeAfFamily);
  EXPECT_THAT(FuzzFiniteFunctionWithFallback(to_consts, from_consts,
                                             BRIDGE_AF_UNSUPPORTED, ITER_BOUND),
              to_matcher);
}

}  // namespace

}  // namespace asylo
