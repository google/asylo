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

#include "asylo/platform/host_call/type_conversions/generated_types_functions.h"

#include <gtest/gtest.h>
#include "asylo/test/util/finite_domain_fuzz.h"

namespace asylo {
namespace host_call {
namespace {

using ::testing::Eq;

// These tests only validate the behavior and correctness of the generated types
// conversion functions. It does not test the internal implementation of the
// types conversions generator itself.

// Arbitrarily chosen number of iterations.
constexpr int kIterationCount = 6000;

class GeneratedTypesFunctionsTest : public ::testing::Test {
 public:
};

TEST_F(GeneratedTypesFunctionsTest, FileStatusFlagTest) {
  std::vector<int> from_bits = {
      kLinux_O_RDONLY, kLinux_O_WRONLY, kLinux_O_RDWR,  kLinux_O_CREAT,
      kLinux_O_APPEND, kLinux_O_EXCL,   kLinux_O_TRUNC, kLinux_O_NONBLOCK,
      kLinux_O_DIRECT, kLinux_O_CLOEXEC};
  std::vector<int> to_bits = {O_RDONLY, O_WRONLY, O_RDWR,  O_CREAT,
                              O_APPEND, O_EXCL,   O_TRUNC, O_NONBLOCK,
                              O_DIRECT, O_CLOEXEC};

  auto from_matcher = IsFiniteRestrictionOf<int, int>(FromkLinuxFileStatusFlag);
  EXPECT_THAT(
      FuzzBitsetTranslationFunction(from_bits, to_bits, kIterationCount),
      from_matcher);
  auto to_matcher = IsFiniteRestrictionOf<int, int>(TokLinuxFileStatusFlag);
  EXPECT_THAT(
      FuzzBitsetTranslationFunction(to_bits, from_bits, kIterationCount),
      to_matcher);
}

TEST_F(GeneratedTypesFunctionsTest, FcntlCommandTest) {
  std::vector<int> from_consts = {kLinux_F_GETFD,      kLinux_F_SETFD,
                                  kLinux_F_GETFL,      kLinux_F_SETFL,
                                  kLinux_F_GETPIPE_SZ, kLinux_F_SETPIPE_SZ};
  std::vector<int> to_consts = {F_GETFD, F_SETFD,      F_GETFL,
                                F_SETFL, F_GETPIPE_SZ, F_SETPIPE_SZ};
  auto from_matcher = IsFiniteRestrictionOf<int, int>(FromkLinuxFcntlCommand);
  EXPECT_THAT(FuzzFiniteFunctionWithFallback(from_consts, to_consts, -1,
                                             kIterationCount),
              from_matcher);
  auto to_matcher = IsFiniteRestrictionOf<int, int>(TokLinuxFcntlCommand);
  EXPECT_THAT(FuzzFiniteFunctionWithFallback(to_consts, from_consts, -1,
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
    EXPECT_THAT(TokLinuxAfFamily(to_bits[i]), Eq(from_bits[i]));
    EXPECT_THAT(FromkLinuxAfFamily(from_bits[i]), Eq(to_bits[i]));
  }
}

TEST_F(GeneratedTypesFunctionsTest, FDFlagTest) {
  std::vector<int> from_bits = {kLinux_FD_CLOEXEC};
  std::vector<int> to_bits = {FD_CLOEXEC};

  auto from_matcher = IsFiniteRestrictionOf<int, int>(FromkLinuxFDFlag);
  EXPECT_THAT(
      FuzzBitsetTranslationFunction(from_bits, to_bits, kIterationCount),
      from_matcher);
  auto to_matcher = IsFiniteRestrictionOf<int, int>(TokLinuxFDFlag);
  EXPECT_THAT(
      FuzzBitsetTranslationFunction(to_bits, from_bits, kIterationCount),
      to_matcher);
}

}  // namespace
}  // namespace host_call
}  // namespace asylo
