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

}  // namespace
}  // namespace asylo
