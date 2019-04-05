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
#include <gmock/gmock.h>
#include <gtest/gtest.h>

using ::testing::Eq;

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
    EXPECT_THAT(TokLinuxSocketType(to_bits[i]), Eq(from_bits[i]));
    EXPECT_THAT(FromkLinuxSocketType(from_bits[i]), Eq(to_bits[i]));

    int from = kLinux_SOCK_CLOEXEC | kLinux_SOCK_NONBLOCK | from_bits[i];
    int to = SOCK_CLOEXEC | SOCK_NONBLOCK | to_bits[i];

    EXPECT_THAT(TokLinuxSocketType(to), Eq(from));
    EXPECT_THAT(FromkLinuxSocketType(from), Eq(to));

    from = kLinux_SOCK_CLOEXEC | from_bits[i];
    to = SOCK_CLOEXEC | to_bits[i];
    EXPECT_THAT(TokLinuxSocketType(to), Eq(from));
    EXPECT_THAT(FromkLinuxSocketType(from), Eq(to));

    from = kLinux_SOCK_NONBLOCK | from_bits[i];
    to = SOCK_NONBLOCK | to_bits[i];
    EXPECT_THAT(TokLinuxSocketType(to), Eq(from));
    EXPECT_THAT(FromkLinuxSocketType(from), Eq(to));
  }
}

}  // namespace
}  // namespace system_call
}  // namespace asylo
