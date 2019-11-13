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

#include <netinet/in.h>
#include <signal.h>
#include <sys/un.h>
#include <sys/utsname.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/platform/system_call/type_conversions/manual_types_functions.h"

using ::testing::Eq;
using ::testing::Gt;

namespace asylo {
namespace system_call {
namespace {

// Since klinux_fd_set is expected to be a drop-in replacement for fd_set from a
// native Linux environment, this test checks if klinux_fd_set can be
// interchangeably used with the native Linux macros - FD_ZERO, FD_SET, FD_CLR
// and FD_ISSET.
TEST(ManualTypesFunctionsTest, KlinuxFdSetStructTest) {
  klinux_fd_set kfs = {};
  FD_ZERO(&kfs);
  for (uint64_t klinux_fds_bit : kfs.fds_bits) {
    EXPECT_THAT(klinux_fds_bit, Eq(0));
  }

  int fd = 21;
  EXPECT_THAT(FD_ISSET(fd, &kfs), Eq(0));
  FD_SET(fd, &kfs);
  EXPECT_THAT(FD_ISSET(fd, &kfs), Gt(0));
  FD_CLR(fd, &kfs);
  EXPECT_THAT(FD_ISSET(fd, &kfs), Eq(0));
  for (uint64_t klinux_fds_bit : kfs.fds_bits) {
    EXPECT_THAT(klinux_fds_bit, Eq(0));
  }
}

TEST(ManualTypesFunctionsTest, KlinuxFdSetMacroTest) {
  klinux_fd_set kfs = {};
  KLINUX_FD_ZERO(&kfs);
  for (uint64_t klinux_fds_bit : kfs.fds_bits) {
    EXPECT_THAT(klinux_fds_bit, Eq(0));
  }

  int fd = 21;
  EXPECT_THAT(KLINUX_FD_ISSET(fd, &kfs), Eq(0));
  KLINUX_FD_SET(fd, &kfs);
  EXPECT_THAT(KLINUX_FD_ISSET(fd, &kfs), Gt(0));
  KLINUX_FD_CLR(fd, &kfs);
  EXPECT_THAT(KLINUX_FD_ISSET(fd, &kfs), Eq(0));
  for (uint64_t klinux_fds_bit : kfs.fds_bits) {
    EXPECT_THAT(klinux_fds_bit, Eq(0));
  }
}

TEST(ManualTypesFunctionsTest, EpollEventSizeTest) {
  EXPECT_THAT(sizeof(struct epoll_event),
              Eq(sizeof(struct klinux_epoll_event)));
}

TEST(ManualTypesFunctionsTest, RusageSizeTest) {
  EXPECT_THAT(sizeof(struct klinux_rusage), Eq(sizeof(struct rusage)));
}

TEST(ManualTypesFunctionsTest, UtsnameLengthTest) {
  EXPECT_THAT(sizeof(struct klinux_utsname), Eq(sizeof(struct utsname)));
}

TEST(ManualTypesFunctionsTest, SigInfoSizeTest) {
  siginfo_t sig{};
  klinux_siginfo_t k_sig{};
  EXPECT_THAT(sizeof(k_sig), Eq(sizeof(sig)));
}

}  // namespace
}  // namespace system_call
}  // namespace asylo
