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
#include <signal.h>
#include <sys/un.h>
#include <sys/utsname.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using ::testing::Eq;
using ::testing::Gt;
using ::testing::StrEq;

namespace asylo {
namespace system_call {
namespace {

TEST(ManualTypesFunctionsTest, LinuxErrnoTest) {
  EXPECT_EQ(FromkLinuxErrno(kLinux_E2BIG), E2BIG);
  EXPECT_EQ(FromkLinuxErrno(0x12344321), 0x1234C321);
}

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
  socklen_t sock_len = sizeof(sa_family_t) + truncated_path.length() + 1;
  FromkLinuxSockAddr(reinterpret_cast<klinux_sockaddr *>(&klinux_sock_un),
                     sizeof(klinux_sock_un),
                     reinterpret_cast<sockaddr *>(&sock), &sock_len, nullptr);
  auto sock_un = reinterpret_cast<sockaddr_un *>(&sock);
  EXPECT_THAT(sock_un->sun_family, Eq(AF_UNIX));
  EXPECT_THAT(sock_un->sun_path, StrEq(truncated_path));
}

TEST(ManualTypesFunctionsTest, FromkLinuxFdSetTest) {
  klinux_fd_set kfs = {};
  KLINUX_FD_ZERO(&kfs);
  for (int fd = 0; fd < KLINUX_FD_SETSIZE; ++fd) {
    if (fd % 2) {
      KLINUX_FD_SET(fd, &kfs);
    }
  }

  fd_set fs = {};
  FD_ZERO(&fs);
  FromkLinuxFdSet(&kfs, &fs);
  for (int fd = 0; fd < std::min(KLINUX_FD_SETSIZE, FD_SETSIZE); ++fd) {
    if (fd % 2) {
      EXPECT_THAT(FD_ISSET(fd, &fs), Gt(0));
    } else {
      EXPECT_THAT(FD_ISSET(fd, &fs), Eq(0));
    }
  }
}

TEST(ManualTypesFunctionsTest, TokLinuxFdSetTest) {
  fd_set fs = {};
  FD_ZERO(&fs);
  for (int fd = 0; fd < FD_SETSIZE; ++fd) {
    if (fd % 2) {
      FD_SET(fd, &fs);
    }
  }

  klinux_fd_set kfs = {};
  KLINUX_FD_ZERO(&kfs);
  TokLinuxFdSet(&fs, &kfs);
  for (int fd = 0; fd < std::min(KLINUX_FD_SETSIZE, FD_SETSIZE); ++fd) {
    if (fd % 2) {
      EXPECT_THAT(KLINUX_FD_ISSET(fd, &kfs), Gt(0));
    } else {
      EXPECT_THAT(KLINUX_FD_ISSET(fd, &kfs), Eq(0));
    }
  }
}

TEST(ManualTypesFunctionsTest, SignalNumberTest) {
#if defined(SIGRTMIN)
  int sig = SIGRTMIN + 2;
  int klinux_sig = TokLinuxSignalNumber(sig);
  EXPECT_THAT(klinux_sig, Eq(kLinux_SIGRTMIN + 2));

  sig = FromkLinuxSignalNumber(klinux_sig);
  EXPECT_THAT(sig, Eq(SIGRTMIN + 2));
#endif

  EXPECT_THAT(TokLinuxSignalNumber(SIGABRT), Eq(kLinux_SIGABRT));
  EXPECT_THAT(FromkLinuxSignalNumber(kLinux_SIGABRT), Eq(SIGABRT));

  EXPECT_THAT(TokLinuxSignalNumber(SIGILL), Eq(kLinux_SIGILL));
  EXPECT_THAT(FromkLinuxSignalNumber(kLinux_SIGILL), Eq(SIGILL));

  EXPECT_THAT(TokLinuxSignalNumber(SIGABRT), Eq(kLinux_SIGABRT));
  EXPECT_THAT(FromkLinuxSignalNumber(kLinux_SIGABRT), Eq(SIGABRT));

  EXPECT_THAT(TokLinuxSignalNumber(SIGKILL), Eq(kLinux_SIGKILL));
  EXPECT_THAT(FromkLinuxSignalNumber(kLinux_SIGKILL), Eq(SIGKILL));

  EXPECT_THAT(TokLinuxSignalNumber(SIGSEGV), Eq(kLinux_SIGSEGV));
  EXPECT_THAT(FromkLinuxSignalNumber(kLinux_SIGSEGV), Eq(SIGSEGV));

  EXPECT_THAT(TokLinuxSignalNumber(SIGTERM), Eq(kLinux_SIGTERM));
  EXPECT_THAT(FromkLinuxSignalNumber(kLinux_SIGTERM), Eq(SIGTERM));

  EXPECT_THAT(TokLinuxSignalNumber(SIGPROF), Eq(kLinux_SIGPROF));
  EXPECT_THAT(FromkLinuxSignalNumber(kLinux_SIGPROF), Eq(SIGPROF));

  EXPECT_THAT(TokLinuxSignalNumber(SIGCHLD), Eq(kLinux_SIGCHLD));
  EXPECT_THAT(FromkLinuxSignalNumber(kLinux_SIGCHLD), Eq(SIGCHLD));

  EXPECT_THAT(TokLinuxSignalNumber(SIGINT), Eq(kLinux_SIGINT));
  EXPECT_THAT(FromkLinuxSignalNumber(kLinux_SIGINT), Eq(SIGINT));
}

TEST(ManualTypesFunctionsTest, ToItimervalTest) {
  EXPECT_THAT(sizeof(struct itimerval), Eq(sizeof(struct klinux_itimerval)));

  struct itimerval tval {};
  struct klinux_itimerval k_tval {};
  tval.it_interval.tv_usec = 1;
  tval.it_interval.tv_sec = 2;
  tval.it_value.tv_usec = 3;
  tval.it_value.tv_sec = 4;

  EXPECT_THAT(TokLinuxItimerval(&tval, &k_tval), Eq(true));
  EXPECT_THAT(k_tval.klinux_it_interval.kLinux_tv_usec, Eq(1));
  EXPECT_THAT(k_tval.klinux_it_interval.kLinux_tv_sec, Eq(2));
  EXPECT_THAT(k_tval.klinux_it_value.kLinux_tv_usec, Eq(3));
  EXPECT_THAT(k_tval.klinux_it_value.kLinux_tv_sec, Eq(4));
}

TEST(ManualTypesFunctionsTest, FromItimervalTest) {
  struct itimerval tval {};
  struct klinux_itimerval k_tval {};
  k_tval.klinux_it_interval.kLinux_tv_usec = 1;
  k_tval.klinux_it_interval.kLinux_tv_sec = 2;
  k_tval.klinux_it_value.kLinux_tv_usec = 3;
  k_tval.klinux_it_value.kLinux_tv_sec = 4;

  EXPECT_THAT(FromkLinuxItimerval(&k_tval, &tval), Eq(true));
  EXPECT_THAT(tval.it_interval.tv_usec, Eq(1));
  EXPECT_THAT(tval.it_interval.tv_sec, Eq(2));
  EXPECT_THAT(tval.it_value.tv_usec, Eq(3));
  EXPECT_THAT(tval.it_value.tv_sec, Eq(4));
}

TEST(ManualTypesFunctionsTest, ToPollFdTest) {
  EXPECT_THAT(sizeof(struct pollfd), Eq(sizeof(struct klinux_pollfd)));

  struct pollfd poll_fd {};
  poll_fd.fd = 1;
  poll_fd.events = POLLIN;
  poll_fd.revents = POLLOUT;
  struct klinux_pollfd klinux_poll_fd {};

  EXPECT_THAT(TokLinuxPollfd(&poll_fd, &klinux_poll_fd), Eq(true));
  EXPECT_THAT(klinux_poll_fd.klinux_fd, Eq(poll_fd.fd));
  EXPECT_THAT(klinux_poll_fd.klinux_events, Eq(kLinux_POLLIN));
  EXPECT_THAT(klinux_poll_fd.klinux_revents, Eq(kLinux_POLLOUT));
}

TEST(ManualTypesFunctionsTest, FromPollFdTest) {
  struct klinux_pollfd klinux_poll_fd {};
  klinux_poll_fd.klinux_fd = 1;
  klinux_poll_fd.klinux_events = kLinux_POLLIN;
  klinux_poll_fd.klinux_revents = kLinux_POLLOUT;
  struct pollfd poll_fd {};

  EXPECT_THAT(FromkLinuxPollfd(&klinux_poll_fd, &poll_fd), Eq(true));
  EXPECT_THAT(poll_fd.fd, Eq(klinux_poll_fd.klinux_fd));
  EXPECT_THAT(poll_fd.events, Eq(POLLIN));
  EXPECT_THAT(poll_fd.revents, Eq(POLLOUT));
}

TEST(ManualTypesFunctionsTest, UtsnameTest) {
  const char *sysname = "abc";
  const char *nodename = "def";
  const char *release = "ghi";
  const char *version = "jkl";
  const char *machine = "mno";
  struct utsname uname {};
  struct klinux_utsname klinux_uname {};

  strncpy(klinux_uname.sysname, sysname, sizeof(klinux_uname.sysname));
  strncpy(klinux_uname.nodename, nodename, sizeof(klinux_uname.sysname));
  strncpy(klinux_uname.release, release, sizeof(klinux_uname.sysname));
  strncpy(klinux_uname.version, version, sizeof(klinux_uname.sysname));
  strncpy(klinux_uname.machine, machine, sizeof(klinux_uname.sysname));

  EXPECT_THAT(FromkLinuxUtsName(&klinux_uname, &uname), Eq(true));
  EXPECT_THAT(uname.sysname, StrEq(sysname));
  EXPECT_THAT(uname.nodename, StrEq(nodename));
  EXPECT_THAT(uname.release, StrEq(release));
  EXPECT_THAT(uname.version, StrEq(version));
  EXPECT_THAT(uname.machine, StrEq(machine));
}

TEST(ManualTypesFunctionsTest, SysLogPriorityTest) {
  std::vector<int> high_from_consts = {kLinux_LOG_USER,   kLinux_LOG_LOCAL0,
                                       kLinux_LOG_LOCAL1, kLinux_LOG_LOCAL2,
                                       kLinux_LOG_LOCAL3, kLinux_LOG_LOCAL4,
                                       kLinux_LOG_LOCAL5, kLinux_LOG_LOCAL6,
                                       kLinux_LOG_LOCAL7, 0};
  std::vector<int> low_from_consts = {
      kLinux_LOG_EMERG,   kLinux_LOG_ALERT,  kLinux_LOG_CRIT, kLinux_LOG_ERR,
      kLinux_LOG_WARNING, kLinux_LOG_NOTICE, kLinux_LOG_INFO, kLinux_LOG_DEBUG};
  std::vector<int> high_to_consts = {
      LOG_USER,   LOG_LOCAL0, LOG_LOCAL1, LOG_LOCAL2, LOG_LOCAL3,
      LOG_LOCAL4, LOG_LOCAL5, LOG_LOCAL6, LOG_LOCAL7, 0};
  std::vector<int> low_to_consts = {LOG_EMERG, LOG_ALERT,   LOG_CRIT,
                                    LOG_ERR,   LOG_WARNING, LOG_NOTICE,
                                    LOG_INFO,  LOG_DEBUG};

  for (int i = 0; i < high_from_consts.size(); i++) {
    for (int j = 0; j < low_from_consts.size(); j++) {
      int from = high_from_consts[i] | low_from_consts[j];
      int to = high_to_consts[i] | low_to_consts[j];
      EXPECT_EQ(TokLinuxSyslogPriority(to), from);
    }
  }
}

TEST(ManualTypesFunctionsTest, TokLinuxSockAddrIn6Test) {
  struct sockaddr_in6 enclave_in6 {};
  enclave_in6.sin6_addr = in6addr_loopback;
  enclave_in6.sin6_family = AF_INET6;
  enclave_in6.sin6_flowinfo = 1;
  enclave_in6.sin6_port = 1234;
  enclave_in6.sin6_scope_id = 10;

  struct klinux_sockaddr_in6 host_in6 {};
  socklen_t host_in6_len = sizeof(host_in6);
  EXPECT_THAT(
      TokLinuxSockAddr(reinterpret_cast<struct sockaddr *>(&enclave_in6),
                       sizeof(enclave_in6),
                       reinterpret_cast<struct klinux_sockaddr *>(&host_in6),
                       &host_in6_len, nullptr),
      Eq(true));
  EXPECT_THAT(host_in6.klinux_sin6_family, Eq(kLinux_AF_INET6));
  EXPECT_THAT(host_in6.klinux_sin6_flowinfo, Eq(1));
  EXPECT_THAT(host_in6.klinux_sin6_port, Eq(1234));
  EXPECT_THAT(host_in6.klinux_sin6_scope_id, Eq(10));

  // Verify loopback address to be {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1}
  for (int i = 0; i < 15; i++) {
    EXPECT_THAT(host_in6.klinux_sin6_addr.klinux_s6_addr[i], Eq(0));
  }
  EXPECT_THAT(host_in6.klinux_sin6_addr.klinux_s6_addr[15], Eq(1));
}

}  // namespace
}  // namespace system_call
}  // namespace asylo
