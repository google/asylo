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

TEST_F(GeneratedTypesFunctionsTest, ErrorNumberTest) {
  std::vector<int> from_consts = {kLinux_E2BIG,
                                  kLinux_EACCES,
                                  kLinux_EADDRINUSE,
                                  kLinux_EADDRNOTAVAIL,
                                  kLinux_EADV,
                                  kLinux_EAFNOSUPPORT,
                                  kLinux_EAGAIN,
                                  kLinux_EALREADY,
                                  kLinux_EBADE,
                                  kLinux_EBADF,
                                  kLinux_EBADFD,
                                  kLinux_EBADMSG,
                                  kLinux_EBADR,
                                  kLinux_EBADRQC,
                                  kLinux_EBADSLT,
                                  kLinux_EBFONT,
                                  kLinux_EBUSY,
                                  kLinux_ECANCELED,
                                  kLinux_ECHILD,
                                  kLinux_ECHRNG,
                                  kLinux_ECOMM,
                                  kLinux_ECONNABORTED,
                                  kLinux_ECONNREFUSED,
                                  kLinux_ECONNRESET,
                                  kLinux_EDEADLOCK,
                                  kLinux_EDESTADDRREQ,
                                  kLinux_EDOM,
                                  kLinux_EDOTDOT,
                                  kLinux_EDQUOT,
                                  kLinux_EEXIST,
                                  kLinux_EFAULT,
                                  kLinux_EFBIG,
                                  kLinux_EHOSTDOWN,
                                  kLinux_EHOSTUNREACH,
                                  kLinux_EIDRM,
                                  kLinux_EILSEQ,
                                  kLinux_EINPROGRESS,
                                  kLinux_EINTR,
                                  kLinux_EINVAL,
                                  kLinux_EIO,
                                  kLinux_EISCONN,
                                  kLinux_EISDIR,
                                  kLinux_EL2HLT,
                                  kLinux_EL2NSYNC,
                                  kLinux_EL3HLT,
                                  kLinux_EL3RST,
                                  kLinux_ELIBACC,
                                  kLinux_ELIBBAD,
                                  kLinux_ELIBEXEC,
                                  kLinux_ELIBMAX,
                                  kLinux_ELIBSCN,
                                  kLinux_ELNRNG,
                                  kLinux_ELOOP,
                                  kLinux_EMFILE,
                                  kLinux_EMLINK,
                                  kLinux_EMSGSIZE,
                                  kLinux_EMULTIHOP,
                                  kLinux_ENAMETOOLONG,
                                  kLinux_ENETDOWN,
                                  kLinux_ENETRESET,
                                  kLinux_ENETUNREACH,
                                  kLinux_ENFILE,
                                  kLinux_ENOANO,
                                  kLinux_ENOBUFS,
                                  kLinux_ENOCSI,
                                  kLinux_ENODATA,
                                  kLinux_ENODEV,
                                  kLinux_ENOENT,
                                  kLinux_ENOEXEC,
                                  kLinux_ENOLCK,
                                  kLinux_ENOLINK,
                                  kLinux_ENOMEDIUM,
                                  kLinux_ENOMEM,
                                  kLinux_ENOMSG,
                                  kLinux_ENONET,
                                  kLinux_ENOPKG,
                                  kLinux_ENOPROTOOPT,
                                  kLinux_ENOSPC,
                                  kLinux_ENOSR,
                                  kLinux_ENOSTR,
                                  kLinux_ENOSYS,
                                  kLinux_ENOTBLK,
                                  kLinux_ENOTCONN,
                                  kLinux_ENOTDIR,
                                  kLinux_ENOTEMPTY,
                                  kLinux_ENOTRECOVERABLE,
                                  kLinux_ENOTSOCK,
                                  kLinux_ENOTTY,
                                  kLinux_ENOTUNIQ,
                                  kLinux_ENXIO,
                                  kLinux_EOPNOTSUPP,
                                  kLinux_EOVERFLOW,
                                  kLinux_EOWNERDEAD,
                                  kLinux_EPERM,
                                  kLinux_EPFNOSUPPORT,
                                  kLinux_EPIPE,
                                  kLinux_EPROTO,
                                  kLinux_EPROTONOSUPPORT,
                                  kLinux_EPROTOTYPE,
                                  kLinux_ERANGE,
                                  kLinux_EREMCHG,
                                  kLinux_EREMOTE,
                                  kLinux_EROFS,
                                  kLinux_ESHUTDOWN,
                                  kLinux_ESOCKTNOSUPPORT,
                                  kLinux_ESPIPE,
                                  kLinux_ESRCH,
                                  kLinux_ESRMNT,
                                  kLinux_ESTALE,
                                  kLinux_ESTRPIPE,
                                  kLinux_ETIME,
                                  kLinux_ETIMEDOUT,
                                  kLinux_ETOOMANYREFS,
                                  kLinux_ETXTBSY,
                                  kLinux_EUNATCH,
                                  kLinux_EUSERS,
                                  kLinux_EXDEV,
                                  kLinux_EXFULL};
  std::vector<int> to_consts = {E2BIG,
                                EACCES,
                                EADDRINUSE,
                                EADDRNOTAVAIL,
                                EADV,
                                EAFNOSUPPORT,
                                EAGAIN,
                                EALREADY,
                                EBADE,
                                EBADF,
                                EBADFD,
                                EBADMSG,
                                EBADR,
                                EBADRQC,
                                EBADSLT,
                                EBFONT,
                                EBUSY,
                                ECANCELED,
                                ECHILD,
                                ECHRNG,
                                ECOMM,
                                ECONNABORTED,
                                ECONNREFUSED,
                                ECONNRESET,
                                EDEADLOCK,
                                EDESTADDRREQ,
                                EDOM,
                                EDOTDOT,
                                EDQUOT,
                                EEXIST,
                                EFAULT,
                                EFBIG,
                                EHOSTDOWN,
                                EHOSTUNREACH,
                                EIDRM,
                                EILSEQ,
                                EINPROGRESS,
                                EINTR,
                                EINVAL,
                                EIO,
                                EISCONN,
                                EISDIR,
                                EL2HLT,
                                EL2NSYNC,
                                EL3HLT,
                                EL3RST,
                                ELIBACC,
                                ELIBBAD,
                                ELIBEXEC,
                                ELIBMAX,
                                ELIBSCN,
                                ELNRNG,
                                ELOOP,
                                EMFILE,
                                EMLINK,
                                EMSGSIZE,
                                EMULTIHOP,
                                ENAMETOOLONG,
                                ENETDOWN,
                                ENETRESET,
                                ENETUNREACH,
                                ENFILE,
                                ENOANO,
                                ENOBUFS,
                                ENOCSI,
                                ENODATA,
                                ENODEV,
                                ENOENT,
                                ENOEXEC,
                                ENOLCK,
                                ENOLINK,
                                ENOMEDIUM,
                                ENOMEM,
                                ENOMSG,
                                ENONET,
                                ENOPKG,
                                ENOPROTOOPT,
                                ENOSPC,
                                ENOSR,
                                ENOSTR,
                                ENOSYS,
                                ENOTBLK,
                                ENOTCONN,
                                ENOTDIR,
                                ENOTEMPTY,
                                ENOTRECOVERABLE,
                                ENOTSOCK,
                                ENOTTY,
                                ENOTUNIQ,
                                ENXIO,
                                EOPNOTSUPP,
                                EOVERFLOW,
                                EOWNERDEAD,
                                EPERM,
                                EPFNOSUPPORT,
                                EPIPE,
                                EPROTO,
                                EPROTONOSUPPORT,
                                EPROTOTYPE,
                                ERANGE,
                                EREMCHG,
                                EREMOTE,
                                EROFS,
                                ESHUTDOWN,
                                ESOCKTNOSUPPORT,
                                ESPIPE,
                                ESRCH,
                                ESRMNT,
                                ESTALE,
                                ESTRPIPE,
                                ETIME,
                                ETIMEDOUT,
                                ETOOMANYREFS,
                                ETXTBSY,
                                EUNATCH,
                                EUSERS,
                                EXDEV,
                                EXFULL};

  for (int i = 0; i < from_consts.size(); i++) {
    int result;
    TokLinuxErrorNumber(&to_consts[i], &result);
    EXPECT_THAT(result, Eq(from_consts[i]));
    FromkLinuxErrorNumber(&from_consts[i], &result);
    EXPECT_THAT(result, Eq(to_consts[i]));
  }
}

TEST_F(GeneratedTypesFunctionsTest, ErrorNumberUnknownInputTest) {
  int input = 4000;
  int output;
  TokLinuxErrorNumber(&input, &output);
  EXPECT_THAT(output, Eq(input | 0x8000));
  FromkLinuxErrorNumber(&input, &output);
  EXPECT_THAT(output, Eq(input | 0x8000));
}

TEST_F(GeneratedTypesFunctionsTest, SysconfConstantTest) {
  std::vector<int> from_consts = {
      kLinux__SC_ARG_MAX,          kLinux__SC_CHILD_MAX,
      kLinux__SC_HOST_NAME_MAX,    kLinux__SC_LOGIN_NAME_MAX,
      kLinux__SC_NGROUPS_MAX,      kLinux__SC_CLK_TCK,
      kLinux__SC_OPEN_MAX,         kLinux__SC_PAGESIZE,
      kLinux__SC_PAGE_SIZE,        kLinux__SC_RE_DUP_MAX,
      kLinux__SC_STREAM_MAX,       kLinux__SC_SYMLOOP_MAX,
      kLinux__SC_TTY_NAME_MAX,     kLinux__SC_TZNAME_MAX,
      kLinux__SC_VERSION,          kLinux__SC_NPROCESSORS_CONF,
      kLinux__SC_NPROCESSORS_ONLN, kLinux__SC_PHYS_PAGES,
      kLinux__SC_AVPHYS_PAGES,     kLinux__SC_BC_BASE_MAX,
      kLinux__SC_BC_DIM_MAX,       kLinux__SC_BC_SCALE_MAX,
      kLinux__SC_BC_STRING_MAX,    kLinux__SC_COLL_WEIGHTS_MAX,
      kLinux__SC_EXPR_NEST_MAX,    kLinux__SC_LINE_MAX,
      kLinux__SC_2_VERSION,        kLinux__SC_2_C_DEV,
      kLinux__SC_2_FORT_DEV,       kLinux__SC_2_FORT_RUN,
      kLinux__SC_2_LOCALEDEF,      kLinux__SC_2_SW_DEV};
  std::vector<int> to_consts = {
      _SC_ARG_MAX,          _SC_CHILD_MAX,        _SC_HOST_NAME_MAX,
      _SC_LOGIN_NAME_MAX,   _SC_NGROUPS_MAX,      _SC_CLK_TCK,
      _SC_OPEN_MAX,         _SC_PAGESIZE,         _SC_PAGE_SIZE,
      _SC_RE_DUP_MAX,       _SC_STREAM_MAX,       _SC_SYMLOOP_MAX,
      _SC_TTY_NAME_MAX,     _SC_TZNAME_MAX,       _SC_VERSION,
      _SC_NPROCESSORS_CONF, _SC_NPROCESSORS_ONLN, _SC_PHYS_PAGES,
      _SC_AVPHYS_PAGES,     _SC_BC_BASE_MAX,      _SC_BC_DIM_MAX,
      _SC_BC_SCALE_MAX,     _SC_BC_STRING_MAX,    _SC_COLL_WEIGHTS_MAX,
      _SC_EXPR_NEST_MAX,    _SC_LINE_MAX,         _SC_2_VERSION,
      _SC_2_C_DEV,          _SC_2_FORT_DEV,       _SC_2_FORT_RUN,
      _SC_2_LOCALEDEF,      _SC_2_SW_DEV};
  auto from_matcher = IsFiniteRestrictionOf<int, int>([&](int input) {
    int output;
    FromkLinuxSysconfConstant(&input, &output);
    return output;
  });
  EXPECT_THAT(FuzzFiniteFunctionWithFallback(from_consts, to_consts, -1,
                                             kIterationCount),
              from_matcher);
  auto to_matcher = IsFiniteRestrictionOf<int, int>([&](int input) {
    int output;
    TokLinuxSysconfConstant(&input, &output);
    return output;
  });
  EXPECT_THAT(FuzzFiniteFunctionWithFallback(to_consts, from_consts, -1,
                                             kIterationCount),
              to_matcher);
}

TEST_F(GeneratedTypesFunctionsTest, RecvSendFlagTest) {
  std::vector<int> from_bits = {
      kLinux_MSG_OOB,         kLinux_MSG_PEEK,       kLinux_MSG_DONTROUTE,
      kLinux_MSG_CTRUNC,      kLinux_MSG_PROXY,      kLinux_MSG_TRUNC,
      kLinux_MSG_DONTWAIT,    kLinux_MSG_EOR,        kLinux_MSG_WAITALL,
      kLinux_MSG_FIN,         kLinux_MSG_SYN,        kLinux_MSG_CONFIRM,
      kLinux_MSG_RST,         kLinux_MSG_ERRQUEUE,   kLinux_MSG_NOSIGNAL,
      kLinux_MSG_MORE,        kLinux_MSG_WAITFORONE, kLinux_MSG_FASTOPEN,
      kLinux_MSG_CMSG_CLOEXEC};
  std::vector<int> to_bits = {
      MSG_OOB,   MSG_PEEK,       MSG_DONTROUTE, MSG_CTRUNC,      MSG_PROXY,
      MSG_TRUNC, MSG_DONTWAIT,   MSG_EOR,       MSG_WAITALL,     MSG_FIN,
      MSG_SYN,   MSG_CONFIRM,    MSG_RST,       MSG_ERRQUEUE,    MSG_NOSIGNAL,
      MSG_MORE,  MSG_WAITFORONE, MSG_FASTOPEN,  MSG_CMSG_CLOEXEC};

  TestMultiValuedEnums(from_bits, to_bits, FromkLinuxRecvSendFlag,
                       TokLinuxRecvSendFlag);
}

}  // namespace
}  // namespace system_call
}  // namespace asylo
