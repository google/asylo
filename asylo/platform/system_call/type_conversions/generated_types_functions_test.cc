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
#include <optional>
#include <vector>

#include <gtest/gtest.h>
#include "asylo/platform/system_call/type_conversions/manual_types_functions.h"
#include "asylo/test/util/finite_domain_fuzz.h"

#ifdef ABSL_USES_STD_OPTIONAL
namespace std {
template <typename T>
std::ostream &operator<<(std::ostream &os, const std::optional<T> &opt) {
  if (opt) {
    return os << ::testing::PrintToString(*opt);
  }
  return os << "<nullopt>";
}
}  // namespace std
#else
namespace absl {
template <typename T>
std::ostream &operator<<(std::ostream &os, const absl::optional<T> &opt) {
  if (opt) {
    return os << ::testing::PrintToString(*opt);
  }
  return os << "<nullopt>";
}
}  // namespace absl
#endif

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
 protected:
  template <typename T>
  void TestMultiValuedEnums(
      const std::vector<T> &from_bits, const std::vector<int64_t> &to_bits,
      std::function<absl::optional<int64_t>(int64_t, bool)> from_function,
      std::function<absl::optional<int64_t>(int64_t, bool)> to_function) {
    EXPECT_THAT(FuzzBitsetTranslationFunction(
                    from_bits, MakeOptionalVector(to_bits), kIterationCount),
                IsFiniteRestrictionOf(from_function));
    EXPECT_THAT(FuzzBitsetTranslationFunction(
                    to_bits, MakeOptionalVector(from_bits), kIterationCount),
                IsFiniteRestrictionOf(to_function));

    // The above tests run with the default of "ignore_unexpected_bits" set to
    // true. Add an extra quick check to ensure that if ALL bits are set, we
    // still get a good conversion. Since the converters are automatically
    // generated, and identical code, this should be a sufficient test of the
    // ignore_unexpected_bits functionality.
    EXPECT_NE(from_function(0xffffffff, /*ignore_unexpected_bits=*/true),
              absl::nullopt);
    EXPECT_NE(to_function(0xffffffff, /*ignore_unexpected_bits=*/true),
              absl::nullopt);
  }

  // Tests that all values map both ways between |from| and |to|. Any values not
  // in the mappings return absl::nullopt.
  void TestDirectValueMapping(
      const std::vector<int> &from, const std::vector<int> &to,
      std::function<absl::optional<int>(int)> from_function,
      std::function<absl::optional<int>(int)> to_function) {
    EXPECT_THAT(
        FuzzFiniteFunction(from, MakeOptionalVector(to), kIterationCount),
        IsFiniteRestrictionOf(from_function));
    EXPECT_THAT(
        FuzzFiniteFunction(to, MakeOptionalVector(from), kIterationCount),
        IsFiniteRestrictionOf(to_function));
  }

  template <typename T>
  std::vector<absl::optional<T>> MakeOptionalVector(
      const std::vector<T> &values) {
    return {values.begin(), values.end()};
  }
};

TEST_F(GeneratedTypesFunctionsTest, FileStatusFlagTest) {
  std::vector<int64_t> from_bits = {
      kLinux_O_RDONLY, kLinux_O_WRONLY, kLinux_O_RDWR,  kLinux_O_CREAT,
      kLinux_O_APPEND, kLinux_O_EXCL,   kLinux_O_TRUNC, kLinux_O_NONBLOCK,
      kLinux_O_DIRECT, kLinux_O_CLOEXEC};
  std::vector<int64_t> to_bits = {O_RDONLY, O_WRONLY, O_RDWR,  O_CREAT,
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

  TestDirectValueMapping(from_consts, to_consts, FromkLinuxFcntlCommand,
                         TokLinuxFcntlCommand);
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

  EXPECT_EQ(FromkLinuxFcntlCommand(123), absl::nullopt);
  EXPECT_EQ(TokLinuxFcntlCommand(123), absl::nullopt);
}

TEST_F(GeneratedTypesFunctionsTest, FDFlagTest) {
  std::vector<int64_t> from_bits = {kLinux_FD_CLOEXEC};
  std::vector<int64_t> to_bits = {FD_CLOEXEC};
  TestMultiValuedEnums(from_bits, to_bits, FromkLinuxFDFlag, TokLinuxFDFlag);
}

TEST_F(GeneratedTypesFunctionsTest, TcpOptionNameTest) {
  std::vector<int> from_consts = {kLinux_TCP_NODELAY, kLinux_TCP_KEEPIDLE,
                                  kLinux_TCP_KEEPINTVL, kLinux_TCP_KEEPCNT};
  std::vector<int> to_consts = {TCP_NODELAY, TCP_KEEPIDLE, TCP_KEEPINTVL,
                                TCP_KEEPCNT};
  TestDirectValueMapping(from_consts, to_consts, FromkLinuxTcpOptionName,
                         TokLinuxTcpOptionName);
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
  TestDirectValueMapping(from_consts, to_consts, FromkLinuxIpV6OptionName,
                         TokLinuxIpV6OptionName);
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
  TestDirectValueMapping(from_consts, to_consts, FromkLinuxSocketOptionName,
                         TokLinuxSocketOptionName);
}

TEST_F(GeneratedTypesFunctionsTest, FlockOperationTest) {
  std::vector<int64_t> from_bits = {kLinux_LOCK_SH, kLinux_LOCK_EX,
                                    kLinux_LOCK_NB, kLinux_LOCK_UN};
  std::vector<int64_t> to_bits = {LOCK_SH, LOCK_EX, LOCK_NB, LOCK_UN};
  TestMultiValuedEnums(from_bits, to_bits, FromkLinuxFLockOperation,
                       TokLinuxFLockOperation);
}

TEST_F(GeneratedTypesFunctionsTest, InotifyFlagsTest) {
  std::vector<int64_t> from_bits = {kLinux_IN_NONBLOCK, kLinux_IN_CLOEXEC};
  std::vector<int64_t> to_bits = {IN_NONBLOCK, IN_CLOEXEC};
  TestMultiValuedEnums(from_bits, to_bits, FromkLinuxInotifyFlag,
                       TokLinuxInotifyFlag);
}

TEST_F(GeneratedTypesFunctionsTest, InotifyEventMaskTest) {
  std::vector<uint32_t> from_bits = {
      kLinux_IN_ACCESS,        kLinux_IN_ATTRIB,      kLinux_IN_CLOSE_WRITE,
      kLinux_IN_CLOSE_NOWRITE, kLinux_IN_CREATE,      kLinux_IN_DELETE,
      kLinux_IN_DELETE_SELF,   kLinux_IN_MODIFY,      kLinux_IN_MOVE_SELF,
      kLinux_IN_MOVED_FROM,    kLinux_IN_MOVED_TO,    kLinux_IN_OPEN,
      kLinux_IN_DONT_FOLLOW,   kLinux_IN_EXCL_UNLINK, kLinux_IN_MASK_ADD,
      kLinux_IN_ONLYDIR,       kLinux_IN_IGNORED,     kLinux_IN_ISDIR,
      kLinux_IN_Q_OVERFLOW,    kLinux_IN_UNMOUNT};
  std::vector<uint32_t> to_bits = {
      IN_ACCESS,      IN_ATTRIB,      IN_CLOSE_WRITE, IN_CLOSE_NOWRITE,
      IN_CREATE,      IN_DELETE,      IN_DELETE_SELF, IN_MODIFY,
      IN_MOVE_SELF,   IN_MOVED_FROM,  IN_MOVED_TO,    IN_OPEN,
      IN_DONT_FOLLOW, IN_EXCL_UNLINK, IN_MASK_ADD,    IN_ONLYDIR,
      IN_IGNORED,     IN_ISDIR,       IN_Q_OVERFLOW,  IN_UNMOUNT};
  for (int i = 0; i < from_bits.size(); i++) {
    EXPECT_THAT(FromkLinuxInotifyEventMask(from_bits[i]), Eq(to_bits[i]));
    EXPECT_THAT(TokLinuxInotifyEventMask(to_bits[i]), Eq(from_bits[i]));
  }
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
    EXPECT_THAT(TokLinuxErrorNumber(to_consts[i]), Eq(from_consts[i]));
    EXPECT_THAT(FromkLinuxErrorNumber(from_consts[i]), Eq(to_consts[i]));
  }
}

TEST_F(GeneratedTypesFunctionsTest, ErrorNumberUnknownInputTest) {
  int input = 4000;
  EXPECT_THAT(TokLinuxErrorNumber(input), Eq(absl::nullopt));
  EXPECT_THAT(FromkLinuxErrorNumber(input), Eq(absl::nullopt));
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
  TestDirectValueMapping(from_consts, to_consts, FromkLinuxSysconfConstant,
                         TokLinuxSysconfConstant);
}

TEST_F(GeneratedTypesFunctionsTest, RecvSendFlagTest) {
  std::vector<int64_t> from_bits = {
      kLinux_MSG_OOB,         kLinux_MSG_PEEK,       kLinux_MSG_DONTROUTE,
      kLinux_MSG_CTRUNC,      kLinux_MSG_PROXY,      kLinux_MSG_TRUNC,
      kLinux_MSG_DONTWAIT,    kLinux_MSG_EOR,        kLinux_MSG_WAITALL,
      kLinux_MSG_FIN,         kLinux_MSG_SYN,        kLinux_MSG_CONFIRM,
      kLinux_MSG_RST,         kLinux_MSG_ERRQUEUE,   kLinux_MSG_NOSIGNAL,
      kLinux_MSG_MORE,        kLinux_MSG_WAITFORONE, kLinux_MSG_FASTOPEN,
      kLinux_MSG_CMSG_CLOEXEC};
  std::vector<int64_t> to_bits = {
      MSG_OOB,   MSG_PEEK,       MSG_DONTROUTE, MSG_CTRUNC,      MSG_PROXY,
      MSG_TRUNC, MSG_DONTWAIT,   MSG_EOR,       MSG_WAITALL,     MSG_FIN,
      MSG_SYN,   MSG_CONFIRM,    MSG_RST,       MSG_ERRQUEUE,    MSG_NOSIGNAL,
      MSG_MORE,  MSG_WAITFORONE, MSG_FASTOPEN,  MSG_CMSG_CLOEXEC};

  TestMultiValuedEnums(from_bits, to_bits, FromkLinuxRecvSendFlag,
                       TokLinuxRecvSendFlag);
}

TEST_F(GeneratedTypesFunctionsTest, BaseSignalNumberTest) {
  std::vector<int> from_consts = {
      kLinux_SIGHUP,    kLinux_SIGINT,  kLinux_SIGQUIT,  kLinux_SIGILL,
      kLinux_SIGTRAP,   kLinux_SIGABRT, kLinux_SIGBUS,   kLinux_SIGFPE,
      kLinux_SIGKILL,   kLinux_SIGUSR1, kLinux_SIGSEGV,  kLinux_SIGUSR2,
      kLinux_SIGPIPE,   kLinux_SIGALRM, kLinux_SIGTERM,  kLinux_SIGCHLD,
      kLinux_SIGCONT,   kLinux_SIGSTOP, kLinux_SIGTSTP,  kLinux_SIGTTIN,
      kLinux_SIGTTOU,   kLinux_SIGURG,  kLinux_SIGXCPU,  kLinux_SIGXFSZ,
      kLinux_SIGVTALRM, kLinux_SIGPROF, kLinux_SIGWINCH, kLinux_SIGSYS,
      kLinux_SIGIO,
#ifdef SIGPWR
      kLinux_SIGPWR,
#endif
#ifdef SIGRTMIN
      kLinux_SIGRTMIN,
#endif
#ifdef SIGRTMAX
      kLinux_SIGRTMAX,
#endif
      kLinux_NSIG,
  };
  std::vector<int> to_consts = {
      SIGHUP,    SIGINT,  SIGQUIT,  SIGILL,  SIGTRAP, SIGABRT, SIGBUS,  SIGFPE,
      SIGKILL,   SIGUSR1, SIGSEGV,  SIGUSR2, SIGPIPE, SIGALRM, SIGTERM, SIGCHLD,
      SIGCONT,   SIGSTOP, SIGTSTP,  SIGTTIN, SIGTTOU, SIGURG,  SIGXCPU, SIGXFSZ,
      SIGVTALRM, SIGPROF, SIGWINCH, SIGSYS,  SIGIO,
#ifdef SIGPWR
      SIGPWR,
#endif
#ifdef SIGRTMIN
      SIGRTMIN,
#endif
#ifdef SIGRTMAX
      SIGRTMAX,
#endif
      NSIG,
  };
  TestDirectValueMapping(from_consts, to_consts, FromkLinuxBaseSignalNumber,
                         TokLinuxBaseSignalNumber);
}

TEST_F(GeneratedTypesFunctionsTest, ClockIdTest) {
  std::vector<clockid_t> from_consts = {
      kLinux_CLOCK_MONOTONIC, kLinux_CLOCK_REALTIME,
  };
  std::vector<clockid_t> to_consts = {
      CLOCK_MONOTONIC, CLOCK_REALTIME,
  };

  for (int i = 0; i < from_consts.size(); i++) {
    EXPECT_THAT(TokLinuxClockId(to_consts[i]), Eq(from_consts[i]));
    EXPECT_THAT(FromkLinuxClockId(from_consts[i]), Eq(to_consts[i]));
  }
}

TEST_F(GeneratedTypesFunctionsTest, ItimerTypeTest) {
  std::vector<int> from_consts = {kLinux_ITIMER_REAL, kLinux_ITIMER_VIRTUAL,
                                  kLinux_ITIMER_PROF};
  std::vector<int> to_consts = {ITIMER_REAL, ITIMER_VIRTUAL, ITIMER_PROF};
  TestDirectValueMapping(from_consts, to_consts, FromkLinuxItimerType,
                         TokLinuxItimerType);
}

TEST_F(GeneratedTypesFunctionsTest, AddressInfoFlagTest) {
  std::vector<int64_t> from_bits = {
      kLinux_AI_CANONNAME,   kLinux_AI_NUMERICHOST, kLinux_AI_V4MAPPED,
      kLinux_AI_ADDRCONFIG,  kLinux_AI_ALL,         kLinux_AI_PASSIVE,
      kLinux_AI_NUMERICSERV, kLinux_AI_IDN,         kLinux_AI_CANONIDN};
  std::vector<int64_t> to_bits = {AI_CANONNAME,   AI_NUMERICHOST, AI_V4MAPPED,
                                  AI_ADDRCONFIG,  AI_ALL,         AI_PASSIVE,
                                  AI_NUMERICSERV, AI_IDN,         AI_CANONIDN};

  TestMultiValuedEnums(from_bits, to_bits, FromkLinuxAddressInfoFlag,
                       TokLinuxAddressInfoFlag);
}

TEST_F(GeneratedTypesFunctionsTest, AddressInfoErrorTest) {
  std::vector<int> from_consts = {
      kLinux_EAI_ADDRFAMILY, kLinux_EAI_AGAIN,     kLinux_EAI_BADFLAGS,
      kLinux_EAI_FAIL,       kLinux_EAI_FAMILY,    kLinux_EAI_MEMORY,
      kLinux_EAI_NODATA,     kLinux_EAI_NONAME,    kLinux_EAI_SERVICE,
      kLinux_EAI_SOCKTYPE,   kLinux_EAI_SYSTEM,    kLinux_EAI_OVERFLOW,
      kLinux_EAI_INPROGRESS, kLinux_EAI_CANCELED,  kLinux_EAI_ALLDONE,
      kLinux_EAI_INTR,       kLinux_EAI_IDN_ENCODE};
  std::vector<int> to_consts = {
      EAI_ADDRFAMILY, EAI_AGAIN,     EAI_BADFLAGS,   EAI_FAIL,     EAI_FAMILY,
      EAI_MEMORY,     EAI_NODATA,    EAI_NONAME,     EAI_SERVICE,  EAI_SOCKTYPE,
      EAI_SYSTEM,     EAI_OVERFLOW,  EAI_INPROGRESS, EAI_CANCELED, EAI_ALLDONE,
      EAI_INTR,       EAI_IDN_ENCODE};
  for (int i = 0; i < from_consts.size(); i++) {
    EXPECT_THAT(TokLinuxAddressInfoError(to_consts[i]), Eq(from_consts[i]));
    EXPECT_THAT(FromkLinuxAddressInfoError(from_consts[i]), Eq(to_consts[i]));
  }
}

TEST_F(GeneratedTypesFunctionsTest, PollEventTest) {
  std::vector<int64_t> from_bits = {
      kLinux_POLLIN,     kLinux_POLLPRI,    kLinux_POLLOUT,   kLinux_POLLRDHUP,
      kLinux_POLLERR,    kLinux_POLLHUP,    kLinux_POLLNVAL,  kLinux_POLLRDNORM,
      kLinux_POLLRDBAND, kLinux_POLLWRNORM, kLinux_POLLWRBAND};
  std::vector<int64_t> to_bits = {POLLIN,     POLLPRI,    POLLOUT,   POLLRDHUP,
                                  POLLERR,    POLLHUP,    POLLNVAL,  POLLRDNORM,
                                  POLLRDBAND, POLLWRNORM, POLLWRBAND};

  TestMultiValuedEnums(from_bits, to_bits, FromkLinuxPollEvent,
                       TokLinuxPollEvent);
}

TEST_F(GeneratedTypesFunctionsTest, UtimbufTest) {
  EXPECT_THAT(sizeof(struct utimbuf), Eq(sizeof(struct kLinux_utimbuf)));
  struct utimbuf from {};
  struct kLinux_utimbuf to {};
  from.actime = 1;
  from.modtime = 2;

  EXPECT_THAT(TokLinuxutimbuf(&from, &to), Eq(true));
  EXPECT_THAT(to.kLinux_actime, Eq(from.actime));
  EXPECT_THAT(to.kLinux_modtime, Eq(from.modtime));

  to.kLinux_actime = 3;
  to.kLinux_modtime = 4;
  EXPECT_THAT(FromkLinuxutimbuf(&to, &from), Eq(true));
  EXPECT_THAT(from.actime, Eq(3));
  EXPECT_THAT(from.modtime, Eq(4));
}

TEST_F(GeneratedTypesFunctionsTest, RusageTargetTest) {
  std::vector<int> from_consts = {kLinux_RUSAGE_SELF, kLinux_RUSAGE_CHILDREN};
  std::vector<int> to_consts = {RUSAGE_SELF, RUSAGE_CHILDREN};
  TestDirectValueMapping(from_consts, to_consts, FromkLinuxRusageTarget,
                         TokLinuxRusageTarget);
}

TEST_F(GeneratedTypesFunctionsTest, SyslogFacilityTest) {
  std::vector<int> from_consts = {kLinux_LOG_KERN,   kLinux_LOG_USER,
                                  kLinux_LOG_LOCAL0, kLinux_LOG_LOCAL1,
                                  kLinux_LOG_LOCAL2, kLinux_LOG_LOCAL3,
                                  kLinux_LOG_LOCAL4, kLinux_LOG_LOCAL5,
                                  kLinux_LOG_LOCAL6, kLinux_LOG_LOCAL7};
  std::vector<int> to_consts = {LOG_KERN,   LOG_USER,   LOG_LOCAL0, LOG_LOCAL1,
                                LOG_LOCAL2, LOG_LOCAL3, LOG_LOCAL4, LOG_LOCAL5,
                                LOG_LOCAL6, LOG_LOCAL7};
  TestDirectValueMapping(from_consts, to_consts, FromkLinuxSyslogFacility,
                         TokLinuxSyslogFacility);
}

TEST_F(GeneratedTypesFunctionsTest, SyslogLevelTest) {
  std::vector<int> from_consts = {
      kLinux_LOG_EMERG,   kLinux_LOG_ALERT,  kLinux_LOG_CRIT, kLinux_LOG_ERR,
      kLinux_LOG_WARNING, kLinux_LOG_NOTICE, kLinux_LOG_INFO, kLinux_LOG_DEBUG};
  std::vector<int> to_consts = {LOG_EMERG,   LOG_ALERT,  LOG_CRIT, LOG_ERR,
                                LOG_WARNING, LOG_NOTICE, LOG_INFO, LOG_DEBUG};
  TestDirectValueMapping(from_consts, to_consts, FromkLinuxSyslogLevel,
                         TokLinuxSyslogLevel);
}

TEST_F(GeneratedTypesFunctionsTest, SyslogOptionTest) {
  std::vector<int64_t> from_bits = {kLinux_LOG_PID,    kLinux_LOG_CONS,
                                    kLinux_LOG_ODELAY, kLinux_LOG_NDELAY,
                                    kLinux_LOG_NOWAIT, kLinux_LOG_PERROR};
  std::vector<int64_t> to_bits = {LOG_PID,    LOG_CONS,   LOG_ODELAY,
                                  LOG_NDELAY, LOG_NOWAIT, LOG_PERROR};

  TestMultiValuedEnums(from_bits, to_bits, FromkLinuxSyslogOption,
                       TokLinuxSyslogOption);
}

TEST_F(GeneratedTypesFunctionsTest, SignalCodeTest) {
  std::vector<int> from_consts = {kLinux_SI_USER, kLinux_SI_QUEUE,
                                  kLinux_SI_TIMER, kLinux_SI_ASYNCIO,
                                  kLinux_SI_MESGQ};
  std::vector<int> to_consts = {SI_USER, SI_QUEUE, SI_TIMER, SI_ASYNCIO,
                                SI_MESGQ};
  TestDirectValueMapping(from_consts, to_consts, FromkLinuxSignalCode,
                         TokLinuxSignalCode);
}

}  // namespace
}  // namespace system_call
}  // namespace asylo
