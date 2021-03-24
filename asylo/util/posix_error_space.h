/*
 *
 * Copyright 2017 Asylo authors
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

#ifndef ASYLO_UTIL_POSIX_ERROR_SPACE_H_
#define ASYLO_UTIL_POSIX_ERROR_SPACE_H_

#include <errno.h>

#include <cerrno>
#include <string>

#include "absl/base/macros.h"
#include "asylo/util/error_space.h"

namespace asylo {
namespace error {

/// The enum associated with the POSIX error-space. To avoid conflict with the
/// macros defined in the <cerrno> system header, all the codes in this enum are
/// prefixed with a "P_".
///
/// \deprecated Deprecated as part of Asylo's `absl::Status` migration. Use the
///             functions from asylo/util/posix_errors.h or the matchers from
///             asylo/util/posix_error_matchers.h instead.
enum ABSL_DEPRECATED(
    "Deprecated as part of Asylo's absl::Status migration. Use the functions "
    "from asylo/util/posix_errors.h or the matchers from "
    "asylo/util/posix_error_matchers.h instead.") PosixError {
  P_E2BIG = E2BIG,
  P_EACCES = EACCES,
  P_EADDRINUSE = EADDRINUSE,
  P_EADDRNOTAVAIL = EADDRNOTAVAIL,
  P_EAFNOSUPPORT = EAFNOSUPPORT,
  P_EAGAIN = EAGAIN,
  P_EALREADY = EALREADY,
  P_EBADF = EBADF,
  P_EBADMSG = EBADMSG,
  P_EBUSY = EBUSY,
  P_ECANCELED = ECANCELED,
  P_ECHILD = ECHILD,
  P_ECONNABORTED = ECONNABORTED,
  P_ECONNREFUSED = ECONNREFUSED,
  P_ECONNRESET = ECONNRESET,
  P_EDEADLK = EDEADLK,
  P_EDESTADDRREQ = EDESTADDRREQ,
  P_EDOM = EDOM,
  P_EDQUOT = EDQUOT,
  P_EEXIST = EEXIST,
  P_EFAULT = EFAULT,
  P_EFBIG = EFBIG,
  P_EHOSTUNREACH = EHOSTUNREACH,
  P_EIDRM = EIDRM,
  P_EILSEQ = EILSEQ,
  P_EINPROGRESS = EINPROGRESS,
  P_EINTR = EINTR,
  P_EINVAL = EINVAL,
  P_EIO = EIO,
  P_EISCONN = EISCONN,
  P_EISDIR = EISDIR,
  P_ELOOP = ELOOP,
  P_EMFILE = EMFILE,
  P_EMLINK = EMLINK,
  P_EMSGSIZE = EMSGSIZE,
  P_EMULTIHOP = EMULTIHOP,
  P_ENAMETOOLONG = ENAMETOOLONG,
  P_ENETDOWN = ENETDOWN,
  P_ENETRESET = ENETRESET,
  P_ENETUNREACH = ENETUNREACH,
  P_ENFILE = ENFILE,
  P_ENOBUFS = ENOBUFS,
  P_ENODATA = ENODATA,
  P_ENODEV = ENODEV,
  P_ENOENT = ENOENT,
  P_ENOEXEC = ENOEXEC,
  P_ENOLCK = ENOLCK,
  P_ENOLINK = ENOLINK,
  P_ENOMEM = ENOMEM,
  P_ENOMSG = ENOMSG,
  P_ENOPROTOOPT = ENOPROTOOPT,
  P_ENOSPC = ENOSPC,
  P_ENOSR = ENOSR,
  P_ENOSTR = ENOSTR,
  P_ENOSYS = ENOSYS,
  P_ENOTCONN = ENOTCONN,
  P_ENOTDIR = ENOTDIR,
  P_ENOTEMPTY = ENOTEMPTY,
  P_ENOTRECOVERABLE = ENOTRECOVERABLE,
  P_ENOTSOCK = ENOTSOCK,
  P_ENOTSUP = ENOTSUP,
  P_ENOTTY = ENOTTY,
  P_ENXIO = ENXIO,
  // P_EOPNOTSUPP: Linux aliases this. Use P_ENOTSUP instead.
  P_EOVERFLOW = EOVERFLOW,
  P_EOWNERDEAD = EOWNERDEAD,
  P_EPERM = EPERM,
  P_EPIPE = EPIPE,
  P_EPROTO = EPROTO,
  P_EPROTONOSUPPORT = EPROTONOSUPPORT,
  P_EPROTOTYPE = EPROTOTYPE,
  P_ERANGE = ERANGE,
  P_EROFS = EROFS,
  P_ESPIPE = ESPIPE,
  P_ESRCH = ESRCH,
  P_ESTALE = ESTALE,
  P_ETIME = ETIME,
  P_ETIMEDOUT = ETIMEDOUT,
  P_ETXTBSY = ETXTBSY,
  // P_EWOULDBLOCK: Linux aliases this. Use P_EAGAIN instead.
  P_EXDEV = EXDEV
};

/// Binds the PosixErrorSpace class to the PosixError enum.
///
/// \deprecated Deprecated as part of Asylo's `absl::Status` migration. Use the
///             functions from asylo/util/posix_errors.h or the matchers from
///             asylo/util/posix_error_matchers.h instead.
ABSL_DEPRECATED(
    "Deprecated as part of Asylo's absl::Status migration. Use the functions "
    "from asylo/util/posix_errors.h or the matchers from "
    "asylo/util/posix_error_matchers.h instead.")
ErrorSpace const *GetErrorSpace(ErrorSpaceAdlTag<PosixError> tag);

/// An implementation of the ErrorSpace interface for POSIX error codes.
///
/// \deprecated Deprecated as part of Asylo's `absl::Status` migration. Use the
///             functions from asylo/util/posix_errors.h or the matchers from
///             asylo/util/posix_error_matchers.h instead.
class ABSL_DEPRECATED(
    "Deprecated as part of Asylo's absl::Status migration. Use the functions "
    "from asylo/util/posix_errors.h or the matchers from "
    "asylo/util/posix_error_matchers.h instead.") PosixErrorSpace
    : public ErrorSpaceImplementationHelper<PosixErrorSpace> {
 public:
  using code_type = PosixError;

  PosixErrorSpace(const PosixErrorSpace &other) = delete;
  virtual ~PosixErrorSpace() = default;
  PosixErrorSpace &operator=(const PosixErrorSpace &other) = delete;

  /// Gets the singleton instance of PosixErrorSpace.
  /// \return The one instance of PosixErrorSpace.
  static ErrorSpace const *GetInstance();

 private:
  PosixErrorSpace();
  GoogleError PosixToGoogle(PosixError code) const;
};

}  // namespace error
}  // namespace asylo

#endif  // ASYLO_UTIL_POSIX_ERROR_SPACE_H_
