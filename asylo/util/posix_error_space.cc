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

#include "asylo/util/posix_error_space.h"

#include <cstring>

#include "asylo/util/error_space.h"

namespace asylo {
namespace error {

ErrorSpace const *GetErrorSpace(
    ErrorSpaceAdlTag<::asylo::error::PosixError> tag) {
  return PosixErrorSpace::GetInstance();
}

ErrorSpace const *PosixErrorSpace::GetInstance() {
  static ErrorSpace const *instance = new PosixErrorSpace();
  return instance;
}

PosixErrorSpace::PosixErrorSpace()
    : ErrorSpaceImplementationHelper<PosixErrorSpace>(
          "::asylo::error::PosixErrorSpace") {
  AddTranslationMapEntry(P_E2BIG, std::strerror(P_E2BIG),
                         PosixToGoogle(P_E2BIG));
  AddTranslationMapEntry(P_EACCES, std::strerror(P_EACCES),
                         PosixToGoogle(P_EACCES));
  AddTranslationMapEntry(P_EADDRINUSE, std::strerror(P_EADDRINUSE),
                         PosixToGoogle(P_EADDRINUSE));
  AddTranslationMapEntry(P_EADDRNOTAVAIL, std::strerror(P_EADDRNOTAVAIL),
                         PosixToGoogle(P_EADDRNOTAVAIL));
  AddTranslationMapEntry(P_EAFNOSUPPORT, std::strerror(P_EAFNOSUPPORT),
                         PosixToGoogle(P_EAFNOSUPPORT));
  AddTranslationMapEntry(P_EAGAIN, std::strerror(P_EAGAIN),
                         PosixToGoogle(P_EAGAIN));
  AddTranslationMapEntry(P_EALREADY, std::strerror(P_EALREADY),
                         PosixToGoogle(P_EALREADY));
  AddTranslationMapEntry(P_EBADF, std::strerror(P_EBADF),
                         PosixToGoogle(P_EBADF));
  AddTranslationMapEntry(P_EBADMSG, std::strerror(P_EBADMSG),
                         PosixToGoogle(P_EBADMSG));
  AddTranslationMapEntry(P_EBUSY, std::strerror(P_EBUSY),
                         PosixToGoogle(P_EBUSY));
  AddTranslationMapEntry(P_ECANCELED, std::strerror(P_ECANCELED),
                         PosixToGoogle(P_ECANCELED));
  AddTranslationMapEntry(P_ECHILD, std::strerror(P_ECHILD),
                         PosixToGoogle(P_ECHILD));
  AddTranslationMapEntry(P_ECONNABORTED, std::strerror(P_ECONNABORTED),
                         PosixToGoogle(P_ECONNABORTED));
  AddTranslationMapEntry(P_ECONNREFUSED, std::strerror(P_ECONNREFUSED),
                         PosixToGoogle(P_ECONNREFUSED));
  AddTranslationMapEntry(P_ECONNRESET, std::strerror(P_ECONNRESET),
                         PosixToGoogle(P_ECONNRESET));
  AddTranslationMapEntry(P_EDEADLK, std::strerror(P_EDEADLK),
                         PosixToGoogle(P_EDEADLK));
  AddTranslationMapEntry(P_EDESTADDRREQ, std::strerror(P_EDESTADDRREQ),
                         PosixToGoogle(P_EDESTADDRREQ));
  AddTranslationMapEntry(P_EDOM, std::strerror(P_EDOM), PosixToGoogle(P_EDOM));
  AddTranslationMapEntry(P_EDQUOT, std::strerror(P_EDQUOT),
                         PosixToGoogle(P_EDQUOT));
  AddTranslationMapEntry(P_EEXIST, std::strerror(P_EEXIST),
                         PosixToGoogle(P_EEXIST));
  AddTranslationMapEntry(P_EFAULT, std::strerror(P_EFAULT),
                         PosixToGoogle(P_EFAULT));
  AddTranslationMapEntry(P_EFBIG, std::strerror(P_EFBIG),
                         PosixToGoogle(P_EFBIG));
  AddTranslationMapEntry(P_EHOSTUNREACH, std::strerror(P_EHOSTUNREACH),
                         PosixToGoogle(P_EHOSTUNREACH));
  AddTranslationMapEntry(P_EIDRM, std::strerror(P_EIDRM),
                         PosixToGoogle(P_EIDRM));
  AddTranslationMapEntry(P_EILSEQ, std::strerror(P_EILSEQ),
                         PosixToGoogle(P_EILSEQ));
  AddTranslationMapEntry(P_EINPROGRESS, std::strerror(P_EINPROGRESS),
                         PosixToGoogle(P_EINPROGRESS));
  AddTranslationMapEntry(P_EINTR, std::strerror(P_EINTR),
                         PosixToGoogle(P_EINTR));
  AddTranslationMapEntry(P_EINVAL, std::strerror(P_EINVAL),
                         PosixToGoogle(P_EINVAL));
  AddTranslationMapEntry(P_EIO, std::strerror(P_EIO), PosixToGoogle(P_EIO));
  AddTranslationMapEntry(P_EISCONN, std::strerror(P_EISCONN),
                         PosixToGoogle(P_EISCONN));
  AddTranslationMapEntry(P_EISDIR, std::strerror(P_EISDIR),
                         PosixToGoogle(P_EISDIR));
  AddTranslationMapEntry(P_ELOOP, std::strerror(P_ELOOP),
                         PosixToGoogle(P_ELOOP));
  AddTranslationMapEntry(P_EMFILE, std::strerror(P_EMFILE),
                         PosixToGoogle(P_EMFILE));
  AddTranslationMapEntry(P_EMLINK, std::strerror(P_EMLINK),
                         PosixToGoogle(P_EMLINK));
  AddTranslationMapEntry(P_EMSGSIZE, std::strerror(P_EMSGSIZE),
                         PosixToGoogle(P_EMSGSIZE));
  AddTranslationMapEntry(P_EMULTIHOP, std::strerror(P_EMULTIHOP),
                         PosixToGoogle(P_EMULTIHOP));
  AddTranslationMapEntry(P_ENAMETOOLONG, std::strerror(P_ENAMETOOLONG),
                         PosixToGoogle(P_ENAMETOOLONG));
  AddTranslationMapEntry(P_ENETDOWN, std::strerror(P_ENETDOWN),
                         PosixToGoogle(P_ENETDOWN));
  AddTranslationMapEntry(P_ENETRESET, std::strerror(P_ENETRESET),
                         PosixToGoogle(P_ENETRESET));
  AddTranslationMapEntry(P_ENETUNREACH, std::strerror(P_ENETUNREACH),
                         PosixToGoogle(P_ENETUNREACH));
  AddTranslationMapEntry(P_ENFILE, std::strerror(P_ENFILE),
                         PosixToGoogle(P_ENFILE));
  AddTranslationMapEntry(P_ENOBUFS, std::strerror(P_ENOBUFS),
                         PosixToGoogle(P_ENOBUFS));
  AddTranslationMapEntry(P_ENODATA, std::strerror(P_ENODATA),
                         PosixToGoogle(P_ENODATA));
  AddTranslationMapEntry(P_ENODEV, std::strerror(P_ENODEV),
                         PosixToGoogle(P_ENODEV));
  AddTranslationMapEntry(P_ENOENT, std::strerror(P_ENOENT),
                         PosixToGoogle(P_ENOENT));
  AddTranslationMapEntry(P_ENOEXEC, std::strerror(P_ENOEXEC),
                         PosixToGoogle(P_ENOEXEC));
  AddTranslationMapEntry(P_ENOLCK, std::strerror(P_ENOLCK),
                         PosixToGoogle(P_ENOLCK));
  AddTranslationMapEntry(P_ENOLINK, std::strerror(P_ENOLINK),
                         PosixToGoogle(P_ENOLINK));
  AddTranslationMapEntry(P_ENOMEM, std::strerror(P_ENOMEM),
                         PosixToGoogle(P_ENOMEM));
  AddTranslationMapEntry(P_ENOMSG, std::strerror(P_ENOMSG),
                         PosixToGoogle(P_ENOMSG));
  AddTranslationMapEntry(P_ENOPROTOOPT, std::strerror(P_ENOPROTOOPT),
                         PosixToGoogle(P_ENOPROTOOPT));
  AddTranslationMapEntry(P_ENOSPC, std::strerror(P_ENOSPC),
                         PosixToGoogle(P_ENOSPC));
  AddTranslationMapEntry(P_ENOSR, std::strerror(P_ENOSR),
                         PosixToGoogle(P_ENOSR));
  AddTranslationMapEntry(P_ENOSTR, std::strerror(P_ENOSTR),
                         PosixToGoogle(P_ENOSTR));
  AddTranslationMapEntry(P_ENOSYS, std::strerror(P_ENOSYS),
                         PosixToGoogle(P_ENOSYS));
  AddTranslationMapEntry(P_ENOTCONN, std::strerror(P_ENOTCONN),
                         PosixToGoogle(P_ENOTCONN));
  AddTranslationMapEntry(P_ENOTDIR, std::strerror(P_ENOTDIR),
                         PosixToGoogle(P_ENOTDIR));
  AddTranslationMapEntry(P_ENOTEMPTY, std::strerror(P_ENOTEMPTY),
                         PosixToGoogle(P_ENOTEMPTY));
  AddTranslationMapEntry(P_ENOTRECOVERABLE, std::strerror(P_ENOTRECOVERABLE),
                         PosixToGoogle(P_ENOTRECOVERABLE));
  AddTranslationMapEntry(P_ENOTSOCK, std::strerror(P_ENOTSOCK),
                         PosixToGoogle(P_ENOTSOCK));
  AddTranslationMapEntry(P_ENOTSUP, std::strerror(P_ENOTSUP),
                         PosixToGoogle(P_ENOTSUP));
  AddTranslationMapEntry(P_ENOTTY, std::strerror(P_ENOTTY),
                         PosixToGoogle(P_ENOTTY));
  AddTranslationMapEntry(P_ENXIO, std::strerror(P_ENXIO),
                         PosixToGoogle(P_ENXIO));
  AddTranslationMapEntry(P_EOVERFLOW, std::strerror(P_EOVERFLOW),
                         PosixToGoogle(P_EOVERFLOW));
  AddTranslationMapEntry(P_EOWNERDEAD, std::strerror(P_EOWNERDEAD),
                         PosixToGoogle(P_EOWNERDEAD));
  AddTranslationMapEntry(P_EPERM, std::strerror(P_EPERM),
                         PosixToGoogle(P_EPERM));
  AddTranslationMapEntry(P_EPIPE, std::strerror(P_EPIPE),
                         PosixToGoogle(P_EPIPE));
  AddTranslationMapEntry(P_EPROTO, std::strerror(P_EPROTO),
                         PosixToGoogle(P_EPROTO));
  AddTranslationMapEntry(P_EPROTONOSUPPORT, std::strerror(P_EPROTONOSUPPORT),
                         PosixToGoogle(P_EPROTONOSUPPORT));
  AddTranslationMapEntry(P_EPROTOTYPE, std::strerror(P_EPROTOTYPE),
                         PosixToGoogle(P_EPROTOTYPE));
  AddTranslationMapEntry(P_ERANGE, std::strerror(P_ERANGE),
                         PosixToGoogle(P_ERANGE));
  AddTranslationMapEntry(P_EROFS, std::strerror(P_EROFS),
                         PosixToGoogle(P_EROFS));
  AddTranslationMapEntry(P_ESPIPE, std::strerror(P_ESPIPE),
                         PosixToGoogle(P_ESPIPE));
  AddTranslationMapEntry(P_ESRCH, std::strerror(P_ESRCH),
                         PosixToGoogle(P_ESRCH));
  AddTranslationMapEntry(P_ESTALE, std::strerror(P_ESTALE),
                         PosixToGoogle(P_ESTALE));
  AddTranslationMapEntry(P_ETIME, std::strerror(P_ETIME),
                         PosixToGoogle(P_ETIME));
  AddTranslationMapEntry(P_ETIMEDOUT, std::strerror(P_ETIMEDOUT),
                         PosixToGoogle(P_ETIMEDOUT));
  AddTranslationMapEntry(P_ETXTBSY, std::strerror(P_ETXTBSY),
                         PosixToGoogle(P_ETXTBSY));
  AddTranslationMapEntry(P_EXDEV, std::strerror(P_EXDEV),
                         PosixToGoogle(P_EXDEV));
}

GoogleError PosixErrorSpace::PosixToGoogle(PosixError code) const {
  if (static_cast<int>(code) == 0) {
    return GoogleError::OK;
  }

  switch (code) {
    case PosixError::P_EINVAL:
    case PosixError::P_ENAMETOOLONG:
    case PosixError::P_E2BIG:
    case PosixError::P_EMSGSIZE:
    case PosixError::P_EDESTADDRREQ:
    case PosixError::P_EDOM:
    case PosixError::P_EFAULT:
    case PosixError::P_EILSEQ:
    case PosixError::P_ENOPROTOOPT:
    case PosixError::P_ENOSTR:
    case PosixError::P_ENOTSOCK:
    case PosixError::P_ENOTTY:
    case PosixError::P_EPROTOTYPE:
    case PosixError::P_ESPIPE:
      return GoogleError::INVALID_ARGUMENT;

    case PosixError::P_ETIME:
    case PosixError::P_ETIMEDOUT:
      return GoogleError::DEADLINE_EXCEEDED;

    case PosixError::P_ENODEV:
    case PosixError::P_ENOENT:
    case PosixError::P_ENXIO:
    case PosixError::P_ESRCH:
      return GoogleError::NOT_FOUND;

    case PosixError::P_EEXIST:
    case PosixError::P_EADDRNOTAVAIL:
    case PosixError::P_EALREADY:
      return GoogleError::ALREADY_EXISTS;

    case PosixError::P_EACCES:
    case PosixError::P_EPERM:
    case PosixError::P_EROFS:
      return GoogleError::PERMISSION_DENIED;

    case PosixError::P_ENOTEMPTY:
    case PosixError::P_EISDIR:
    case PosixError::P_ENOTDIR:
    case PosixError::P_EADDRINUSE:
    case PosixError::P_EBADF:
    case PosixError::P_EBUSY:
    case PosixError::P_ECHILD:
    case PosixError::P_EISCONN:
    case PosixError::P_ENOTCONN:
    case PosixError::P_EPIPE:
    case PosixError::P_ETXTBSY:
      return GoogleError::FAILED_PRECONDITION;

    case PosixError::P_ENOSPC:
    case PosixError::P_EDQUOT:
    case PosixError::P_EMFILE:
    case PosixError::P_EMLINK:
    case PosixError::P_ENFILE:
    case PosixError::P_ENOBUFS:
    case PosixError::P_ENODATA:
    case PosixError::P_ENOMEM:
    case PosixError::P_ENOSR:
      return GoogleError::RESOURCE_EXHAUSTED;

    case PosixError::P_EFBIG:
    case PosixError::P_EOVERFLOW:
    case PosixError::P_ERANGE:
      return GoogleError::OUT_OF_RANGE;

    case PosixError::P_ENOSYS:
    case PosixError::P_ENOTSUP:
    case PosixError::P_EAFNOSUPPORT:
    case PosixError::P_EPROTONOSUPPORT:
    case PosixError::P_EXDEV:
      return GoogleError::UNIMPLEMENTED;

    case PosixError::P_EAGAIN:
    case PosixError::P_ECONNABORTED:
    case PosixError::P_ECONNREFUSED:
    case PosixError::P_ECONNRESET:
    case PosixError::P_EINTR:
    case PosixError::P_EHOSTUNREACH:
    case PosixError::P_ENETDOWN:
    case PosixError::P_ENETRESET:
    case PosixError::P_ENETUNREACH:
    case PosixError::P_ENOLCK:
    case PosixError::P_ENOLINK:
      return GoogleError::UNAVAILABLE;

    case PosixError::P_EDEADLK:
    case PosixError::P_ESTALE:
      return GoogleError::ABORTED;

    case PosixError::P_ECANCELED:
      return GoogleError::CANCELLED;

    case PosixError::P_EBADMSG:
    case PosixError::P_EIDRM:
    case PosixError::P_EINPROGRESS:
    case PosixError::P_EIO:
    case PosixError::P_ELOOP:
    case PosixError::P_ENOEXEC:
    case PosixError::P_ENOMSG:
    case PosixError::P_EPROTO:
    case PosixError::P_EMULTIHOP:
      return GoogleError::UNKNOWN;

    default:
      return GoogleError::UNKNOWN;
  }
}

}  // namespace error
}  // namespace asylo
