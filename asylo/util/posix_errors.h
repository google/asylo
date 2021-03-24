/*
 * Copyright 2021 Asylo authors
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
 */

#ifndef ASYLO_UTIL_POSIX_ERRORS_H_
#define ASYLO_UTIL_POSIX_ERRORS_H_

#include "absl/strings/string_view.h"
#include "asylo/util/status.h"

namespace asylo {

/// Returns a Status representing a POSIX error. If `errnum` is zero,
/// `PosixError()` returns an OK status. Otherwise, the returned error message
/// includes the POSIX error explanation string.
///
/// Callers should not rely on how `PosixError()` embeds error information in
/// the returned `Status`. Instead, callers can use `GetErrno()` to inspect a
/// `Status` for POSIX error information.
///
/// However, callers may rely on stability in the mapping between POSIX error
/// numbers and `absl::StatusCode`s. Callers can also use this function to
/// create `Status`es that are understandable by other code that uses the POSIX
/// error space.
///
/// \param errnum A POSIX error number. See errno(3).
/// \param message An optional message to prepend to the POSIX error explanation
///                string.
/// \return An error representing `errnum`, or an OK status if `errnum` is zero.
Status PosixError(int errnum, absl::string_view message = "");

/// Returns a Status representing the last POSIX error in this thread.
///
/// Equivalent to calling `PosixError(errno, message)`.
///
/// \param message An optional message to prepend to the POSIX error explanation
///                string.
/// \return An error the last POSIX error in this thread.
Status LastPosixError(absl::string_view message = "");

/// Returns the POSIX error number that a `Status` represents, or zero if the
/// `Status` does not represent a POSIX error.
///
/// This function understands `Status`es that were created in the POSIX error
/// space.
///
/// \param status A status object.
/// \return The POSIX error number represented by `status`, or zero if `status`
///         does not represent a POSIX error.
int GetErrno(const Status &status);

}  // namespace asylo

#endif  // ASYLO_UTIL_POSIX_ERRORS_H_
