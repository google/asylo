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

// For GNU strerror_r().
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif  // _GNU_SOURCE

#include "asylo/util/posix_errors.h"

#include <cerrno>
#include <cstring>
#include <string>

#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "asylo/util/posix_error_space.h"
#include "asylo/util/status.h"

namespace asylo {
namespace {

// A thread-safe implementation of strerror().
std::string StrError(int errnum) {
  // A buffer of 1024 should be sufficient on GNU systems according to
  // https://man7.org/linux/man-pages/man3/strerror.3.html.
  thread_local char strerror_buffer[1024] = {0};

  return strerror_r(errnum, strerror_buffer, sizeof(strerror_buffer));
}

}  // namespace

Status PosixError(int errnum, absl::string_view message) {
  if (errnum == 0) {
    return OkStatus();
  }

  if (message.empty()) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    return Status(static_cast<error::PosixError>(errnum), StrError(errnum));
#pragma GCC diagnostic pop
  } else {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    return Status(static_cast<error::PosixError>(errnum),
                  absl::StrCat(message, ": ", StrError(errnum)));
#pragma GCC diagnostic pop
  }
}

Status LastPosixError(absl::string_view message) {
  return PosixError(errno, message);
}

int GetErrno(const Status &status) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
  if (status.error_space() == error::PosixErrorSpace::GetInstance()) {
#pragma GCC diagnostic pop
    return status.raw_code();
  }
  return 0;
}

}  // namespace asylo
