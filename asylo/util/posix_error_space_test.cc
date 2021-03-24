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

#include <set>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/strings/str_format.h"

// Suppress deprecation warnings because this file tests deprecated APIs.
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

namespace asylo {
namespace error {
namespace {

constexpr int kMinErrorCode = 1;
constexpr int kMaxErrorCode = 1000;

// A test fixture is used for naming consistency and future scalability.
class PosixErrorSpaceTest : public ::testing::Test {
 protected:
  PosixErrorSpaceTest()
      : codes_{PosixError::P_E2BIG,
               PosixError::P_EACCES,
               PosixError::P_EADDRINUSE,
               PosixError::P_EADDRNOTAVAIL,
               PosixError::P_EAFNOSUPPORT,
               PosixError::P_EAGAIN,
               PosixError::P_EALREADY,
               PosixError::P_EBADF,
               PosixError::P_EBADMSG,
               PosixError::P_EBUSY,
               PosixError::P_ECANCELED,
               PosixError::P_ECHILD,
               PosixError::P_ECONNABORTED,
               PosixError::P_ECONNREFUSED,
               PosixError::P_ECONNRESET,
               PosixError::P_EDEADLK,
               PosixError::P_EDESTADDRREQ,
               PosixError::P_EDOM,
               PosixError::P_EDQUOT,
               PosixError::P_EEXIST,
               PosixError::P_EFAULT,
               PosixError::P_EFBIG,
               PosixError::P_EHOSTUNREACH,
               PosixError::P_EIDRM,
               PosixError::P_EILSEQ,
               PosixError::P_EINPROGRESS,
               PosixError::P_EINTR,
               PosixError::P_EINVAL,
               PosixError::P_EIO,
               PosixError::P_EISCONN,
               PosixError::P_EISDIR,
               PosixError::P_ELOOP,
               PosixError::P_EMFILE,
               PosixError::P_EMLINK,
               PosixError::P_EMSGSIZE,
               PosixError::P_EMULTIHOP,
               PosixError::P_ENAMETOOLONG,
               PosixError::P_ENETDOWN,
               PosixError::P_ENETRESET,
               PosixError::P_ENETUNREACH,
               PosixError::P_ENFILE,
               PosixError::P_ENOBUFS,
               PosixError::P_ENODATA,
               PosixError::P_ENODEV,
               PosixError::P_ENOENT,
               PosixError::P_ENOEXEC,
               PosixError::P_ENOLCK,
               PosixError::P_ENOLINK,
               PosixError::P_ENOMEM,
               PosixError::P_ENOMSG,
               PosixError::P_ENOPROTOOPT,
               PosixError::P_ENOSPC,
               PosixError::P_ENOSR,
               PosixError::P_ENOSTR,
               PosixError::P_ENOSYS,
               PosixError::P_ENOTCONN,
               PosixError::P_ENOTDIR,
               PosixError::P_ENOTEMPTY,
               PosixError::P_ENOTRECOVERABLE,
               PosixError::P_ENOTSOCK,
               PosixError::P_ENOTSUP,
               PosixError::P_ENOTTY,
               PosixError::P_ENXIO,
               PosixError::P_EOVERFLOW,
               PosixError::P_EOWNERDEAD,
               PosixError::P_EPERM,
               PosixError::P_EPIPE,
               PosixError::P_EPROTO,
               PosixError::P_EPROTONOSUPPORT,
               PosixError::P_EPROTOTYPE,
               PosixError::P_ERANGE,
               PosixError::P_EROFS,
               PosixError::P_ESPIPE,
               PosixError::P_ESRCH,
               PosixError::P_ESTALE,
               PosixError::P_ETIME,
               PosixError::P_ETIMEDOUT,
               PosixError::P_ETXTBSY,
               PosixError::P_EXDEV} {}

  std::set<PosixError> codes_;
};

// Make sure that the GoogleErrorSpace singleton can be retrieved based on the
// enum as well as the name, and that it returns the same value.
TEST_F(PosixErrorSpaceTest, PosixErrorSpaceSingletonCorrectness) {
  ErrorSpace const *space1 = error_enum_traits<PosixError>::get_error_space();
  EXPECT_NE(space1, nullptr);
  ErrorSpace const *space2 =
      ErrorSpace::Find("::asylo::error::PosixErrorSpace");
  EXPECT_NE(space2, nullptr);
  EXPECT_EQ(space1, space2);
}

TEST_F(PosixErrorSpaceTest, PosixErrorSpaceSpaceName) {
  ErrorSpace const *space = error_enum_traits<PosixError>::get_error_space();
  EXPECT_EQ(space->SpaceName(), "::asylo::error::PosixErrorSpace");
}

// Verify that String() translates every valid POSIX error code into a string
// that is not "Unrecognized Code". Also verify that it translates an invalid
// POSIX error code to "Unrecognized Code".
TEST_F(PosixErrorSpaceTest, PosixErrorSpaceString) {
  ErrorSpace const *space = error_enum_traits<PosixError>::get_error_space();
  for (const auto &code : codes_) {
    // Make sure that all the error codes defined by PosixError map to a string
    // other than "Unrecognized code".
    EXPECT_NE(space->String(code), "Unrecognized Code");
  }

  for (int i = kMinErrorCode; i < kMaxErrorCode; i++) {
    PosixError code = static_cast<PosixError>(i);
    if (codes_.find(code) == codes_.end()) {
      EXPECT_EQ(space->String(code),
                absl::StrFormat("%s (%d)", "Unrecognized Code", code));
    }
  }
}

// Verify that GoogleErrorCode() translates every valid POSIX error code into a
// valid GoogleError code. Also verify that it translates an invalid POSIX error
// code into GoogleError::UNKNOWN.
TEST_F(PosixErrorSpaceTest, PosixErrorSpaceGoogleErrorCode) {
  ErrorSpace const *space = error_enum_traits<PosixError>::get_error_space();
  for (const auto &code : codes_) {
    // Returned GoogleErrorCode must be a valid member of the GoogleError enum.
    GoogleError google_code = space->GoogleErrorCode(code);
    EXPECT_GE(google_code, GoogleError::OK);
    EXPECT_LE(google_code, GoogleError::UNAUTHENTICATED);
  }

  for (int i = kMinErrorCode; i < kMaxErrorCode; i++) {
    PosixError code = static_cast<PosixError>(i);
    if (codes_.find(code) == codes_.end()) {
      EXPECT_EQ(space->GoogleErrorCode(code), GoogleError::UNKNOWN);
    }
  }
}

}  // namespace
}  // namespace error
}  // namespace asylo
