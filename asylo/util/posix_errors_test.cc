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

#include "asylo/util/posix_errors.h"

#include <cerrno>
#include <cstring>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status.h"

namespace asylo {
namespace {

using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::Not;

TEST(PosixErrorsTest, PosixErrorReturnsOkIfErrnumIsZero) {
  ASYLO_EXPECT_OK(PosixError(0));
  ASYLO_EXPECT_OK(PosixError(0, "message"));
}

TEST(PosixErrorsTest, PosixErrorIsNotOkIfErrnumIsNonZero) {
  EXPECT_THAT(PosixError(EINVAL), Not(IsOk()));
  EXPECT_THAT(PosixError(ENOMEM, "no more memory :("), Not(IsOk()));
}

TEST(PosixErrorsTest, PosixErrorContainsStrerrorAndMessage) {
  constexpr absl::string_view kMessage = "some message";
  Status error = PosixError(EINVAL, kMessage);
  EXPECT_THAT(error.message(), HasSubstr(strerror(EINVAL)));
  EXPECT_THAT(error.message(), HasSubstr(kMessage));
}

TEST(PosixErrorsTest, GetErrnoReturnsZeroOnNonPosixStatus) {
  EXPECT_THAT(GetErrno(OkStatus()), Eq(0));
  EXPECT_THAT(GetErrno(absl::InvalidArgumentError("foobar")), Eq(0));
}

TEST(PosixErrorsTest, GetErrnoReturnsErrnoFromPosixError) {
  EXPECT_THAT(GetErrno(PosixError(EINVAL)), Eq(EINVAL));
  EXPECT_THAT(GetErrno(PosixError(ENOMEM, "no more memory :(")), Eq(ENOMEM));
}

TEST(PosixErrorsTest, LastPosixErrorRepresentsErrno) {
  errno = EBADF;
  EXPECT_THAT(GetErrno(LastPosixError()), Eq(EBADF));
}

}  // namespace
}  // namespace asylo
