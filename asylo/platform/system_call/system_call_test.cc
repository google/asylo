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

#include "asylo/platform/system_call/system_call.h"

#include <fcntl.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <string>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/flags/flag.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "asylo/platform/primitives/primitive_status.h"
#include "asylo/platform/primitives/untrusted_primitives.h"
#include "asylo/platform/system_call/sysno.h"
#include "asylo/platform/system_call/type_conversions/types.h"
#include "asylo/platform/system_call/type_conversions/types_functions.h"
#include "asylo/platform/system_call/untrusted_invoke.h"
#include "asylo/test/util/test_flags.h"
#include "asylo/util/status_macros.h"

namespace asylo {
namespace system_call {
namespace {

using testing::Eq;
using testing::IsNull;
using testing::Not;
using testing::StrEq;

// A system call dispatch function which invokes a request message locally.
asylo::primitives::PrimitiveStatus SystemCallDispatcher(
    const uint8_t *request_buffer, size_t request_size,
    uint8_t **response_buffer, size_t *response_size) {
  primitives::Extent response;

  ASYLO_RETURN_IF_ERROR(
      UntrustedInvoke({request_buffer, request_size}, &response));

  *response_buffer = response.As<uint8_t>();
  *response_size = response.size();

  return asylo::primitives::PrimitiveStatus::OkStatus();
}

void error_handler(const char *message) {
  fprintf(stderr, "%s\n", message);
  fflush(stderr);
  abort();
}

// A system call dispatch function that return invalid response.
asylo::primitives::PrimitiveStatus InvalidResponseDispatcher(
    const uint8_t *request_buffer, size_t request_size,
    uint8_t **response_buffer, size_t *response_size) {
  primitives::Extent response;

  ASYLO_RETURN_IF_ERROR(
      UntrustedInvoke({request_buffer, request_size}, &response));

  *response_buffer = response.As<uint8_t>();
  *response_size = 1;

  return asylo::primitives::PrimitiveStatus::OkStatus();
}

// A system call dispatch function that always fails.
asylo::primitives::PrimitiveStatus AlwaysFailingDispatcher(
    const uint8_t *request_buffer, size_t request_size,
    uint8_t **response_buffer, size_t *response_size) {
  return {primitives::AbslStatusCode::kUnknown, "some random failure"};
}

// Invokes a system call with zero parameters.
TEST(SystemCallTest, ZeroParameterTest) {
  enc_set_dispatch_syscall(SystemCallDispatcher);
  EXPECT_THAT(enc_untrusted_syscall(SYS_getpid), Eq(getpid()));
  EXPECT_THAT(enc_untrusted_syscall(SYS_geteuid), Eq(geteuid()));
  EXPECT_THAT(enc_untrusted_syscall(SYS_getgid), Eq(getgid()));
  EXPECT_THAT(enc_untrusted_syscall(SYS_getegid), Eq(getegid()));
}

// Invokes a system call which copies a buffer out of the kernel.
TEST(SystemCallTest, BufferOutTest) {
  enc_set_dispatch_syscall(SystemCallDispatcher);
  char buffer_expected[2048];
  char buffer_actual[2048];
  EXPECT_THAT(getcwd(buffer_expected, sizeof(buffer_expected)), Not(IsNull()));

  enc_untrusted_syscall(SYS_getcwd, buffer_actual, sizeof(buffer_actual));
  EXPECT_THAT(&buffer_expected[0], StrEq(buffer_actual));
}

// Invokes a system call which takes a scalar input parameter.
TEST(SystemCallTest, ScalarInTest) {
  enc_set_dispatch_syscall(SystemCallDispatcher);
  std::string path =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/scalar_in_test.tmp");
  int fd = open(path.c_str(), O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);

  EXPECT_GE(fd, 0);

  // Check fd is an open file descriptor.
  EXPECT_NE(fcntl(fd, F_GETFD), -1);

  EXPECT_THAT(enc_untrusted_syscall(SYS_close, fd), Eq(0));

  // Check fd is a closed file descriptor.
  EXPECT_THAT(fcntl(fd, F_GETFD), Eq(-1));
}

// Invokes a system call which takes a string input parameter.
TEST(SystemCallTest, StringInTest) {
  enc_set_dispatch_syscall(SystemCallDispatcher);
  std::string path =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/string_in_test.tmp");
  int fd = enc_untrusted_syscall(SYS_open, path.c_str(),
                                 O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);

  // Check a valid file descriptor was returned.
  EXPECT_GE(fd, 0);

  // Check fd is an open file descriptor.
  EXPECT_NE(fcntl(fd, F_GETFD), -1);

  // Check that the file exists and has the correct permissions.
  EXPECT_THAT(access(path.c_str(), R_OK | W_OK), Eq(0));

  close(fd);
}

// Invokes a system call and passes null values to in and out pointer
// parameters.
TEST(SystemCallTest, NullBufferTest) {
  enc_set_dispatch_syscall(SystemCallDispatcher);
  std::string path =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/null_buffer_test.tmp");
  int fd = open(path.c_str(), O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);

  // Check a valid file descriptor was returned.
  EXPECT_GE(fd, 0);

  // Write zero bytes to the file.
  EXPECT_THAT(enc_untrusted_syscall(SYS_write, fd, nullptr, 0), Eq(0));

  // Read zero bytes from the file.
  EXPECT_THAT(enc_untrusted_syscall(SYS_read, fd, nullptr, 0), Eq(0));
}

// Invokes a system call which copies a fixed size struct out of the kernel.
TEST(SystemCallTest, FixedOutTest) {
  enc_set_dispatch_syscall(SystemCallDispatcher);

  // Call stat on the temporary file directory.
  std::string path = absl::GetFlag(FLAGS_test_tmpdir);
  struct stat stat_expected;
  struct stat stat_actual;
  int result_expected = stat(path.c_str(), &stat_expected);
  int result_actual =
      enc_untrusted_syscall(SYS_stat, path.c_str(), &stat_actual);

  EXPECT_THAT(result_expected, Eq(result_actual));
  EXPECT_THAT(memcmp(&stat_expected, &stat_actual, sizeof(struct stat)), Eq(0));
}

// Invokes a system call which copies a fixed size array out of the kernel.
TEST(SystemCallTest, ArrayOutTest) {
  enc_set_dispatch_syscall(SystemCallDispatcher);
  int fd[2];
  EXPECT_THAT(enc_untrusted_syscall(SYS_pipe2, &fd, 0), Eq(0));
  const char message[] = "testing one, two, three...";
  int message_len = strlen(message) + 1;
  EXPECT_THAT(write(fd[1], &message, message_len), Eq(message_len));
  char buf[1024];
  EXPECT_THAT(read(fd[0], buf, sizeof(buf)), Eq(message_len));
  EXPECT_THAT(buf, StrEq(message));
  close(fd[0]);
  close(fd[1]);
}

// Ensure that a header file containing system call numbers was generated
// correctly.
TEST(SystemCallTest, SysCallNumbers) {
  EXPECT_EQ(kSYS_read, 0);
  EXPECT_EQ(kSYS_getcwd, 79);
}

TEST(SystemCallTest, AbortIfNoCallbackFunctionSet) {
  enc_set_dispatch_syscall(nullptr);
  EXPECT_THAT(enc_is_syscall_dispatcher_set(), Eq(false));
  EXPECT_EXIT(enc_untrusted_syscall(SYS_getpid),
              ::testing::KilledBySignal(SIGABRT), ".*");
}

// Ensure that syscall aborts if callback function fails for any reason.
TEST(SystemCallTest, AbortOnCallbackFailure) {
  enc_set_dispatch_syscall(AlwaysFailingDispatcher);
  enc_set_error_handler(error_handler);
  EXPECT_EXIT(enc_untrusted_syscall(SYS_getpid),
              ::testing::KilledBySignal(SIGABRT), ".*");
}

// Ensure that syscall aborts if incorrect sysno provided.
TEST(SystemCallTest, AbortOnSerializationFailure) {
  enc_set_error_handler(error_handler);
  EXPECT_EXIT(enc_untrusted_syscall(1000000),
              ::testing::KilledBySignal(SIGABRT), ".*");
}

// Ensure that syscall aborts if incorrect response received.
TEST(SystemCallTest, AbortOnResponseMessageFailure) {
  enc_set_error_handler(error_handler);
  enc_set_dispatch_syscall(InvalidResponseDispatcher);
  EXPECT_EXIT(enc_untrusted_syscall(SYS_getpid),
              ::testing::KilledBySignal(SIGABRT), ".*");
}

// Ensure that errno is correctly set if system call fails.
TEST(SystemCallTest, Errnotest) {
  enc_set_dispatch_syscall(SystemCallDispatcher);
  int result = enc_untrusted_syscall(SYS_getcwd, nullptr, 1);
  EXPECT_THAT(result, Eq(-1));
  EXPECT_THAT(errno, Eq(ERANGE));
}

// Tests nanosleep return value and verifies conversions between klinux_timespec
// and timespec.
TEST(SystemCallTest, Nanosleeptest) {
  enc_set_dispatch_syscall(SystemCallDispatcher);

  struct timespec req, rem;
  struct kLinux_timespec klinux_req, klinux_rem;
  req.tv_sec = 1;
  req.tv_nsec = 500000000L;  // 0.5 sec

  // Deliberately set incorrect values for output.
  klinux_rem.kLinux_tv_sec = 100;
  klinux_rem.kLinux_tv_nsec = 1000L;

  TokLinuxtimespec(&req, &klinux_req);

  // If klinux_req interprets order of members incorrectly from req, test will
  // suspend for 15 years!
  EXPECT_THAT(enc_untrusted_syscall(SYS_nanosleep, &klinux_req, &klinux_rem),
              Eq(0));

  FromkLinuxtimespec(&klinux_rem, &rem);
  EXPECT_THAT(klinux_rem.kLinux_tv_sec, Eq(0));
  EXPECT_THAT(klinux_rem.kLinux_tv_nsec, Eq(0));
}

TEST(SystemCallTest, BoundedBufferByParamLenTest) {
  enc_set_dispatch_syscall(SystemCallDispatcher);

  struct pollfd fds_actual[2], fds_expected[2];
  // Watch stdin for input.
  fds_actual[0].fd = STDIN_FILENO;
  fds_actual[0].events = POLLIN;
  fds_actual[0].revents = -1;
  fds_expected[0].fd = STDIN_FILENO;
  fds_expected[0].events = POLLIN;
  // Watch stdout for ability to write.
  fds_actual[1].fd = STDOUT_FILENO;
  fds_actual[1].events = POLLOUT;
  fds_actual[1].revents = -1;
  fds_expected[1].fd = STDOUT_FILENO;
  fds_expected[1].events = POLLOUT;

  EXPECT_THAT(poll(fds_expected, 2, 1000), Not(Eq(-1)));
  EXPECT_THAT(enc_untrusted_syscall(SYS_poll, fds_actual, 2, 10000),
              Not(Eq(-1)));
  EXPECT_THAT(fds_actual[0].revents, Eq(fds_expected[0].revents));
  EXPECT_THAT(fds_actual[1].revents, Eq(fds_actual[1].revents));
}

}  // namespace
}  // namespace system_call
}  // namespace asylo
