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

#include <fcntl.h>
#include <sys/file.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/flags/flag.h"
#include "absl/strings/str_cat.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "asylo/platform/host_call/test/enclave_test_selectors.h"
#include "asylo/platform/host_call/untrusted/host_call_handlers_initializer.h"
#include "asylo/platform/primitives/extent.h"
#include "asylo/platform/primitives/test/test_backend.h"
#include "asylo/platform/primitives/untrusted_primitives.h"
#include "asylo/platform/primitives/util/message.h"
#include "asylo/platform/storage/utils/fd_closer.h"
#include "asylo/platform/system_call/type_conversions/types_functions.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/test/util/test_flags.h"

using ::testing::Eq;
using ::testing::Gt;
using ::testing::Not;
using ::testing::SizeIs;
using ::testing::StrEq;

namespace asylo {
namespace host_call {
namespace {

class HostCallTest : public ::testing::Test {
 protected:
  // Loads the enclave. The function uses the factory method
  // |primitives::test::TestBackend::Get()| for loading the enclave, and the
  // type of backend (sim, remote, sgx etc.) loaded depends upon the type of
  // library included with the build that implements the abstract factory class
  // |TestBackend|.
  std::shared_ptr<primitives::Client> LoadTestEnclaveOrDie(
      StatusOr<std::unique_ptr<primitives::Client::ExitCallProvider>>
          exit_call_provider = GetHostCallHandlersMapping()) {
    ASYLO_EXPECT_OK(exit_call_provider);
    const auto client =
        primitives::test::TestBackend::Get()->LoadTestEnclaveOrDie(
            /*enclave_name=*/"host_call_test_enclave",
            std::move(exit_call_provider.ValueOrDie()));

    return client;
  }

  void SetUp() override {
    client_ = LoadTestEnclaveOrDie();
    ASSERT_FALSE(client_->IsClosed());
  }

  void TearDown() override {
    client_->Destroy();
    EXPECT_TRUE(client_->IsClosed());
  }

  std::shared_ptr<primitives::Client> client_;
};

// Tests enc_untrusted_access() by creating a file and calling
// enc_untrusted_access() from inside the enclave and verifying its return
// value.
TEST_F(HostCallTest, TestAccess) {
  std::string path =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/test_file.tmp");
  int fd = creat(path.c_str(), S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  ASSERT_GE(fd, 0);

  primitives::MessageWriter in;
  in.Push(path);
  in.Push<int>(/*value=mode=*/R_OK | W_OK);

  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestAccess, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // should only contain return value.
  EXPECT_THAT(out.next<int>(), access(path.c_str(), R_OK | W_OK));
}

// Tests enc_untrusted_access() against a non-existent path.
TEST_F(HostCallTest, TestAccessNonExistentPath) {
  const char *path = "illegal_path";

  primitives::MessageWriter in;
  in.Push(primitives::Extent{path, strlen(path) + 1});
  in.Push<int>(/*value=mode=*/F_OK);

  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestAccess, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // should only contain return value.
  EXPECT_THAT(out.next<int>(), access(path, F_OK));
}

// Tests enc_untrusted_chmod() by creating a file with multiple mode bits
// and calling enc_untrusted_chmod() from inside the enclave to remove one mode
// bit, and verifying that the expected mode gets removed from the file.
TEST_F(HostCallTest, TestChmod) {
  std::string path =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/test_file.tmp");

  // Make sure the file does not exist.
  if (access(path.c_str(), F_OK) == 0) {
    EXPECT_NE(unlink(path.c_str()), -1);
  }

  int fd = creat(path.c_str(), DEFFILEMODE);
  platform::storage::FdCloser fd_closer(fd);

  ASSERT_GE(fd, 0);
  struct stat sb;
  ASSERT_NE(stat(path.c_str(), &sb), -1);
  ASSERT_NE((sb.st_mode & S_IRUSR), 0);
  primitives::MessageWriter in;
  in.Push(path);
  in.Push<mode_t>(/*value=mode=*/DEFFILEMODE ^ S_IRUSR);

  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestChmod, &in, &out));
  ASSERT_THAT(out, SizeIs(1));
  ASSERT_THAT(out.next<int>(), Eq(0));
  ASSERT_NE(stat(path.c_str(), &sb), -1);
  ASSERT_EQ((sb.st_mode & S_IRUSR), 0);
  EXPECT_NE(unlink(path.c_str()), -1);
}

// Tests enc_untrusted_chmod() against a non-existent path.
TEST_F(HostCallTest, TestChmodNonExistentFile) {
  const char *path = "illegal_path";

  primitives::MessageWriter in;
  in.Push(primitives::Extent{path, strlen(path) + 1});
  in.Push<mode_t>(/*value=mode=*/S_IWUSR);

  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestChmod, &in, &out));
  ASSERT_THAT(out, SizeIs(1));
  EXPECT_THAT(out.next<int>(), Eq(access(path, F_OK)));
}

// Tests enc_untrusted_close() by creating a file to be closed and calling
// enc_untrusted_close() from inside the enclave to close the file handle.
TEST_F(HostCallTest, TestClose) {
  std::string path =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/test_file.tmp");
  int fd = open(path.c_str(), O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
  platform::storage::FdCloser fd_closer(fd);
  ASSERT_GE(fd, 0);
  ASSERT_NE(fcntl(fd, F_GETFD), -1);  // check fd is an open file descriptor.

  primitives::MessageWriter in;
  in.Push<int>(fd);

  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestClose, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // should only contain return value.
  EXPECT_THAT(out.next<int>(), Eq(0));
}

// Tries closing a non-existent file handle by calling enc_untrusted_close()
// from inside the enclave.
TEST_F(HostCallTest, TestCloseNonExistentFile) {
  primitives::MessageWriter in;
  in.Push<int>(/*value=fd=*/123456);

  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestClose, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // should only contain return value.
  EXPECT_THAT(out.next<int>(), Eq(-1));
}

// Tests enc_untrusted_fchmod() by creating a file with multiple mode bits
// and calling enc_untrusted_fchmod() from inside the enclave to remove one mode
// bit, and verifying that the expected mode gets removed from the file.
TEST_F(HostCallTest, TestFchmod) {
  std::string path =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/test_file.tmp");

  // Make sure the file does not exist.
  if (access(path.c_str(), F_OK) == 0) {
    EXPECT_NE(unlink(path.c_str()), -1);
  }

  int fd = creat(path.c_str(), DEFFILEMODE);
  platform::storage::FdCloser fd_closer(fd);

  ASSERT_GE(fd, 0);
  struct stat sb;
  ASSERT_NE(stat(path.c_str(), &sb), -1);
  ASSERT_NE((sb.st_mode & S_IRUSR), 0);
  primitives::MessageWriter in;
  in.Push<int>(fd);
  in.Push<mode_t>(/*value=mode=*/DEFFILEMODE ^ S_IRUSR);

  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestFchmod, &in, &out));
  ASSERT_THAT(out, SizeIs(1));
  ASSERT_THAT(out.next<int>(), Eq(0));
  ASSERT_NE(stat(path.c_str(), &sb), -1);
  ASSERT_EQ((sb.st_mode & S_IRUSR), 0);
  EXPECT_NE(unlink(path.c_str()), -1);
}

// Tests enc_untrusted_fchmod() against a non-existent file descriptor.
TEST_F(HostCallTest, TestFchmodNonExistentFile) {
  primitives::MessageWriter in;
  in.Push<int>(/*value=fd=*/-1);
  in.Push<mode_t>(/*value=mode=*/S_IWUSR);

  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestFchmod, &in, &out));
  ASSERT_THAT(out, SizeIs(1));
  EXPECT_THAT(out.next<int>(), Eq(-1));
}

// Tests enc_untrusted_getpid() by calling it from inside the enclave and
// verifying its return value against pid obtained from native system call.
TEST_F(HostCallTest, TestGetpid) {
  primitives::MessageWriter in;
  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestGetPid, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // should only contain return value.
  EXPECT_THAT(out.next<pid_t>(), Eq(getpid()));
}

// Tests enc_untrusted_getppid() by calling it from inside the enclave and
// verifying its return value against ppid obtained from native system call.
TEST_F(HostCallTest, TestGetPpid) {
  primitives::MessageWriter in;
  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestGetPpid, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // should only contain return value.
  EXPECT_THAT(out.next<pid_t>(), Eq(getppid()));
}

// Tests enc_untrusted_setsid() by calling it from inside the enclave and
// verifying its return value against sid obtained from getsid(0), which
// gets the sid of the current process.
TEST_F(HostCallTest, TestSetSid) {
  primitives::MessageWriter in;
  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestSetSid, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // should only contain return value.
  EXPECT_THAT(out.next<pid_t>(), Eq(getsid(0)));
}

// Tests enc_untrusted_kill() by forking the current process and putting the
// child process to sleep, then calling enc_untrusted_kill() from inside the
// enclave to kill the child process.
TEST_F(HostCallTest, TestKill) {
  pid_t pid = fork();  // child process to be killed
  if (pid == 0) {
    execl("sleep", "10", nullptr);
    FAIL();
  }

  primitives::MessageWriter in;
  in.Push<pid_t>(/*value=pid=*/pid);
  in.Push<int>(/*value=sig=*/SIGABRT);

  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestKill, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // should only contain return value.
  EXPECT_THAT(out.next<int>(), Eq(0));
}

// Tests enc_untrusted_link() by creating a file (|oldpath|) and calling
// enc_untrusted_link() from inside the enclave to link it to |newpath|, then
// verifying that |newpath| is indeed accessible.
TEST_F(HostCallTest, TestLink) {
  std::string oldpath =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/old_name.tmp");
  std::string newpath =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/new_name.tmp");

  int fd = open(oldpath.c_str(), O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
  platform::storage::FdCloser fd_closer(fd);
  ASSERT_GE(fd, 0);
  ASSERT_NE(access(oldpath.c_str(), F_OK), -1);

  primitives::MessageWriter in;
  in.Push(oldpath);
  in.Push(newpath);

  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestLink, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // should only contain return value.

  EXPECT_NE(access(newpath.c_str(), F_OK), -1);
  EXPECT_NE(access(oldpath.c_str(), F_OK), -1);
}

// Tests enc_untrusted_lseek() by creating a file and calling
// enc_untrusted_leek() from inside the enclave and verify the return value for
// the provided offset.
TEST_F(HostCallTest, TestLseek) {
  std::string path =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/test_file.tmp");

  int fd = open(path.c_str(), O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
  platform::storage::FdCloser fd_closer(fd);
  ASSERT_GE(fd, 0);
  ASSERT_NE(access(path.c_str(), F_OK), -1);
  EXPECT_THAT(write(fd, "hello", 5), Eq(5));

  primitives::MessageWriter in;
  in.Push<int>(/*value=fd=*/fd);
  in.Push<off_t>(/*value=offset=*/2);
  in.Push<int>(/*value=whence=*/SEEK_SET);

  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestLseek, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // should only contain the return value.
  EXPECT_THAT(out.next<off_t>(), Eq(2));
}

TEST_F(HostCallTest, TestLseekBadReturn) {
  std::string path =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/test_file.tmp");

  int fd = open(path.c_str(), O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
  platform::storage::FdCloser fd_closer(fd);
  ASSERT_GE(fd, 0);
  ASSERT_NE(access(path.c_str(), F_OK), -1);
  EXPECT_THAT(write(fd, "hello", 5), Eq(5));

  primitives::MessageWriter in;
  in.Push<int>(/*value=fd=*/fd);
  in.Push<off_t>(/*value=offset=*/0);
  in.Push<int>(/*value=whence=*/1000);

  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestLseek, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // should only contain the return value.
  EXPECT_THAT(out.next<off_t>(), Eq(-1));
}

// Tests enc_untrusted_mkdir() by calling it from inside the enclave and
// verifying that the directory created indeed exists.
TEST_F(HostCallTest, TestMkdir) {
  std::string path =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/dir_to_make");

  primitives::MessageWriter in;
  in.Push(path);
  in.Push<mode_t>(/*value=mode=*/0777);

  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestMkdir, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // should only contain the return value.
  EXPECT_THAT(out.next<int>(), Eq(0));

  struct stat sb;
  EXPECT_TRUE(stat(path.c_str(), &sb) == 0 && S_ISDIR(sb.st_mode));
}

TEST_F(HostCallTest, TestMkdirNonExistentPath) {
  std::string path = absl::StrCat("/non-existent-path/dir_to_make");

  primitives::MessageWriter in;
  in.Push(path);
  in.Push<mode_t>(/*value=mode=*/0777);

  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestMkdir, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // should only contain the return value.
  EXPECT_THAT(out.next<int>(), Eq(-1));
}

// Tests enc_untrusted_open() by using it to create a new file from inside the
// enclave and verifying that it exists.
TEST_F(HostCallTest, TestOpen) {
  std::string path =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/test_file.tmp");

  primitives::MessageWriter in;
  in.Push(path);
  in.Push<int>(/*value=flags=*/O_RDWR | O_CREAT | O_TRUNC);
  in.Push<mode_t>(/*value=mode=*/S_IRUSR | S_IWUSR);

  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestOpen, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // should only contain the return value.
  EXPECT_THAT(out.next<int>(), Gt(0));
  EXPECT_NE(access(path.c_str(), F_OK), -1);
}

// Test enc_untrusted_open() by opening an existing file (omit passing mode when
// opening the file).
TEST_F(HostCallTest, TestOpenExistingFile) {
  std::string path =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/test_file.tmp");

  creat(path.c_str(), S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  ASSERT_NE(access(path.c_str(), F_OK), -1);

  primitives::MessageWriter in;
  in.Push(path);
  in.Push<int>(/*value=flags*/ O_RDWR | O_CREAT | O_TRUNC);

  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestOpen, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // should only contain the return value.
  EXPECT_THAT(out.next<int>(), Gt(0));
  EXPECT_NE(access(path.c_str(), F_OK), -1);
}

// Tests enc_untrusted_unlink() by deleting an existing file on the untrusted
// side from inside the enclave using the host call.
TEST_F(HostCallTest, TestUnlink) {
  std::string path =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/test_file.tmp");
  creat(path.c_str(), S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  ASSERT_NE(access(path.c_str(), F_OK), -1);

  primitives::MessageWriter in;
  in.Push(path);

  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestUnlink, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // should only contain the return value.
  EXPECT_THAT(out.next<int>(), Eq(0));
  EXPECT_THAT(access(path.c_str(), F_OK), Eq(-1));
}

TEST_F(HostCallTest, TestUnlinkNonExistingFile) {
  std::string path("obviously-illegal-file.tmp");
  ASSERT_THAT(access(path.c_str(), F_OK), Eq(-1));

  primitives::MessageWriter in;
  in.Push(path);

  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestUnlink, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // should only contain the return value.
  EXPECT_THAT(out.next<int>(), Eq(-1));
}

// Tests enc_untrusted_getuid() by making the host call from inside the enclave
// and comparing the result with the value obtained from native getuid().
TEST_F(HostCallTest, TestGetuid) {
  primitives::MessageWriter in;
  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestGetUid, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // should only contain the return value.
  EXPECT_THAT(out.next<uid_t>(), Eq(getuid()));
}

// Tests enc_untrusted_umask() by calling it from inside the enclave to mask
// certain permission bits(S_IWGRP | S_IWOTH) and verifying newly created
// directory or file will not have masked permission.
TEST_F(HostCallTest, TestUmask) {
  primitives::MessageWriter in;
  in.Push<int>(/*value=mask=*/S_IWGRP | S_IWOTH);
  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestUmask, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // should only contain return value.
  mode_t default_mode = out.next<mode_t>();

  struct stat sb;
  std::string path =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/dir_to_make");

  // Make sure the directory does not exist.
  if (access(path.c_str(), F_OK) == 0) {
    EXPECT_NE(rmdir(path.c_str()), -1);
  }

  EXPECT_NE(mkdir(path.c_str(), DEFFILEMODE), -1);
  EXPECT_TRUE(stat(path.c_str(), &sb) == 0 && S_ISDIR(sb.st_mode));
  EXPECT_TRUE(!(sb.st_mode & S_IWGRP) && !(sb.st_mode & S_IWOTH));
  EXPECT_NE(rmdir(path.c_str()), -1);

  path = absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/test_file.tmp");
  // Make sure the file does not exist.
  if (access(path.c_str(), F_OK) == 0) {
    EXPECT_NE(unlink(path.c_str()), -1);
  }

  int fd = creat(path.c_str(), DEFFILEMODE);
  ASSERT_GE(fd, 0);
  EXPECT_NE(access(path.c_str(), F_OK), -1);
  EXPECT_TRUE(stat(path.c_str(), &sb) == 0 && S_ISREG(sb.st_mode));
  EXPECT_TRUE(!(sb.st_mode & S_IWGRP) && !(sb.st_mode & S_IWOTH));
  EXPECT_NE(unlink(path.c_str()), -1);

  primitives::MessageWriter in2;
  in2.Push<int>(/*value=mask=*/default_mode);
  primitives::MessageReader out2;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestUmask, &in2, &out2));
  ASSERT_THAT(out2, SizeIs(1));
  ASSERT_THAT(out2.next<mode_t>(), Eq(S_IWGRP | S_IWOTH));
}

// Tests enc_untrusted_getgid() by making the host call from inside the enclave
// and comparing the result with the value obtained from native getgid().
TEST_F(HostCallTest, TestGetgid) {
  primitives::MessageWriter in;
  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestGetGid, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // should only contain the return value.
  EXPECT_THAT(out.next<gid_t>(), Eq(getgid()));
}

// Tests enc_untrusted_geteuid() by making the host call from inside the enclave
// and comparing the result with the value obtained from native geteuid().
TEST_F(HostCallTest, TestGetEuid) {
  primitives::MessageWriter in;
  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestGetEuid, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // should only contain the return value.
  EXPECT_THAT(out.next<uid_t>(), Eq(geteuid()));
}

// Tests enc_untrusted_getegid() by making the host call from inside the enclave
// and comparing the result with the value obtained from native getegid().
TEST_F(HostCallTest, TestGetEgid) {
  primitives::MessageWriter in;
  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestGetEgid, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // should only contain the return value.
  EXPECT_THAT(out.next<gid_t>(), Eq(getegid()));
}

// Tests enc_untrusted_rename() by making a host call from inside the enclave
// and verifying that the file is indeed renamed on the untrusted side.
TEST_F(HostCallTest, TestRename) {
  std::string oldpath =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/oldname.tmp");
  std::string newpath =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/newname.tmp");

  creat(oldpath.c_str(), S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  ASSERT_NE(access(oldpath.c_str(), F_OK), -1);

  primitives::MessageWriter in;
  in.Push(oldpath);
  in.Push(newpath);

  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestRename, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // should only contain the return value.
  EXPECT_THAT(out.next<int>(), Eq(0));

  EXPECT_THAT(access(oldpath.c_str(), F_OK), Eq(-1));
  EXPECT_NE(access(newpath.c_str(), F_OK), -1);
}

// Tests enc_untrusted_read() by making a host call from inside the enclave and
// verifying that what is read on untrusted side is identical to what is read
// from inside the enclave for a provided file.
TEST_F(HostCallTest, TestRead) {
  std::string test_file =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/test_file.tmp");

  int fd =
      open(test_file.c_str(), O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
  platform::storage::FdCloser fd_closer(fd);
  ASSERT_GE(fd, 0);
  ASSERT_NE(access(test_file.c_str(), F_OK), -1);

  std::string expected_content = "this is what's being read!";
  ASSERT_THAT(
      write(fd, expected_content.c_str(), expected_content.length() + 1),
      Eq(expected_content.length() + 1));
  ASSERT_THAT(lseek(fd, 0, SEEK_SET), Eq(0));

  // We do not push the empty read buffer on the stack since a read buffer would
  // need to be created inside the enclave anyway.
  primitives::MessageWriter in;
  in.Push<int>(/*value=fd=*/fd);
  in.Push<size_t>(/*value=count=*/expected_content.length() + 1);
  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestRead, &in, &out));
  ASSERT_THAT(out, SizeIs(2));  // Contains return value and buffer.
  EXPECT_THAT(out.next<ssize_t>(), Eq(expected_content.length() + 1));
  EXPECT_THAT(out.next().As<char>(), StrEq(expected_content));
}

// Tests enc_untrusted_write() by making a host call from inside the enclave to
// write to a file, and verifying that the content read from the file on the
// host matches it.
TEST_F(HostCallTest, TestWrite) {
  std::string test_file =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/test_file.tmp");

  int fd =
      open(test_file.c_str(), O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
  platform::storage::FdCloser fd_closer(fd);
  ASSERT_GE(fd, 0);
  ASSERT_NE(access(test_file.c_str(), F_OK), -1);

  std::string write_buf = "text to be written";
  primitives::MessageWriter in;
  in.Push<int>(/*value=fd=*/fd);
  in.PushByCopy(primitives::Extent{write_buf.c_str(), write_buf.length() + 1});
  in.Push<size_t>(/*value=count=*/write_buf.length() + 1);

  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestWrite, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // Should only contain return value.
  EXPECT_THAT(out.next<ssize_t>(), Eq(write_buf.length() + 1));

  ASSERT_THAT(lseek(fd, 0, SEEK_SET), Eq(0));
  char read_buf[20];
  EXPECT_THAT(read(fd, read_buf, write_buf.length() + 1),
              Eq(write_buf.length() + 1));
  EXPECT_THAT(read_buf, StrEq(write_buf));
}

// Tests enc_untrusted_symlink() by attempting to create a symlink from inside
// the enclave and verifying that the created symlink is accessible.
TEST_F(HostCallTest, TestSymlink) {
  std::string test_file =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/test_file.tmp");
  std::string target =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/target.tmp");

  int fd =
      open(test_file.c_str(), O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
  platform::storage::FdCloser fd_closer(fd);
  ASSERT_GE(fd, 0);
  ASSERT_NE(access(test_file.c_str(), F_OK), -1);

  primitives::MessageWriter in;
  in.Push(test_file);
  in.Push(target);

  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestSymlink, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // Should only contain return value.
  EXPECT_THAT(out.next<int>(), Eq(0));
  EXPECT_NE(access(target.c_str(), F_OK), -1);
}

// Tests enc_untrusted_readlink() by making a call from inside the enclave and
// verifying that the returned target path is same as that obtained from calling
// readlink() natively on the untrusted side.
TEST_F(HostCallTest, TestReadlink) {
  std::string test_file =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/test_file.tmp");
  std::string sym_file =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/test_sym_file.tmp");

  int fd =
      open(test_file.c_str(), O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
  platform::storage::FdCloser fd_closer(fd);
  ASSERT_GE(fd, 0);
  ASSERT_NE(access(test_file.c_str(), F_OK), -1);

  // Create a symlink to be read by readlink.
  ASSERT_THAT(symlink(test_file.c_str(), sym_file.c_str()), Eq(0));

  primitives::MessageWriter in;
  in.Push(sym_file);

  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestReadLink, &in, &out));

  char buf_expected[PATH_MAX];
  ssize_t len_expected =
      readlink(sym_file.c_str(), buf_expected, sizeof(buf_expected) - 1);
  buf_expected[len_expected] = '\0';

  ASSERT_THAT(out, SizeIs(2));  // Return value and the buffer.
  EXPECT_THAT(out.next<ssize_t>(), Eq(len_expected));
  EXPECT_THAT(out.next().As<char>(), StrEq(buf_expected));
}

}  // namespace
}  // namespace host_call
}  // namespace asylo
