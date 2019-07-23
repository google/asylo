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
#include <netinet/in.h>
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
#include "asylo/enclave_manager.h"
#include "asylo/platform/host_call/test/enclave_test_selectors.h"
#include "asylo/platform/host_call/untrusted/host_call_handlers_initializer.h"
#include "asylo/platform/primitives/extent.h"
#include "asylo/platform/primitives/test/test_backend.h"
#include "asylo/platform/primitives/untrusted_primitives.h"
#include "asylo/platform/primitives/util/message.h"
#include "asylo/platform/storage/utils/fd_closer.h"
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
    EnclaveManager::Configure(EnclaveManagerOptions());
    client_ = LoadTestEnclaveOrDie();
    ASSERT_FALSE(client_->IsClosed());
  }

  void TearDown() override {
    client_->Destroy();
    EXPECT_TRUE(client_->IsClosed());
  }

  std::shared_ptr<primitives::Client> client_;
};

// Keep this test always the first.
// Moving it to the later position in the file causes the tests to hang up
// in some backends.
TEST_F(HostCallTest, TestSend) {
  // Create a local socket and ensure that it is valid (fd > 0).
  int socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  EXPECT_THAT(socket_fd, Gt(0));

  std::string sockpath =
      absl::StrCat("/tmp/", absl::ToUnixNanos(absl::Now()), ".sock");

  // Create a local socket address and bind the socket to it.
  sockaddr_un sa = {};
  sa.sun_family = AF_UNIX;
  strncpy(&sa.sun_path[0], sockpath.c_str(), sizeof(sa.sun_path) - 1);
  ASSERT_THAT(
      bind(socket_fd, reinterpret_cast<struct sockaddr *>(&sa), sizeof(sa)),
      Not(Eq(-1)));

  ASSERT_THAT(listen(socket_fd, 8), Not(Eq(-1)));

  // Create another local socket and ensures that it is valid (fd > 0).
  int client_sock = socket(AF_UNIX, SOCK_STREAM, 0);
  EXPECT_THAT(client_sock, Gt(0));

  // Attempt to connect the new socket to the local address. This call
  // will only succeed if the listen is successful.
  ASSERT_THAT(connect(client_sock, reinterpret_cast<struct sockaddr *>(&sa),
                      sizeof(sa)),
              Not(Eq(-1)));

  int connection_socket = accept(socket_fd, nullptr, nullptr);

  std::string msg = "Hello world!";

  primitives::MessageWriter in;
  in.Push<int>(/*value=sockfd=*/connection_socket);
  in.Push(/*value=buf*/ msg);
  in.Push<size_t>(/*value=len*/ msg.length());
  in.Push<int>(/*value=flags*/ 0);
  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestSend, &in, &out));
  ASSERT_THAT(out, SizeIs(1));
  EXPECT_THAT(out.next<int>(), Eq(msg.length()));

  close(socket_fd);
  close(client_sock);
  close(connection_socket);
}

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

// Tests enc_untrusted_truncate() by making a call from inside the enclave and
// verifying that the file is indeed truncated on the untrusted side by reading
// the file.
TEST_F(HostCallTest, TestTruncate) {
  std::string test_file =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/test_file.tmp");
  int fd =
      open(test_file.c_str(), O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
  platform::storage::FdCloser fd_closer(fd);
  ASSERT_GE(fd, 0);
  ASSERT_NE(access(test_file.c_str(), F_OK), -1);

  // Write something to the file.
  std::string file_content = "some random content.";
  ASSERT_THAT(write(fd, file_content.c_str(), file_content.length() + 1),
              Eq(file_content.length() + 1));

  primitives::MessageWriter in;
  constexpr int kTruncLen = 5;
  in.Push(test_file);
  in.Push<off_t>(/*value=length=*/kTruncLen);

  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestTruncate, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // Should only contain return value.
  EXPECT_THAT(out.next<int>(), 0);

  // Verify contents of the file by reading it.
  char read_buf[10];
  ASSERT_THAT(lseek(fd, 0, SEEK_SET), Eq(0));
  EXPECT_THAT(read(fd, read_buf, 10), Eq(kTruncLen));
  read_buf[kTruncLen] = '\0';
  EXPECT_THAT(read_buf, StrEq(file_content.substr(0, kTruncLen)));
}

// Tests enc_untrusted_ftruncate() by making a call from inside the enclave and
// verifying that the file is indeed truncated on the untrusted side by reading
// the file.
TEST_F(HostCallTest, TestFTruncate) {
  std::string test_file =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/test_file.tmp");
  int fd =
      open(test_file.c_str(), O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
  platform::storage::FdCloser fd_closer(fd);
  ASSERT_GE(fd, 0);
  ASSERT_NE(access(test_file.c_str(), F_OK), -1);

  // Write something to the file.
  std::string file_content = "some random content.";
  ASSERT_THAT(write(fd, file_content.c_str(), file_content.length() + 1),
              Eq(file_content.length() + 1));

  primitives::MessageWriter in2;
  constexpr int kTruncLen = 5;
  in2.Push<int>(/*value=fd=*/fd);
  in2.Push<off_t>(/*value=length=*/kTruncLen);

  primitives::MessageReader out2;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestFTruncate, &in2, &out2));
  ASSERT_THAT(out2, SizeIs(1));  // Should only contain return value.
  EXPECT_THAT(out2.next<int>(), 0);

  // Verify contents of the file by reading it.
  char read_buf[10];
  ASSERT_THAT(lseek(fd, 0, SEEK_SET), Eq(0));
  EXPECT_THAT(read(fd, read_buf, 10), Eq(kTruncLen));
  read_buf[kTruncLen] = '\0';
  EXPECT_THAT(read_buf, StrEq(file_content.substr(0, kTruncLen)));

  // Force an error and verify that the return value is non-zero.
  primitives::MessageWriter in3;
  in3.Push<int>(/*value=fd=*/-1);
  in3.Push<off_t>(/*value=length=*/kTruncLen);

  primitives::MessageReader out3;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestFTruncate, &in3, &out3));
  ASSERT_THAT(out3, SizeIs(1));  // Should only contain return value.
  EXPECT_THAT(out3.next<int>(), -1);
}

// Tests enc_untrusted_rmdir() by making a call from inside the enclave and
// verifying that the directory is indeed deleted.
TEST_F(HostCallTest, TestRmdir) {
  std::string dir_to_del =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/dir_to_del");
  ASSERT_THAT(mkdir(dir_to_del.c_str(), O_CREAT | O_RDWR), Eq(0));

  primitives::MessageWriter in;
  in.Push(dir_to_del);

  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestRmdir, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // Should only contain return value.
  EXPECT_THAT(out.next<int>(), Eq(0));

  // Verify that the directory does not exist.
  struct stat sb;
  EXPECT_FALSE(stat(dir_to_del.c_str(), &sb) == 0 && S_ISDIR(sb.st_mode));
}

// Tests enc_untrusted_socket() by trying to obtain a valid (greater than 0)
// socket file descriptor when the method is called from inside the enclave.
TEST_F(HostCallTest, TestSocket) {
  primitives::MessageWriter in;
  // Setup bidirectional IPv6 socket.
  in.Push<int>(/*value=domain=*/AF_INET6);
  in.Push<int>(/*value=type=*/SOCK_STREAM);
  in.Push<int>(/*value=protocol=*/0);

  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestSocket, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // Should only contain return value.
  EXPECT_THAT(out.next<int>(), Gt(0));

  // Setup socket for local bidirectional communication between two processes on
  // the host.
  primitives::MessageWriter in2;
  in2.Push<int>(/*value=domain=*/AF_UNIX);
  in2.Push<int>(/*value=type=*/SOCK_STREAM);
  in2.Push<int>(/*value=protocol=*/0);

  primitives::MessageReader out2;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestSocket, &in2, &out2));
  ASSERT_THAT(out2, SizeIs(1));  // Should only contain return value.
  EXPECT_THAT(out2.next<int>(), Gt(0));
}

// Tests enc_untrusted_listen() by creating a local socket and calling
// enc_untrusted_listen() on the socket. Checks to make sure that listen returns
// 0, then creates a client socket and attempts to connect to the address of
// the local socket. The connect attempt will only succeed if the listen call
// is successful.
TEST_F(HostCallTest, TestListen) {
  // Create a local socket and ensure that it is valid (fd > 0).
  int socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  EXPECT_THAT(socket_fd, Gt(0));

  std::string sockpath =
      absl::StrCat("/tmp/", absl::ToUnixNanos(absl::Now()), ".sock");

  // Create a local socket address and bind the socket to it.
  sockaddr_un sa = {};
  sa.sun_family = AF_UNIX;
  strncpy(&sa.sun_path[0], sockpath.c_str(), sizeof(sa.sun_path) - 1);
  EXPECT_THAT(
      bind(socket_fd, reinterpret_cast<struct sockaddr *>(&sa), sizeof(sa)),
      Not(Eq(-1)));

  // Call listen on the bound local socket.
  primitives::MessageWriter in;
  in.Push<int>(/*value=sockfd=*/socket_fd);
  in.Push<int>(/*value=backlog=*/8);

  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestListen, &in, &out));
  ASSERT_THAT(out, SizeIs(1));
  EXPECT_THAT(out.next<int>(), Eq(0));

  // Create another local socket and ensures that it is valid (fd > 0).
  int client_sock = socket(AF_UNIX, SOCK_STREAM, 0);
  EXPECT_THAT(client_sock, Gt(0));

  // Attempt to connect the new socket to the local address. This call
  // will only succeed if the listen is successful.
  EXPECT_THAT(connect(client_sock, reinterpret_cast<struct sockaddr *>(&sa),
                      sizeof(sa)),
              Not(Eq(-1)));

  close(socket_fd);
  close(client_sock);
}

TEST_F(HostCallTest, TestShutdown) {
  // Create a local socket and ensure that it is valid (fd > 0).
  int socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  EXPECT_THAT(socket_fd, Gt(0));

  std::string sockpath =
      absl::StrCat("/tmp/", absl::ToUnixNanos(absl::Now()), ".sock");

  // Create a local socket address and bind the socket to it.
  sockaddr_un sa = {};
  sa.sun_family = AF_UNIX;
  strncpy(&sa.sun_path[0], sockpath.c_str(), sizeof(sa.sun_path) - 1);
  EXPECT_THAT(
      bind(socket_fd, reinterpret_cast<struct sockaddr *>(&sa), sizeof(sa)),
      Not(Eq(-1)));

  // Call shutdown on the bound local socket.
  primitives::MessageWriter in;
  in.Push<int>(/*value=sockfd=*/socket_fd);
  in.Push<int>(/*value=how=*/SHUT_RDWR);

  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestShutdown, &in, &out));
  ASSERT_THAT(out, SizeIs(1));
  EXPECT_THAT(out.next<int>(), Eq(0));

  std::string msg = "Hello world!";
  EXPECT_THAT(send(socket_fd, (void *)msg.c_str(), msg.length(), 0), Eq(-1));

  close(socket_fd);
}

// Tests enc_untrusted_fcntl() by performing various file control operations
// from inside the enclave and validating the return valueswith those obtained
// from native host call to fcntl().
TEST_F(HostCallTest, TestFcntl) {
  std::string test_file =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/test_file.tmp");
  int fd =
      open(test_file.c_str(), O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
  platform::storage::FdCloser fd_closer(fd);
  ASSERT_GE(fd, 0);
  ASSERT_NE(access(test_file.c_str(), F_OK), -1);

  // Get file flags and compare to those obtained from native fcntl() syscall.
  primitives::MessageWriter in;
  in.Push<int>(/*value=fd=*/fd);
  in.Push<int>(/*value=cmd=*/F_GETFL);
  in.Push<int>(/*value=arg=*/0);
  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestFcntl, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // Should only contain return value.

  int klinux_fcntl_return = fcntl(fd, F_GETFL, 0);
  EXPECT_THAT(out.next<int>(), Eq(klinux_fcntl_return & 07777));

  // Turn on one or more of the file status flags for a descriptor.
  int flags_to_set = O_APPEND | O_NONBLOCK | O_RDONLY;
  primitives::MessageWriter in2;
  in2.Push<int>(/*value=fd=*/fd);
  in2.Push<int>(/*value=cmd=*/F_SETFL);
  in2.Push<int>(/*value=arg=*/flags_to_set);
  primitives::MessageReader out2;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestFcntl, &in2, &out2));
  ASSERT_THAT(out2, SizeIs(1));  // Should only contain return value.

  klinux_fcntl_return = fcntl(fd, F_SETFL, flags_to_set);
  EXPECT_THAT(out2.next<int>(), Eq(klinux_fcntl_return));
}

TEST_F(HostCallTest, TestFcntlInvalidCmd) {
  primitives::MessageWriter in;
  in.Push<int>(/*value=fd=*/0);
  in.Push<int>(/*value=cmd=*/10000000);
  in.Push<int>(/*value=arg=*/0);
  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestFcntl, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // Should only contain return value.
  EXPECT_THAT(out.next<int>(), Eq(-1));
}

// Tests enc_untrusted_chown() by attempting to change file ownership by making
// the host call from inside the enclave and verifying the return value.
TEST_F(HostCallTest, TestChown) {
  std::string test_file =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/test_file.tmp");
  int fd =
      open(test_file.c_str(), O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
  platform::storage::FdCloser fd_closer(fd);
  ASSERT_GE(fd, 0);
  ASSERT_NE(access(test_file.c_str(), F_OK), -1);

  primitives::MessageWriter in;
  in.Push(test_file);
  in.Push<uid_t>(/*value=owner=*/getuid());
  in.Push<gid_t>(/*value=group=*/getgid());

  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestChown, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // Should only contain return value.
  EXPECT_THAT(out.next<int>(), Eq(0));
}

// Tests enc_untrusted_fchown() by attempting to change file ownership by making
// the host call from inside the enclave and verifying the return value.
TEST_F(HostCallTest, TestFChown) {
  std::string test_file =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/test_file.tmp");
  int fd =
      open(test_file.c_str(), O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
  platform::storage::FdCloser fd_closer(fd);
  ASSERT_GE(fd, 0);
  ASSERT_NE(access(test_file.c_str(), F_OK), -1);

  struct stat sb = {};
  EXPECT_THAT(fstat(fd, &sb), Eq(0));
  EXPECT_THAT(sb.st_uid, Eq(getuid()));
  EXPECT_THAT(sb.st_gid, Eq(getgid()));

  primitives::MessageWriter in;
  in.Push<int>(/*value=fd=*/fd);
  in.Push<uid_t>(/*value=owner=*/getuid());
  in.Push<gid_t>(/*value=group=*/getgid());

  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestFChown, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // Should only contain return value.
  EXPECT_THAT(out.next<int>(), Eq(0));

  // Attempt to fchown with invalid file descriptor, should return an error.
  primitives::MessageWriter in2;
  in2.Push<int>(/*value=fd=*/-1);
  in2.Push<uid_t>(/*value=owner=*/getuid());
  in2.Push<gid_t>(/*value=group=*/getgid());

  primitives::MessageReader out2;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestFChown, &in2, &out2));
  ASSERT_THAT(out2, SizeIs(1));  // Should only contain return value.
  EXPECT_THAT(out2.next<int>(), Eq(-1));
}

// Tests enc_untrusted_setsockopt() by creating a socket on the untrusted side,
// passing the socket file descriptor to the trusted side, and invoking
// the host call for setsockopt() from inside the enclave. Verifies the return
// value obtained from the host call to confirm that the new options have been
// set.
TEST_F(HostCallTest, TestSetSockOpt) {
  // Create an TCP socket (SOCK_STREAM) with Internet Protocol Family AF_INET6.
  int socket_fd = socket(AF_INET6, SOCK_STREAM, 0);
  EXPECT_THAT(socket_fd, Gt(0));

  // Bind the TCP socket to port 0 for any IP address. Once bind is successful
  // for UDP sockets application can operate on the socket descriptor for
  // sending or receiving data.
  struct sockaddr_in6 sa;
  memset(&sa, 0, sizeof(sa));
  sa.sin6_family = AF_INET6;
  sa.sin6_flowinfo = 0;
  sa.sin6_addr = in6addr_any;
  sa.sin6_port = htons(0);
  EXPECT_THAT(
      bind(socket_fd, reinterpret_cast<struct sockaddr *>(&sa), sizeof(sa)),
      Not(Eq(-1)));

  primitives::MessageWriter in;
  in.Push<int>(/*value=sockfd=*/socket_fd);
  in.Push<int>(/*value=level=*/SOL_SOCKET);
  in.Push<int>(/*value=optname=*/SO_REUSEADDR);
  in.Push<int>(/*value=option=*/1);

  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestSetSockOpt, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // Should only contain return value.
  EXPECT_THAT(out.next<int>(), Gt(-1));

  close(socket_fd);
}

// Tests enc_untrusted_flock() by trying to acquire an exclusive lock on a valid
// file from inside the enclave by making the untrusted host call and verifying
// its return value. We do not validate if the locked file can be accessed from
// another process. A child process created using fork() would be able to access
// the file since both the processes refer to the same lock, and this lock may
// be modified or released by either processes, as specified in the man page for
// flock.
TEST_F(HostCallTest, TestFlock) {
  std::string test_file =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/test_file.tmp");

  int fd =
      open(test_file.c_str(), O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
  platform::storage::FdCloser fd_closer(fd);
  ASSERT_GE(fd, 0);
  ASSERT_NE(access(test_file.c_str(), F_OK), -1);

  primitives::MessageWriter in;
  in.Push<int>(/*value=fd=*/fd);
  in.Push<int>(/*value=operation=*/LOCK_EX);

  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestFlock, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // Should only contain return value.
  EXPECT_THAT(out.next<int>(), Eq(0));
  flock(fd, LOCK_UN);
}

// Tests enc_untrusted_fsync by writing to a valid file, and then running fsync
// on it. Ensures that a successful code of 0 is returned.
TEST_F(HostCallTest, TestFsync) {
  std::string test_file =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/test_file.tmp");
  int fd =
      open(test_file.c_str(), O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
  platform::storage::FdCloser fd_closer(fd);
  ASSERT_GE(fd, 0);
  ASSERT_NE(access(test_file.c_str(), F_OK), -1);

  // Write something to the file.
  std::string file_content = "some random content.";
  ASSERT_THAT(write(fd, file_content.c_str(), file_content.length() + 1),
              Eq(file_content.length() + 1));

  primitives::MessageWriter in;
  in.Push<int>(/*value=fd*/ fd);

  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestFsync, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // Should only contain return value.
  EXPECT_THAT(out.next<int>(), Eq(0));
}

// Tests enc_untrusted_inotify_init1() by initializing a new inotify instance
// from inside the enclave and verifying that a file descriptor associated with
// a new inotify event queue is returned. Only the return value, i.e. the file
// descriptor value is verified to be positive.
TEST_F(HostCallTest, TestInotifyInit1) {
  primitives::MessageWriter in;
  in.Push<int>(/*value=flags=*/IN_NONBLOCK);

  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestInotifyInit1, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // Should only contain return value.
  int inotify_fd = out.next<int>();
  EXPECT_THAT(inotify_fd, Gt(0));
  close(inotify_fd);
}

// Tests enc_untrusted_inotify_add_watch() by initializing an inotify instance
// on the untrusted side, making the enclave call to trigger an untrusted host
// call to inotify_add_watch(), and validating that the correct events are
// recorded in the event buffer for the folder we are monitoring with inotify.
TEST_F(HostCallTest, TestInotifyAddWatch) {
  int inotify_fd = inotify_init1(IN_NONBLOCK);
  ASSERT_THAT(inotify_fd, Gt(0));

  // Call inotify_add_watch from inside the enclave for monitoring tmpdir for
  // all events supported by inotify.
  primitives::MessageWriter in;
  in.Push<int>(inotify_fd);
  in.Push(absl::GetFlag(FLAGS_test_tmpdir));

  in.Push<int>(IN_ALL_EVENTS);
  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestInotifyAddWatch, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // Should only contain return value.
  EXPECT_THAT(out.next<int>(), Eq(1));

  // Read the event buffer when no events have occurred in tmpdir.
  constexpr size_t event_size = sizeof(struct inotify_event);
  constexpr size_t buf_len = 10 * (event_size + NAME_MAX + 1);
  char buf[buf_len];
  EXPECT_THAT(read(inotify_fd, buf, buf_len), Eq(-1));

  // Perform an event by creating a file in tmpdir.
  std::string file_name = "test_file.tmp";
  std::string test_file =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/", file_name);
  int fd =
      open(test_file.c_str(), O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
  platform::storage::FdCloser fd_closer(fd);
  ASSERT_GE(fd, 0);
  ASSERT_NE(access(test_file.c_str(), F_OK), -1);

  // Read the event buffer after the event.
  EXPECT_THAT(read(inotify_fd, buf, buf_len), Gt(0));

  auto *event = reinterpret_cast<struct inotify_event *>(&buf[0]);
  EXPECT_THAT(event->mask, Eq(IN_MODIFY));
  EXPECT_THAT(event->name, StrEq(file_name));
  EXPECT_THAT(event->cookie, Eq(0));

  event =
      reinterpret_cast<struct inotify_event *>(&buf[event_size + event->len]);
  EXPECT_THAT(event->mask, Eq(IN_OPEN));
  EXPECT_THAT(event->name, StrEq(file_name));
  EXPECT_THAT(event->cookie, Eq(0));

  close(inotify_fd);
}

// Tests enc_untrusted_inotify_rm_watch() by de-registering an event from inside
// the enclave on the untrusted side and verifying that subsequent activity
// on the unregistered event is not recorded by inotify.
TEST_F(HostCallTest, TestInotifyRmWatch) {
  int inotify_fd = inotify_init1(IN_NONBLOCK);
  std::string watch_dir = absl::GetFlag(FLAGS_test_tmpdir);
  int wd = inotify_add_watch(inotify_fd, watch_dir.c_str(), IN_ALL_EVENTS);
  ASSERT_THAT(inotify_fd, Gt(0));
  ASSERT_THAT(wd, Eq(1));

  // Perform an event by creating a file in tmpdir.
  std::string file_name = "test_file.tmp";
  std::string test_file = absl::StrCat(watch_dir, "/", file_name);
  int fd =
      open(test_file.c_str(), O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
  platform::storage::FdCloser fd_closer(fd);
  ASSERT_GE(fd, 0);
  ASSERT_NE(access(test_file.c_str(), F_OK), -1);

  // Read the event buffer after the event.
  constexpr size_t event_size = sizeof(struct inotify_event);
  constexpr size_t buf_len = 10 * (event_size + NAME_MAX + 1);
  char buf[buf_len];
  EXPECT_THAT(read(inotify_fd, buf, buf_len), Gt(0));

  auto *event = reinterpret_cast<struct inotify_event *>(&buf[0]);
  EXPECT_THAT(event->mask, Eq(IN_MODIFY));
  EXPECT_THAT(event->name, StrEq(file_name));
  EXPECT_THAT(event->cookie, Eq(0));

  event =
      reinterpret_cast<struct inotify_event *>(&buf[event_size + event->len]);
  EXPECT_THAT(event->mask, Eq(IN_OPEN));
  EXPECT_THAT(event->name, StrEq(file_name));
  EXPECT_THAT(event->cookie, Eq(0));

  // Call inotify_rm_watch from inside the enclave, verify the return value.
  primitives::MessageWriter in;
  in.Push<int>(inotify_fd);
  in.Push<int>(wd);
  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestInotifyRmWatch, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // Should only contain return value.
  EXPECT_THAT(out.next<int>(), Eq(0));

  // Perform another event on the file.
  ASSERT_THAT(unlink(test_file.c_str()), Eq(0));

  // Read from the event buffer again to verify that the event was not recorded.
  EXPECT_THAT(read(inotify_fd, buf, buf_len), Gt(-1));
  close(inotify_fd);
}

// Tests enc_untrusted_sched_yield by calling it and ensuring that 0 is
// returned.
TEST_F(HostCallTest, TestSchedYield) {
  primitives::MessageWriter in;

  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestSchedYield, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // Should only contain return value.
  EXPECT_THAT(out.next<int>(), Eq(0));
}

// Tests enc_untrusted_isatty() by testing with a non-terminal file descriptor,
// it should return 0 since the file is not referring to a terminal.
TEST_F(HostCallTest, TestIsAtty) {
  std::string test_file =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/test_file.tmp");
  int fd =
      open(test_file.c_str(), O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
  platform::storage::FdCloser fd_closer(fd);
  ASSERT_GE(fd, 0);
  ASSERT_NE(access(test_file.c_str(), F_OK), -1);

  primitives::MessageWriter in;
  in.Push<int>(/*value=fd=*/fd);

  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestIsAtty, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // Should only contain return value.
  EXPECT_THAT(out.next<int>(), Eq(0));
}

// Tests enc_untrusted_usleep() by sleeping for 1s, then ensuring that the
// return value is 0, and that at least 1 second passed during the usleep
// enclave call.
TEST_F(HostCallTest, TestUSleep) {
  primitives::MessageWriter in;

  // Push the sleep duration as unsigned int instead of useconds_t, storing
  // it as useconds_t causes a segfault when popping the argument from the
  // stack on the trusted side.
  in.Push<unsigned int>(/*value=usec=*/1000000);
  primitives::MessageReader out;

  absl::Time start = absl::Now();
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestUSleep, &in, &out));
  absl::Time end = absl::Now();

  auto duration = absl::ToInt64Milliseconds(end - start);

  ASSERT_THAT(out, SizeIs(1));  // Should only contain return value.
  EXPECT_THAT(out.next<int>(), Eq(0));
  EXPECT_GE(duration, 1000);
  EXPECT_LE(duration, 1200);
}

// Tests enc_untrusted_stat() by creating a file and get stat of it, ensuring
// that the return value is 0 and returned stat contains expected value.
TEST_F(HostCallTest, TestStat) {
  std::string path = absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir),
      "/test_file.tmp");

  // Make sure the file does not exist.
  if (access(path.c_str(), F_OK) == 0) {
    ASSERT_NE(unlink(path.c_str()), -1);
  }

  int fd = creat(path.c_str(), DEFFILEMODE);
  platform::storage::FdCloser fd_closer(fd);
  ASSERT_GE(fd, 0);
  ASSERT_NE(access(path.c_str(), F_OK), -1);
  primitives::MessageWriter in;

  in.Push(path);
  primitives::MessageReader out;

  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestStat, &in, &out));
  ASSERT_THAT(out, SizeIs(2));  // Contains return value and result stat.
  ASSERT_THAT(out.next<int>(), Eq(0));
  mode_t mask = umask(0777);
  umask(mask);
  ASSERT_THAT(out.next<int>() & DEFFILEMODE, Eq(DEFFILEMODE & ~mask));
  EXPECT_NE(unlink(path.c_str()), -1);
}

}  // namespace
}  // namespace host_call
}  // namespace asylo
