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
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/platform/host_call/test/enclave_test_selectors.h"
#include "asylo/platform/host_call/untrusted/host_call_handlers_initializer.h"
#include "asylo/platform/primitives/test/test_backend.h"
#include "asylo/platform/primitives/untrusted_primitives.h"
#include "asylo/platform/system_call/type_conversions/types_functions.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/test/util/test_flags.h"

using ::testing::Eq;
using ::testing::Gt;
using ::testing::Not;
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
  std::string path = absl::StrCat(FLAGS_test_tmpdir, "/access_test.tmp");
  int fd = creat(path.c_str(), S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  ASSERT_GE(fd, 0);

  primitives::UntrustedParameterStack params;
  params.PushAlloc<char>(path.c_str(), path.length() + 1);
  *(params.PushAlloc<int>()) = /*mode=*/ R_OK | W_OK;

  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestAccess, &params));
  ASSERT_THAT(params.size(), Eq(1));  // should only contain return value.
  EXPECT_THAT(params.Pop<int>(), access(path.c_str(), R_OK | W_OK));
}

// Tests enc_untrusted_access() against a non-existent path.
TEST_F(HostCallTest, TestAccessNonExistentPath) {
  const char* path = "illegal_path";

  primitives::UntrustedParameterStack params;
  params.PushAlloc<char>(path, strlen(path) + 1);
  *(params.PushAlloc<int>()) = /*mode=*/ F_OK;

  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestAccess, &params));
  ASSERT_THAT(params.size(), Eq(1));  // should only contain return value.
  EXPECT_THAT(params.Pop<int>(), access(path, F_OK));
}

// Tests enc_untrusted_close() by creating a file to be closed and calling
// enc_untrusted_close() from inside the enclave to close the file handle.
TEST_F(HostCallTest, TestClose) {
  std::string path = absl::StrCat(FLAGS_test_tmpdir, "/file_to_close.tmp");
  int fd = open(path.c_str(), O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
  ASSERT_GE(fd, 0);
  ASSERT_NE(fcntl(fd, F_GETFD), -1);  // check fd is an open file descriptor.

  primitives::UntrustedParameterStack params;
  *(params.PushAlloc<int>()) = fd;

  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestClose, &params));
  ASSERT_THAT(params.size(), Eq(1));  // should only contain return value.
  EXPECT_THAT(params.Pop<int>(), Eq(0));
}

// Tries closing a non-existent file handle by calling enc_untrusted_close()
// from inside the enclave.
TEST_F(HostCallTest, TestCloseNonExistentFile) {
  primitives::UntrustedParameterStack params;
  *(params.PushAlloc<int>()) = /*fd=*/ 123456;

  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestClose, &params));
  ASSERT_THAT(params.size(), Eq(1));  // should only contain return value.
  EXPECT_THAT(params.Pop<int>(), Eq(-1));
}

// Tests enc_untrusted_getpid() by calling it from inside the enclave and
// verifying its return value against pid obtained from native system call.
TEST_F(HostCallTest, TestGetpid) {
  primitives::UntrustedParameterStack params;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestGetPid, &params));
  ASSERT_THAT(params.size(), Eq(1));  // should only contain return value.
  EXPECT_THAT(params.Pop<pid_t>(), Eq(getpid()));
}

// Tests enc_untrusted_kill() by forking the current process and putting the
// child process to sleep, then calling enc_untrusted_kill() from inside the
// enclave to kill the child process.
TEST_F(HostCallTest, TestKill) {
  pid_t pid = fork();  // child process to be killed
  if (pid == 0) {
    sleep(1000);  // The child process waits until it's killed by the parent.
  }

  primitives::UntrustedParameterStack params;
  *(params.PushAlloc<pid_t>()) = /*pid=*/ pid;
  *(params.PushAlloc<int>()) = /*sig=*/ SIGABRT;

  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestKill, &params));
  ASSERT_THAT(params.size(), Eq(1));  // should only contain return value.
  EXPECT_THAT(params.Pop<int>(), Eq(0));
}

// Tests enc_untrusted_link() by creating a file (|oldpath|) and calling
// enc_untrusted_link() from inside the enclave to link it to |newpath|, then
// verifying that |newpath| is indeed accessible.
TEST_F(HostCallTest, TestLink) {
  std::string oldpath = absl::StrCat(FLAGS_test_tmpdir, "/old_name.tmp");
  std::string newpath = absl::StrCat(FLAGS_test_tmpdir, "/new_name.tmp");

  int fd = open(oldpath.c_str(), O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
  ASSERT_GE(fd, 0);
  ASSERT_NE(access(oldpath.c_str(), F_OK), -1);

  primitives::UntrustedParameterStack params;
  params.PushAlloc<char>(oldpath.c_str(), oldpath.length() + 1);
  params.PushAlloc<char>(newpath.c_str(), newpath.length() + 1);

  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestLink, &params));
  ASSERT_THAT(params.size(), Eq(1));  // should only contain return value.

  EXPECT_NE(access(newpath.c_str(), F_OK), -1);
  EXPECT_NE(access(oldpath.c_str(), F_OK), -1);
}

// Tests enc_untrusted_lseek() by creating a file and calling
// enc_untrusted_leek() from inside the enclave and verify the return value for
// the provided offset.
TEST_F(HostCallTest, TestLseek) {
  std::string path = absl::StrCat(FLAGS_test_tmpdir, "/file_to_lseek.tmp");

  int fd = open(path.c_str(), O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
  ASSERT_GE(fd, 0);
  ASSERT_NE(access(path.c_str(), F_OK), -1);
  EXPECT_THAT(write(fd, "hello", 5), Eq(5));

  primitives::UntrustedParameterStack params;
  *(params.PushAlloc<int>()) = /*fd=*/ fd;
  *(params.PushAlloc<off_t>()) = /*offset=*/ 2;
  *(params.PushAlloc<int>()) = /*whence=*/ SEEK_SET;

  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestLseek, &params));
  ASSERT_THAT(params.size(), Eq(1));  // should only contain the return value.
  EXPECT_THAT(params.Pop<off_t>(), Eq(2));
}

TEST_F(HostCallTest, TestLseekBadReturn) {
  std::string path = absl::StrCat(FLAGS_test_tmpdir, "/file_to_lseek.tmp");

  int fd = open(path.c_str(), O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
  ASSERT_GE(fd, 0);
  ASSERT_NE(access(path.c_str(), F_OK), -1);
  EXPECT_THAT(write(fd, "hello", 5), Eq(5));

  primitives::UntrustedParameterStack params;
  *(params.PushAlloc<int>()) = /*fd=*/ fd;
  *(params.PushAlloc<off_t>()) = /*offset=*/ 0;
  *(params.PushAlloc<int>()) = /*whence=*/ 1000;

  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestLseek, &params));
  ASSERT_THAT(params.size(), Eq(1));  // should only contain the return value.
  EXPECT_THAT(params.Pop<off_t>(), Eq(-1));
}

// Tests enc_untrusted_mkdir() by calling it from inside the enclave and
// verifying that the directory created indeed exists.
TEST_F(HostCallTest, TestMkdir) {
  std::string path = absl::StrCat(FLAGS_test_tmpdir, "/dir_to_make");

  primitives::UntrustedParameterStack params;
  params.PushAlloc<char>(path.c_str(), path.length() + 1);
  *(params.PushAlloc<mode_t>()) = /*mode=*/ 0777;

  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestMkdir, &params));
  ASSERT_THAT(params.size(), Eq(1));  // should only contain the return value.
  EXPECT_THAT(params.Pop<int>(), Eq(0));

  struct stat sb;
  EXPECT_TRUE(stat(path.c_str(), &sb) == 0 && S_ISDIR(sb.st_mode));
}

TEST_F(HostCallTest, TestMkdirNonExistentPath) {
  std::string path = absl::StrCat("/non-existent-path/dir_to_make");

  primitives::UntrustedParameterStack params;
  params.PushAlloc<char>(path.c_str(), path.length() + 1);
  *(params.PushAlloc<mode_t>()) = /*mode=*/ 0777;

  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestMkdir, &params));
  ASSERT_THAT(params.size(), Eq(1));  // should only contain the return value.
  EXPECT_THAT(params.Pop<int>(), Eq(-1));
}

// Tests enc_untrusted_open() by using it to create a new file from inside the
// enclave and verifying that it exists.
TEST_F(HostCallTest, TestOpen) {
  std::string path = absl::StrCat(FLAGS_test_tmpdir, "/file_to_open.tmp");

  primitives::UntrustedParameterStack params;
  params.PushAlloc<char>(path.c_str(), path.length() + 1);
  *(params.PushAlloc<int>()) = /*flags=*/ O_RDWR | O_CREAT | O_TRUNC;
  *(params.PushAlloc<mode_t>()) = /*mode=*/ S_IRUSR | S_IWUSR;

  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestOpen, &params));
  ASSERT_THAT(params.size(), Eq(1));  // should only contain the return value.
  EXPECT_THAT(params.Pop<int>(), Gt(0));
  EXPECT_NE(access(path.c_str(), F_OK), -1);
}

// Test enc_untrusted_open() by opening an existing file (omit passing mode when
// opening the file).
TEST_F(HostCallTest, TestOpenExistingFile) {
  std::string path = absl::StrCat(FLAGS_test_tmpdir, "/file_to_open.tmp");

  creat(path.c_str(), S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  ASSERT_NE(access(path.c_str(), F_OK), -1);

  primitives::UntrustedParameterStack params;
  params.PushAlloc<char>(path.c_str(), path.length() + 1);
  *(params.PushAlloc<int>()) = /*flags*/ O_RDWR | O_CREAT | O_TRUNC;

  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestOpen, &params));
  ASSERT_THAT(params.size(), Eq(1));  // should only contain the return value.
  EXPECT_THAT(params.Pop<int>(), Gt(0));
  EXPECT_NE(access(path.c_str(), F_OK), -1);
}

// Tests enc_untrusted_unlink() by deleting an existing file on the untrusted
// side from inside the enclave using the host call.
TEST_F(HostCallTest, TestUnlink) {
  std::string path = absl::StrCat(FLAGS_test_tmpdir, "/file_to_delete.tmp");
  creat(path.c_str(), S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  ASSERT_NE(access(path.c_str(), F_OK), -1);

  primitives::UntrustedParameterStack params;
  params.PushAlloc<char>(path.c_str(), path.length() + 1);

  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestUnlink, &params));
  ASSERT_THAT(params.size(), Eq(1));  // should only contain the return value.
  EXPECT_THAT(params.Pop<int>(), Eq(0));
  EXPECT_THAT(access(path.c_str(), F_OK), Eq(-1));
}

TEST_F(HostCallTest, TestUnlinkNonExistingFile) {
  const char* path = "obviously-illegal-file.tmp";
  ASSERT_THAT(access(path, F_OK), Eq(-1));

  primitives::UntrustedParameterStack params;
  params.PushAlloc<char>(path, strlen(path) + 1);

  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestUnlink, &params));
  ASSERT_THAT(params.size(), Eq(1));  // should only contain the return value.
  EXPECT_THAT(params.Pop<int>(), Eq(-1));
}

// Tests enc_untrusted_getuid() by making the host call from inside the enclave
// and comparing the result with the value obtained from native getuid().
TEST_F(HostCallTest, TestGetuid) {
  primitives::UntrustedParameterStack params;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestGetUid, &params));
  ASSERT_THAT(params.size(), Eq(1));  // should only contain the return value.
  EXPECT_THAT(params.Pop<uid_t>(), Eq(getuid()));
}

// Tests enc_untrusted_getgid() by making the host call from inside the enclave
// and comparing the result with the value obtained from native getgid().
TEST_F(HostCallTest, TestGetgid) {
  primitives::UntrustedParameterStack params;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestGetGid, &params));
  ASSERT_THAT(params.size(), Eq(1));  // should only contain the return value.
  EXPECT_THAT(params.Pop<gid_t>(), Eq(getgid()));
}

// Tests enc_untrusted_geteuid() by making the host call from inside the enclave
// and comparing the result with the value obtained from native geteuid().
TEST_F(HostCallTest, TestGetEuid) {
  primitives::UntrustedParameterStack params;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestGetEuid, &params));
  ASSERT_THAT(params.size(), Eq(1));  // should only contain the return value.
  EXPECT_THAT(params.Pop<uid_t>(), Eq(geteuid()));
}

// Tests enc_untrusted_getegid() by making the host call from inside the enclave
// and comparing the result with the value obtained from native getegid().
TEST_F(HostCallTest, TestGetEgid) {
  primitives::UntrustedParameterStack params;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestGetEgid, &params));
  ASSERT_THAT(params.size(), Eq(1));  // should only contain the return value.
  EXPECT_THAT(params.Pop<gid_t>(), Eq(getegid()));
}

// Tests enc_untrusted_rename() by making a host call from inside the enclave
// and verifying that the file is indeed renamed on the untrusted side.
TEST_F(HostCallTest, TestRename) {
  std::string oldpath = absl::StrCat(FLAGS_test_tmpdir, "/oldname.tmp");
  std::string newpath = absl::StrCat(FLAGS_test_tmpdir, "/newname.tmp");

  creat(oldpath.c_str(), S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  ASSERT_NE(access(oldpath.c_str(), F_OK), -1);

  primitives::UntrustedParameterStack params;
  params.PushAlloc<char>(oldpath.c_str(), strlen(oldpath.c_str()) + 1);
  params.PushAlloc<char>(newpath.c_str(), strlen(newpath.c_str()) + 1);

  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestRename, &params));
  ASSERT_THAT(params.size(), Eq(1));  // should only contain the return value.
  EXPECT_THAT(params.Pop<int>(), Eq(0));

  EXPECT_THAT(access(oldpath.c_str(), F_OK), Eq(-1));
  EXPECT_NE(access(newpath.c_str(), F_OK), -1);
}

// Tests enc_untrusted_read() by making a host call from inside the enclave and
// verifying that what is read on untrusted side is identical to what is read
// from inside the enclave for a provided file.
TEST_F(HostCallTest, TestRead) {
  std::string test_file = absl::StrCat(FLAGS_test_tmpdir, "/test_file.tmp");

  int fd =
      open(test_file.c_str(), O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
  ASSERT_GE(fd, 0);
  ASSERT_NE(access(test_file.c_str(), F_OK), -1);

  std::string expected_content = "this is what's being read!";
  ASSERT_THAT(
      write(fd, expected_content.c_str(), expected_content.length() + 1),
      Eq(expected_content.length() + 1));
  ASSERT_THAT(lseek(fd, 0, SEEK_SET), Eq(0));

  // We do not push the empty read buffer on the stack since a read buffer would
  // need to be created inside the enclave anyway.
  primitives::UntrustedParameterStack params;
  *(params.PushAlloc<int>()) = /*fd=*/ fd;
  *(params.PushAlloc<size_t>()) = /*count=*/ expected_content.length() + 1;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestRead, &params));
  ASSERT_THAT(params.size(), Eq(2));  // Contains return value and buffer.
  EXPECT_THAT(params.Pop()->As<char>(), StrEq(expected_content));
  EXPECT_THAT(params.Pop<ssize_t>(), Eq(expected_content.length() + 1));
}

// Tests enc_untrusted_write() by making a host call from inside the enclave to
// write to a file, and verifying that the content read from the file on the
// host matches it.
TEST_F(HostCallTest, TestWrite) {
  std::string test_file = absl::StrCat(FLAGS_test_tmpdir, "/test_file.tmp");

  int fd =
      open(test_file.c_str(), O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
  ASSERT_GE(fd, 0);
  ASSERT_NE(access(test_file.c_str(), F_OK), -1);

  std::string write_buf = "text to be written";
  primitives::UntrustedParameterStack params;
  *(params.PushAlloc<int>()) = /*fd=*/ fd;
  params.PushAlloc<char>(write_buf.c_str(), write_buf.length() + 1);
  *(params.PushAlloc<size_t>()) = /*count=*/ write_buf.length() + 1;

  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestWrite, &params));
  ASSERT_THAT(params.size(), Eq(1));  // Should only contain return value.
  EXPECT_THAT(params.Pop<ssize_t>(), Eq(write_buf.length() + 1));

  ASSERT_THAT(lseek(fd, 0, SEEK_SET), Eq(0));
  char read_buf[20];
  EXPECT_THAT(read(fd, read_buf, write_buf.length() + 1),
              Eq(write_buf.length() + 1));
  EXPECT_THAT(read_buf, StrEq(write_buf));
}

// Tests enc_untrusted_symlink() by attempting to create a symlink from inside
// the enclave and verifying that the created symlink is accessible.
TEST_F(HostCallTest, TestSymlink) {
  std::string test_file = absl::StrCat(FLAGS_test_tmpdir, "/test_file.tmp");
  std::string target = absl::StrCat(FLAGS_test_tmpdir, "/target.tmp");

  int fd =
      open(test_file.c_str(), O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
  ASSERT_GE(fd, 0);
  ASSERT_NE(access(test_file.c_str(), F_OK), -1);

  primitives::UntrustedParameterStack params;
  params.PushAlloc<char>(test_file.c_str(), test_file.length() + 1);
  params.PushAlloc<char>(target.c_str(), target.length() + 1);

  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestSymlink, &params));
  ASSERT_THAT(params.size(), Eq(1));  // Should only contain return value.
  EXPECT_THAT(params.Pop<int>(), Eq(0));
  EXPECT_NE(access(target.c_str(), F_OK), -1);
}

// Tests enc_untrusted_readlink() by making a call from inside the enclave and
// verifying that the returned target path is same as that obtained from calling
// readlink() natively on the untrusted side.
TEST_F(HostCallTest, TestReadlink) {
  std::string test_file = absl::StrCat(FLAGS_test_tmpdir, "/test_file.tmp");
  std::string sym_file = absl::StrCat(FLAGS_test_tmpdir, "/test_sym_file.tmp");

  int fd =
      open(test_file.c_str(), O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
  ASSERT_GE(fd, 0);
  ASSERT_NE(access(test_file.c_str(), F_OK), -1);

  // Create a symlink to be read by readlink.
  ASSERT_THAT(symlink(test_file.c_str(), sym_file.c_str()), Eq(0));

  primitives::UntrustedParameterStack params;
  params.PushAlloc<char>(sym_file.c_str(), sym_file.length() + 1);

  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestReadLink, &params));

  char buf_expected[PATH_MAX];
  ssize_t len_expected =
      readlink(sym_file.c_str(), buf_expected, sizeof(buf_expected) - 1);
  buf_expected[len_expected] = '\0';

  ASSERT_THAT(params.size(), Eq(2));  // Return value and the buffer.
  EXPECT_THAT(params.Pop()->As<char>(), StrEq(buf_expected));
  EXPECT_THAT(params.Pop<ssize_t>(), Eq(len_expected));
}

// Tests enc_untrusted_truncate() by making a call from inside the enclave and
// verifying that the file is indeed truncated on the untrusted side by reading
// the file.
TEST_F(HostCallTest, TestTruncate) {
  std::string test_file = absl::StrCat(FLAGS_test_tmpdir, "/test_file.tmp");
  int fd =
      open(test_file.c_str(), O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
  ASSERT_GE(fd, 0);
  ASSERT_NE(access(test_file.c_str(), F_OK), -1);

  // Write something to the file.
  std::string file_content = "some random content.";
  ASSERT_THAT(write(fd, file_content.c_str(), file_content.length() + 1),
              Eq(file_content.length() + 1));

  primitives::UntrustedParameterStack params;
  constexpr int kTruncLen = 5;
  params.PushAlloc<char>(test_file.c_str(), test_file.length() + 1);
  *(params.PushAlloc<off_t>()) = /*length=*/ kTruncLen;

  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestTruncate, &params));
  ASSERT_THAT(params.size(), Eq(1));  // Should only contain return value.
  EXPECT_THAT(params.Pop<int>(), 0);

  // Verify contents of the file by reading it.
  char read_buf[10];
  ASSERT_THAT(lseek(fd, 0, SEEK_SET), Eq(0));
  EXPECT_THAT(read(fd, read_buf, 10), Eq(kTruncLen));
  read_buf[kTruncLen] = '\0';
  EXPECT_THAT(read_buf, StrEq(file_content.substr(0, kTruncLen)));
}

// Tests enc_untrusted_rmdir() by making a call from inside the enclave and
// verifying that the directory is indeed deleted.
TEST_F(HostCallTest, TestRmdir) {
  std::string dir_to_del = absl::StrCat(FLAGS_test_tmpdir, "/dir_to_del");
  ASSERT_THAT(mkdir(dir_to_del.c_str(), O_CREAT | O_RDWR), Eq(0));

  primitives::UntrustedParameterStack params;
  params.PushAlloc<char>(dir_to_del.c_str(), dir_to_del.length() + 1);

  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestRmdir, &params));
  ASSERT_THAT(params.size(), Eq(1));  // Should only contain return value.
  EXPECT_THAT(params.Pop<int>(), Eq(0));

  // Verify that the directory does not exist.
  struct stat sb;
  EXPECT_FALSE(stat(dir_to_del.c_str(), &sb) == 0 && S_ISDIR(sb.st_mode));
}

// Tests enc_untrusted_socket() by trying to obtain a valid (greater than 0)
// socket file descriptor when the method is called from inside the enclave.
TEST_F(HostCallTest, TestSocket) {
  primitives::UntrustedParameterStack params;
  // Setup bidirectional IPv6 socket.
  *(params.PushAlloc<int>()) = /*domain=*/ AF_INET6;
  *(params.PushAlloc<int>()) = /*type=*/ SOCK_STREAM;
  *(params.PushAlloc<int>()) = /*protocol=*/ 0;

  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestSocket, &params));
  ASSERT_THAT(params.size(), Eq(1));  // Should only contain return value.
  EXPECT_THAT(params.Pop<int>(), Gt(0));

  // Setup socket for local bidirectional communication between two processes on
  // the host.
  *(params.PushAlloc<int>()) = /*domain=*/ AF_UNIX;
  *(params.PushAlloc<int>()) = /*type=*/ SOCK_STREAM;
  *(params.PushAlloc<int>()) = /*protocol=*/ 0;

  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestSocket, &params));
  ASSERT_THAT(params.size(), Eq(1));  // Should only contain return value.
  EXPECT_THAT(params.Pop<int>(), Gt(0));
}

// Tests enc_untrusted_fcntl() by performing various file control operations
// from inside the enclave and validating the return valueswith those obtained
// from native host call to fcntl().
TEST_F(HostCallTest, TestFcntl) {
  std::string test_file = absl::StrCat(FLAGS_test_tmpdir, "/fcntl.tmp");
  int fd =
      open(test_file.c_str(), O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
  ASSERT_GE(fd, 0);
  ASSERT_NE(access(test_file.c_str(), F_OK), -1);

  // Get file flags and compare to those obtained from native fcntl() syscall.
  primitives::UntrustedParameterStack params;
  *(params.PushAlloc<int>()) = /*fd=*/ fd;
  *(params.PushAlloc<int>()) = /*cmd=*/ F_GETFL;
  *(params.PushAlloc<int>()) = /*arg=*/ 0;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestFcntl, &params));
  ASSERT_THAT(params.size(), Eq(1));  // Should only contain return value.
  EXPECT_THAT(params.Pop<int>(),
              Eq(FromkLinuxFileStatusFlag(fcntl(fd, F_GETFL, 0))));

  // Turn on one or more of the file status flags for a descriptor.
  int flags_to_set = O_APPEND | O_NONBLOCK | O_RDONLY;
  *(params.PushAlloc<int>()) = /*fd=*/ fd;
  *(params.PushAlloc<int>()) = /*cmd=*/ F_SETFL;
  *(params.PushAlloc<int>()) = /*arg=*/ flags_to_set;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestFcntl, &params));
  ASSERT_THAT(params.size(), Eq(1));  // Should only contain return value.
  EXPECT_THAT(params.Pop<int>(),
              Eq(FromkLinuxFileStatusFlag(fcntl(fd, F_SETFL, flags_to_set))));
}

TEST_F(HostCallTest, TestFcntlInvalidCmd) {
  primitives::UntrustedParameterStack params;
  *(params.PushAlloc<int>()) = /*fd=*/ 0;
  *(params.PushAlloc<int>()) = /*cmd=*/ 10000000;
  *(params.PushAlloc<int>()) = /*arg=*/ 0;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestFcntl, &params));
  ASSERT_THAT(params.size(), Eq(1));  // Should only contain return value.
  EXPECT_THAT(params.Pop<int>(), Eq(-1));
}

// Tests enc_untrusted_chown() by attempting to change file ownership by making
// the host call from inside the enclave and verifying the return value.
TEST_F(HostCallTest, TestChown) {
  std::string test_file = absl::StrCat(FLAGS_test_tmpdir, "/test_file.tmp");
  int fd =
      open(test_file.c_str(), O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
  ASSERT_GE(fd, 0);
  ASSERT_NE(access(test_file.c_str(), F_OK), -1);

  primitives::UntrustedParameterStack params;
  params.PushAlloc<char>(test_file.c_str(), test_file.length() + 1);
  *(params.PushAlloc<uid_t>()) = /*owner=*/ getuid();
  *(params.PushAlloc<gid_t>()) = /*group=*/ getgid();

  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestChown, &params));
  ASSERT_THAT(params.size(), Eq(1));  // Should only contain return value.
  EXPECT_THAT(params.Pop<int>(), Eq(0));
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
  EXPECT_THAT(bind(socket_fd, reinterpret_cast<struct sockaddr*>(&sa),
                   sizeof(sa)),
              Not(Eq(-1)));

  primitives::UntrustedParameterStack params;
  *(params.PushAlloc<int>()) = /*sockfd=*/ socket_fd;
  *(params.PushAlloc<int>()) = /*level=*/ SOL_SOCKET;
  *(params.PushAlloc<int>()) = /*optname=*/ SO_REUSEADDR;
  *(params.PushAlloc<int>()) = /*option=*/ 1;

  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestSetSockOpt, &params));
  ASSERT_THAT(params.size(), Eq(1));  // Should only contain return value.
  EXPECT_THAT(params.Pop<int>(), Gt(-1));

  close(socket_fd);
}

}  // namespace
}  // namespace host_call
}  // namespace asylo

int main(int argc, char* argv[]) {
  ::testing::InitGoogleTest(&argc, argv);
  ::google::ParseCommandLineFlags(&argc, &argv, true);

  return RUN_ALL_TESTS();
}
