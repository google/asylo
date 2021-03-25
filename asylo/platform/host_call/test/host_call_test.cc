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
#include <netdb.h>
#include <netinet/in.h>
#include <sys/file.h>
#include <sys/inotify.h>
#include <sys/poll.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/un.h>
#include <utime.h>

#include <algorithm>
#include <cstddef>
#include <ostream>
#include <string>
#include <thread>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/base/macros.h"
#include "absl/container/flat_hash_set.h"
#include "absl/flags/flag.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "asylo/enclave_manager.h"
#include "asylo/platform/common/time_util.h"
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

using asylo::primitives::Extent;
using asylo::primitives::MessageReader;
using asylo::primitives::MessageWriter;

namespace asylo {
namespace host_call {
namespace {

class HostCallTest : public ::testing::Test {
 protected:
  void SetUp() override {
    EnclaveManager::Configure(EnclaveManagerOptions());

    // Loads the enclave. The function uses the factory method
    // |primitives::test::TestBackend::Get()| for loading the enclave, and the
    // type of backend (sim, remote, sgx etc.) loaded depends upon the type of
    // library linked against the build that implements the abstract factory
    // class |TestBackend|.
    client_ = primitives::test::TestBackend::Get()->LoadTestEnclaveOrDie(
        /*enclave_name=*/"host_call_test_enclave");

    ASYLO_EXPECT_OK(
        AddHostCallHandlersToExitCallProvider(client_->exit_call_provider()));
    ASSERT_FALSE(client_->IsClosed());

    // Check if IPv4 and IPv6 are supported on this system
    addrinfo *result;
    ASSERT_EQ(getaddrinfo("localhost", nullptr, nullptr, &result), 0)
        << strerror(errno);
    ipv4_supported_ = false;
    ipv6_supported_ = false;
    for (addrinfo *current = result; current; current = current->ai_next) {
      if (current->ai_family == AF_INET)
        ipv4_supported_ = true;
      else if (current->ai_family == AF_INET6)
        ipv6_supported_ = true;
    }
    freeaddrinfo(result);
    ASSERT_TRUE(ipv4_supported_ || ipv6_supported_);
  }

  void TearDown() override {
    client_->Destroy();
    EXPECT_TRUE(client_->IsClosed());
  }

  // Compares two struct stat, returning |true| if they are equal, and |false|
  // otherwise.
  bool EqualsStat(const struct stat *st, const struct stat *st_expected) {
    return st->st_atime == st_expected->st_atime &&
           st->st_blksize == st_expected->st_blksize &&
           st->st_blocks == st_expected->st_blocks &&
           st->st_mtime == st_expected->st_mtime &&
           st->st_dev == st_expected->st_dev &&
           st->st_gid == st_expected->st_gid &&
           st->st_ino == st_expected->st_ino &&
           st->st_mode == st_expected->st_mode &&
           st->st_ctime == st_expected->st_ctime &&
           st->st_nlink == st_expected->st_nlink &&
           st->st_rdev == st_expected->st_rdev &&
           st->st_size == st_expected->st_size &&
           st->st_uid == st_expected->st_uid;
  }

  // Fills the struct stat with the information from MessageReader.
  void LoadStatFromMessageReader(MessageReader *out, struct stat *st) {
    st->st_atime = out->next<uint64_t>();
    st->st_blksize = out->next<int64_t>();
    st->st_blocks = out->next<int64_t>();
    st->st_mtime = out->next<uint64_t>();
    st->st_dev = out->next<uint64_t>();
    st->st_gid = out->next<uint32_t>();
    st->st_ino = out->next<uint64_t>();
    st->st_mode = out->next<uint32_t>();
    st->st_ctime = out->next<uint64_t>();
    st->st_nlink = out->next<uint64_t>();
    st->st_rdev = out->next<uint64_t>();
    st->st_size = out->next<int64_t>();
    st->st_uid = out->next<uint32_t>();
  }

  asylo::Status CheckStatFs(const struct statfs *st,
                            const struct statfs *st_expected) {
    if (st->f_type != st_expected->f_type) {
      return absl::InternalError("type");
    }
    if (st->f_bsize != st_expected->f_bsize) {
      return absl::InternalError("bsize");
    }
    if (st->f_blocks != st_expected->f_blocks) {
      return absl::InternalError("blocks");
    }
    // bavail, files, ffree are too volatile to check between enclave and host.
    if (st->f_fsid.__val[0] != st_expected->f_fsid.__val[0]) {
      return absl::InternalError("val0");
    }
    if (st->f_fsid.__val[1] != st_expected->f_fsid.__val[1]) {
      return absl::InternalError("val1");
    }
    if (st->f_namelen != st_expected->f_namelen) {
      return absl::InternalError("namelen");
    }
    if (st->f_frsize != st_expected->f_frsize) {
      return absl::InternalError("frsize");
    }
    int64_t supported_flag_mask = ST_NOSUID
#if (defined(__GNU_VISIBLE) && __GNU_VISIBLE) || \
    (defined(__USE_GNU) && __USE_GNU)
                                  | ST_MANDLOCK | ST_NOATIME | ST_NODEV |
                                  ST_NODIRATIME | ST_NOEXEC | ST_RELATIME |
                                  ST_SYNCHRONOUS
#endif
                                  | ST_RDONLY;
    if ((st->f_flags & supported_flag_mask) !=
        (st_expected->f_flags & supported_flag_mask)) {
      return absl::InternalError("flags");
    }
    for (int i = 0; i < ABSL_ARRAYSIZE(st->f_spare); ++i) {
      if (st->f_spare[i] != st_expected->f_spare[i]) {
        return absl::InternalError(absl::StrCat("spare", i));
      }
    }
    return absl::OkStatus();
  }

  // Fills the struct statfs with the information from MessageReader.
  void LoadStatFsFromMessageReader(MessageReader *out, struct statfs *st) {
    st->f_type = out->next<int64_t>();
    st->f_bsize = out->next<int64_t>();
    st->f_blocks = out->next<uint64_t>();
    st->f_bfree = out->next<uint64_t>();
    st->f_bavail = out->next<uint64_t>();
    st->f_files = out->next<uint64_t>();
    st->f_ffree = out->next<uint64_t>();
    st->f_fsid.__val[0] = out->next<int32_t>();
    st->f_fsid.__val[1] = out->next<int32_t>();
    st->f_namelen = out->next<int64_t>();
    st->f_frsize = out->next<int64_t>();
    st->f_flags = out->next<int64_t>();
    for (int i = 0; i < ABSL_ARRAYSIZE(st->f_spare); ++i) {
      st->f_spare[i] = out->next<int64_t>();
    }
  }

  std::shared_ptr<primitives::Client> client_;
  bool ipv4_supported_;
  bool ipv6_supported_;
};

class AddressFamily {
 public:
  explicit AddressFamily(int af) : family_(af) {}

  absl::string_view getString() const {
    switch (family_) {
      case AF_INET:
        return "(IPv4)";
      case AF_INET6:
        return "(IPv6)";
      default:
        return "(unknown)";
    }
  }

 private:
  int family_;
};
std::ostream &operator<<(std::ostream &stream, const AddressFamily &family) {
  return stream << family.getString();
}

// Tests enc_untrusted_access() by creating a file and calling
// enc_untrusted_access() from inside the enclave and verifying its return
// value.
TEST_F(HostCallTest, TestAccess) {
  std::string path =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/test_file.tmp");
  int fd = creat(path.c_str(), S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  ASSERT_GE(fd, 0);

  MessageWriter in;
  in.PushString(path);
  in.Push<int>(/*value=mode=*/R_OK | W_OK);

  MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestAccess, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // should only contain return value.
  EXPECT_THAT(out.next<int>(), access(path.c_str(), R_OK | W_OK));
}

// Tests enc_untrusted_access() against a non-existent path.
TEST_F(HostCallTest, TestAccessNonExistentPath) {
  const char *path = "illegal_path";

  MessageWriter in;
  in.PushString(path);
  in.Push<int>(/*value=mode=*/F_OK);

  MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestAccess, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // should only contain return value.
  EXPECT_THAT(out.next<int>(), access(path, F_OK));
}

// Tests enc_untrusted_getpid() by calling it from inside the enclave and
// verifying its return value against pid obtained from native system call.
TEST_F(HostCallTest, TestGetpid) {
  MessageWriter in;
  MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestGetPid, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // should only contain return value.
  EXPECT_THAT(out.next<pid_t>(), Eq(getpid()));
}

// Tests enc_untrusted_getppid() by calling it from inside the enclave and
// verifying its return value against ppid obtained from native system call.
TEST_F(HostCallTest, TestGetPpid) {
  MessageWriter in;
  MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestGetPpid, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // should only contain return value.
  EXPECT_THAT(out.next<pid_t>(), Eq(getppid()));
}

// Tests enc_untrusted_getgid() by making the host call from inside the enclave
// and comparing the result with the value obtained from native getgid().
TEST_F(HostCallTest, TestGetgid) {
  MessageWriter in;
  MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestGetGid, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // should only contain the return value.
  EXPECT_THAT(out.next<gid_t>(), Eq(getgid()));
}

// Tests enc_untrusted_geteuid() by making the host call from inside the enclave
// and comparing the result with the value obtained from native geteuid().
TEST_F(HostCallTest, TestGetEuid) {
  MessageWriter in;
  MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestGetEuid, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // should only contain the return value.
  EXPECT_THAT(out.next<uid_t>(), Eq(geteuid()));
}

// Tests enc_untrusted_getegid() by making the host call from inside the enclave
// and comparing the result with the value obtained from native getegid().
TEST_F(HostCallTest, TestGetEgid) {
  MessageWriter in;
  MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestGetEgid, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // should only contain the return value.
  EXPECT_THAT(out.next<gid_t>(), Eq(getegid()));
}

// Tests enc_untrusted_getuid() by making the host call from inside the enclave
// and comparing the result with the value obtained from native getuid().
TEST_F(HostCallTest, TestGetuid) {
  MessageWriter in;
  MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestGetUid, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // should only contain the return value.
  EXPECT_THAT(out.next<uid_t>(), Eq(getuid()));
}

bool sigabrt_received = false;
void sigabrt_handler(int sig) {
  if (sig == SIGABRT) sigabrt_received = true;
}

// Tests enc_untrusted_kill() by calling the method on the current process from
// inside the enclave with a SIGABRT. We substitute the handler for SIGABRT
// temporarily so that the current process doesn't actually get killed.
TEST_F(HostCallTest, TestKill) {
  sigabrt_received = false;

  // Change the default signal handler for SIGABRT.
  struct sigaction old_handler, new_handler;
  new_handler.sa_handler = &sigabrt_handler;
  sigemptyset(&(new_handler.sa_mask));
  new_handler.sa_flags = 0;
  ASSERT_THAT(sigaction(SIGABRT, &new_handler, &old_handler), Not(Eq(-1)));

  MessageWriter in;
  in.Push<pid_t>(/*value=pid=*/getpid());
  in.Push<int>(/*value=sig=*/SIGABRT);

  MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestKill, &in, &out));
  EXPECT_THAT(sigabrt_received, Eq(true));
  ASSERT_THAT(out, SizeIs(1));  // should only contain return value.
  EXPECT_THAT(out.next<int>(), Eq(0));

  // Restore the default handler for SIGABRT.
  ASSERT_THAT(sigaction(SIGABRT, nullptr, &old_handler), Not(Eq(-1)));
  sigabrt_received = false;
}

// Tests enc_untrusted_raise() by calling the method on the current process from
// inside the enclave with a SIGABRT. We substitute the handler for SIGABRT
// temporarily so that the current process doesn't actually get aborted.
TEST_F(HostCallTest, TestRaise) {
  sigabrt_received = false;

  // Change the default signal handler for SIGABRT.
  struct sigaction old_handler, new_handler;
  new_handler.sa_handler = &sigabrt_handler;
  sigemptyset(&(new_handler.sa_mask));
  new_handler.sa_flags = 0;
  ASSERT_THAT(sigaction(SIGABRT, &new_handler, &old_handler), Not(Eq(-1)));

  MessageWriter in;
  in.Push<int>(/*value=sig=*/SIGABRT);

  MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestRaise, &in, &out));
  EXPECT_THAT(sigabrt_received, Eq(true));
  ASSERT_THAT(out, SizeIs(1));  // should only contain return value.
  EXPECT_THAT(out.next<int>(), Eq(0));

  // Restore the default handler for SIGABRT.
  ASSERT_THAT(sigaction(SIGABRT, nullptr, &old_handler), Not(Eq(-1)));
  sigabrt_received = false;
}

// Tests enc_untrusted_send() by creating two sockets and sending a message
// across using enc_untrusted_send() and verifying the length of message
// received by the other socket.
TEST_F(HostCallTest, TestSend) {
  int socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  ASSERT_THAT(socket_fd, Gt(0));

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
  ASSERT_THAT(client_sock, Gt(0));

  // Attempt to connect the new socket to the local address. This call
  // will only succeed if the listen is successful.
  ASSERT_THAT(connect(client_sock, reinterpret_cast<struct sockaddr *>(&sa),
                      sizeof(sa)),
              Not(Eq(-1)));

  int connection_socket = accept(socket_fd, nullptr, nullptr);

  std::string msg = "Hello world!";

  MessageWriter in;
  in.Push<int>(/*value=sockfd=*/connection_socket);
  in.PushString(/*value=buf*/ msg);
  in.Push<size_t>(/*value=len*/ msg.length());
  in.Push<int>(/*value=flags*/ 0);
  MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestSend, &in, &out));
  ASSERT_THAT(out, SizeIs(1));
  EXPECT_THAT(out.next<int>(), Eq(msg.length()));

  close(socket_fd);
  close(client_sock);
  close(connection_socket);
}

// Tests enc_untrusted_sendmsg() by calling enc_untrusted_sendmsg() from inside
// the enclave with an array of 2 strings, and verifies the output size makes
// sense.
TEST_F(HostCallTest, TestSendMsg) {
  // Create a local socket and ensure that it is valid (fd > 0).
  int socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  ASSERT_THAT(socket_fd, Gt(0));

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

  // Create another local socket and ensure that it is valid (fd > 0).
  int client_sock = socket(AF_UNIX, SOCK_STREAM, 0);
  ASSERT_THAT(client_sock, Gt(0));

  // Attempt to connect the new socket to the local address. This call
  // will only succeed if the listen is successful.
  ASSERT_THAT(connect(client_sock, reinterpret_cast<struct sockaddr *>(&sa),
                      sizeof(sa)),
              Not(Eq(-1)));

  int connection_socket = accept(socket_fd, nullptr, nullptr);

  constexpr char kMsg1[] = "First sendmsg message.";
  constexpr char kMsg2[] = "Second sendmsg message.";

  MessageWriter in;
  in.Push<int>(/*value=sockfd=*/connection_socket);
  in.PushByReference(Extent{kMsg1, sizeof(kMsg1)});
  in.PushByReference(Extent{kMsg2, sizeof(kMsg2)});
  in.Push<int>(/*value=flags*/ 0);
  MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestSendMsg, &in, &out));
  ASSERT_THAT(out, SizeIs(1));
  EXPECT_THAT(out.next<int>(), Eq(sizeof(kMsg1) + sizeof(kMsg2)));

  close(socket_fd);
  close(client_sock);
  close(connection_socket);
}

// Tests enc_untrusted_recvmsg() by calling enc_untrusted_recvmsg() from inside
// the enclave with an array of 2 strings, and verifies the output size makes
// sense.
TEST_F(HostCallTest, TestRecvMsg) {
  int socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  ASSERT_THAT(socket_fd, Gt(0));

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

  // Create another local socket and ensure that it is valid (fd > 0).
  int client_sock = socket(AF_UNIX, SOCK_STREAM, 0);
  EXPECT_THAT(client_sock, Gt(0));

  // Attempt to connect the new socket to the local address. This call
  // will only succeed if the listen is successful.
  ASSERT_THAT(connect(client_sock, reinterpret_cast<struct sockaddr *>(&sa),
                      sizeof(sa)),
              Not(Eq(-1)));

  int connection_socket = accept(socket_fd, nullptr, nullptr);

  constexpr size_t kNumMsgs = 2;
  constexpr char kMsg1[] = "First sendmsg message.";
  constexpr char kMsg2[] = "Second sendmsg message.";

  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  struct iovec msg_iov[kNumMsgs];
  memset(msg_iov, 0, sizeof(*msg_iov));
  msg_iov[0].iov_base = reinterpret_cast<void *>(const_cast<char *>(kMsg1));
  msg_iov[0].iov_len = sizeof(kMsg1);
  msg_iov[1].iov_base = reinterpret_cast<void *>(const_cast<char *>(kMsg2));
  msg_iov[1].iov_len = sizeof(kMsg2);
  msg.msg_iov = msg_iov;
  msg.msg_iovlen = kNumMsgs;

  ASSERT_THAT(sendmsg(connection_socket, &msg, 0),
              Eq(sizeof(kMsg1) + sizeof(kMsg2)));

  MessageWriter in;
  in.Push<int>(/*value=sockfd=*/client_sock);
  in.Push<int>(sizeof(kMsg1));
  in.Push<int>(sizeof(kMsg2));
  in.Push<int>(/*value=flags*/ 0);
  MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestRecvMsg, &in, &out));
  ASSERT_THAT(out, SizeIs(1));
  EXPECT_THAT(out.next<int>(), Eq(sizeof(kMsg1) + sizeof(kMsg2)));

  close(socket_fd);
  close(client_sock);
  close(connection_socket);
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

  MessageWriter in;
  in.PushString(oldpath);
  in.PushString(newpath);

  MessageReader out;
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

  MessageWriter in;
  in.Push<int>(/*value=fd=*/fd);
  in.Push<off_t>(/*value=offset=*/2);
  in.Push<int>(/*value=whence=*/SEEK_SET);

  MessageReader out;
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

  MessageWriter in;
  in.Push<int>(/*value=fd=*/fd);
  in.Push<off_t>(/*value=offset=*/0);
  in.Push<int>(/*value=whence=*/1000);

  MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestLseek, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // should only contain the return value.
  EXPECT_THAT(out.next<off_t>(), Eq(-1));
}

// Tests enc_untrusted_mkdir() by calling it from inside the enclave and
// verifying that the directory created indeed exists.
TEST_F(HostCallTest, TestMkdir) {
  std::string path =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/dir_to_make");

  MessageWriter in;
  in.PushString(path);
  in.Push<mode_t>(/*value=mode=*/0777);

  MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestMkdir, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // should only contain the return value.
  EXPECT_THAT(out.next<int>(), Eq(0));

  struct stat sb;
  EXPECT_TRUE(stat(path.c_str(), &sb) == 0 && S_ISDIR(sb.st_mode));
}

TEST_F(HostCallTest, TestMkdirNonExistentPath) {
  std::string path = absl::StrCat("/non-existent-path/dir_to_make");

  MessageWriter in;
  in.PushString(path);
  in.Push<mode_t>(/*value=mode=*/0777);

  MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestMkdir, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // should only contain the return value.
  EXPECT_THAT(out.next<int>(), Eq(-1));
}

// Tests enc_untrusted_open() by using it to create a new file from inside the
// enclave and verifying that it exists.
TEST_F(HostCallTest, TestOpen) {
  std::string path =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/test_file.tmp");

  MessageWriter in;
  in.PushString(path);
  in.Push<int>(/*value=flags=*/O_RDWR | O_CREAT | O_TRUNC);
  in.Push<mode_t>(/*value=mode=*/S_IRUSR | S_IWUSR);

  MessageReader out;
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

  int fd = open(path.c_str(), O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
  ASSERT_NE(fd, -1);
  ASSERT_THAT(write(fd, path.c_str(), path.length() + 1),
              Eq(path.length() + 1));
  ASSERT_THAT(access(path.c_str(), F_OK), Eq(0));

  MessageWriter in;
  in.PushString(path);
  in.Push<int>(/*value=flags*/ O_RDWR | O_CREAT | O_TRUNC);
  in.Push<int>(/*value=mode*/ S_IRUSR | S_IWUSR);

  MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestOpen, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // should only contain the return value.
  EXPECT_THAT(out.next<int>(), Gt(0));
  EXPECT_THAT(access(path.c_str(), F_OK), Eq(0));

  // Make sure file is truncated as specified by O_TRUNC.
  struct stat sb;
  EXPECT_THAT(stat(path.c_str(), &sb), Eq(0));
  EXPECT_THAT(sb.st_size, Eq(0));
}

// Tests enc_untrusted_unlink() by deleting an existing file on the untrusted
// side from inside the enclave using the host call.
TEST_F(HostCallTest, TestUnlink) {
  std::string path =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/test_file.tmp");
  creat(path.c_str(), S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  ASSERT_NE(access(path.c_str(), F_OK), -1);

  MessageWriter in;
  in.PushString(path);

  MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestUnlink, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // should only contain the return value.
  EXPECT_THAT(out.next<int>(), Eq(0));
  EXPECT_THAT(access(path.c_str(), F_OK), Eq(-1));
}

TEST_F(HostCallTest, TestUnlinkNonExistingFile) {
  std::string path("obviously-illegal-file.tmp");
  ASSERT_THAT(access(path.c_str(), F_OK), Eq(-1));

  MessageWriter in;
  in.PushString(path);

  MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestUnlink, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // should only contain the return value.
  EXPECT_THAT(out.next<int>(), Eq(-1));
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

  MessageWriter in;
  in.PushString(oldpath);
  in.PushString(newpath);

  MessageReader out;
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
  MessageWriter in;
  in.Push<int>(/*value=fd=*/fd);
  in.Push<size_t>(/*value=count=*/expected_content.length() + 1);
  MessageReader out;
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
  MessageWriter in;
  in.Push<int>(/*value=fd=*/fd);
  in.PushString(write_buf);
  in.Push<size_t>(/*value=count=*/write_buf.length() + 1);

  MessageReader out;
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

  MessageWriter in;
  in.PushString(test_file);
  in.PushString(target);

  MessageReader out;
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

  MessageWriter in;
  in.PushString(sym_file);

  MessageReader out;
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
  std::string file_content = "test contents";
  ASSERT_THAT(write(fd, file_content.c_str(), file_content.length() + 1),
              Eq(file_content.length() + 1));

  MessageWriter in;
  constexpr int kTruncLen = 5;
  in.PushString(test_file);
  in.Push<off_t>(/*value=length=*/kTruncLen);

  MessageReader out;
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
  std::string file_content = "test contents";
  ASSERT_THAT(write(fd, file_content.c_str(), file_content.length() + 1),
              Eq(file_content.length() + 1));

  MessageWriter in2;
  constexpr int kTruncLen = 5;
  in2.Push<int>(/*value=fd=*/fd);
  in2.Push<off_t>(/*value=length=*/kTruncLen);

  MessageReader out2;
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
  MessageWriter in3;
  in3.Push<int>(/*value=fd=*/-1);
  in3.Push<off_t>(/*value=length=*/kTruncLen);

  MessageReader out3;
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

  MessageWriter in;
  in.PushString(dir_to_del);

  MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestRmdir, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // Should only contain return value.
  EXPECT_THAT(out.next<int>(), Eq(0));

  // Verify that the directory does not exist.
  struct stat sb;
  EXPECT_FALSE(stat(dir_to_del.c_str(), &sb) == 0 && S_ISDIR(sb.st_mode));
}

// Tests enc_untrusted_pipe2() by passing a message to be pipe'd, calling the
// method from inside the enclave, then writing and reading the message from the
// pipe and verifying the message contents.
TEST_F(HostCallTest, TestPipe2) {
  std::string msg_to_pipe = "hello, world";

  MessageWriter in;
  in.PushString(msg_to_pipe);
  MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestPipe2, &in, &out));
  ASSERT_THAT(out, SizeIs(2));
  EXPECT_THAT(out.next<int>(), Eq(0));  // Check return value.
  EXPECT_THAT(out.next().As<char>(), msg_to_pipe);
}

// Tests enc_untrusted_socket() by trying to obtain a valid (greater than 0)
// socket file descriptor when the method is called from inside the enclave.
TEST_F(HostCallTest, TestSocket) {
  for (int family : {AF_INET, AF_INET6}) {
    if ((family == AF_INET && !ipv4_supported_) ||
        (family == AF_INET6 && !ipv6_supported_)) {
      continue;
    }

    // Set up bidirectional IP socket.
    MessageWriter in;
    in.Push<int>(/*value=domain=*/family);
    in.Push<int>(/*value=type=*/SOCK_STREAM);
    in.Push<int>(/*value=protocol=*/0);

    MessageReader out;
    ASYLO_ASSERT_OK(client_->EnclaveCall(kTestSocket, &in, &out))
        << AddressFamily(family);
    // Should only contain return value.
    ASSERT_THAT(out, SizeIs(1)) << AddressFamily(family);
    EXPECT_THAT(out.next<int>(), Gt(0)) << AddressFamily(family);
  }

  // Set up bidirectional unix domain socket.
  MessageWriter in2;
  in2.Push<int>(/*value=domain=*/AF_UNIX);
  in2.Push<int>(/*value=type=*/SOCK_STREAM);
  in2.Push<int>(/*value=protocol=*/0);

  MessageReader out2;
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
  ASSERT_THAT(socket_fd, Gt(0));

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
  MessageWriter in;
  in.Push<int>(/*value=sockfd=*/socket_fd);
  in.Push<int>(/*value=backlog=*/8);

  MessageReader out;
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
  ASSERT_THAT(socket_fd, Gt(0));

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
  MessageWriter in;
  in.Push<int>(/*value=sockfd=*/socket_fd);
  in.Push<int>(/*value=how=*/SHUT_RDWR);

  MessageReader out;
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
  MessageWriter in;
  in.Push<int>(/*value=fd=*/fd);
  in.Push<int>(/*value=cmd=*/F_GETFL);
  in.Push<int>(/*value=arg=*/0);
  MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestFcntl, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // Should only contain return value.

  int klinux_fcntl_return = fcntl(fd, F_GETFL, 0);
  EXPECT_THAT(out.next<int>(), Eq(klinux_fcntl_return & 07777));

  // Turn on one or more of the file status flags for a descriptor.
  int flags_to_set = O_APPEND | O_NONBLOCK | O_RDONLY;
  MessageWriter in2;
  in2.Push<int>(/*value=fd=*/fd);
  in2.Push<int>(/*value=cmd=*/F_SETFL);
  in2.Push<int>(/*value=arg=*/flags_to_set);
  MessageReader out2;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestFcntl, &in2, &out2));
  ASSERT_THAT(out2, SizeIs(1));  // Should only contain return value.

  klinux_fcntl_return = fcntl(fd, F_SETFL, flags_to_set);
  EXPECT_THAT(out2.next<int>(), Eq(klinux_fcntl_return));
}

TEST_F(HostCallTest, TestFcntlInvalidCmd) {
  MessageWriter in;
  in.Push<int>(/*value=fd=*/0);
  in.Push<int>(/*value=cmd=*/10000000);
  in.Push<int>(/*value=arg=*/0);
  MessageReader out;
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

  MessageWriter in;
  in.PushString(test_file);
  in.Push<uid_t>(/*value=owner=*/getuid());
  in.Push<gid_t>(/*value=group=*/getgid());

  MessageReader out;
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

  MessageWriter in;
  in.Push<int>(/*value=fd=*/fd);
  in.Push<uid_t>(/*value=owner=*/getuid());
  in.Push<gid_t>(/*value=group=*/getgid());

  MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestFChown, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // Should only contain return value.
  EXPECT_THAT(out.next<int>(), Eq(0));

  // Attempt to fchown with invalid file descriptor, should return an error.
  MessageWriter in2;
  in2.Push<int>(/*value=fd=*/-1);
  in2.Push<uid_t>(/*value=owner=*/getuid());
  in2.Push<gid_t>(/*value=group=*/getgid());

  MessageReader out2;
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
  sockaddr_storage sas;
  for (int family : {AF_INET, AF_INET6}) {
    if ((family == AF_INET && !ipv4_supported_) ||
        (family == AF_INET6 && !ipv6_supported_)) {
      continue;
    }

    int socket_fd = socket(family, SOCK_STREAM, 0);
    ASSERT_THAT(socket_fd, Gt(0));

    // Bind the TCP socket to port 0 for any IP address. Once bind is successful
    // for UDP sockets application can operate on the socket descriptor for
    // sending or receiving data.
    memset(&sas, 0, sizeof(sockaddr_storage));
    switch (family) {
      case AF_INET: {
        sockaddr_in *sa = reinterpret_cast<sockaddr_in *>(&sas);
        sa->sin_family = AF_INET;
        sa->sin_addr.s_addr = htonl(INADDR_ANY);
        sa->sin_port = htons(0);
      } break;
      case AF_INET6: {
        sockaddr_in6 *sa = reinterpret_cast<sockaddr_in6 *>(&sas);
        sa->sin6_family = AF_INET6;
        sa->sin6_flowinfo = 0;
        sa->sin6_addr = in6addr_any;
        sa->sin6_port = htons(0);
      } break;
    }
    EXPECT_THAT(
        bind(socket_fd, reinterpret_cast<struct sockaddr *>(&sas), sizeof(sas)),
        Not(Eq(-1)))
        << strerror(errno) << AddressFamily(family);

    MessageWriter in;
    in.Push<int>(/*value=sockfd=*/socket_fd);
    in.Push<int>(/*value=level=*/SOL_SOCKET);
    in.Push<int>(/*value=optname=*/SO_REUSEADDR);
    in.Push<int>(/*value=option=*/1);

    MessageReader out;
    ASYLO_ASSERT_OK(client_->EnclaveCall(kTestSetSockOpt, &in, &out))
        << AddressFamily(family);
    ASSERT_THAT(out, SizeIs(1)) << AddressFamily(family);
    EXPECT_THAT(out.next<int>(), Gt(-1)) << AddressFamily(family);

    close(socket_fd);
  }
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

  MessageWriter in;
  in.Push<int>(/*value=fd=*/fd);
  in.Push<int>(/*value=operation=*/LOCK_EX);

  MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestFlock, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // Should only contain return value.
  EXPECT_THAT(out.next<int>(), Eq(0));
  flock(fd, LOCK_UN);
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
  MessageWriter in;
  in.PushString(path);
  in.Push<mode_t>(/*value=mode=*/DEFFILEMODE ^ S_IRUSR);

  MessageReader out;
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

  MessageWriter in;
  in.PushString(path);
  in.Push<mode_t>(/*value=mode=*/S_IWUSR);

  MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestChmod, &in, &out));
  ASSERT_THAT(out, SizeIs(1));
  EXPECT_THAT(out.next<int>(), Eq(access(path, F_OK)));
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
  MessageWriter in;
  in.Push<int>(fd);
  in.Push<mode_t>(/*value=mode=*/DEFFILEMODE ^ S_IRUSR);

  MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestFchmod, &in, &out));
  ASSERT_THAT(out, SizeIs(1));
  ASSERT_THAT(out.next<int>(), Eq(0));
  ASSERT_NE(stat(path.c_str(), &sb), -1);
  ASSERT_EQ((sb.st_mode & S_IRUSR), 0);
  EXPECT_NE(unlink(path.c_str()), -1);
}

// Tests enc_untrusted_fchmod() against a non-existent file descriptor.
TEST_F(HostCallTest, TestFchmodNonExistentFile) {
  MessageWriter in;
  in.Push<int>(/*value=fd=*/-1);
  in.Push<mode_t>(/*value=mode=*/S_IWUSR);

  MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestFchmod, &in, &out));
  ASSERT_THAT(out, SizeIs(1));
  EXPECT_THAT(out.next<int>(), Eq(-1));
}

// Tests enc_untrusted_umask() by calling it from inside the enclave to mask
// certain permission bits(S_IWGRP | S_IWOTH) and verifying newly created
// directory or file will not have masked permission.
TEST_F(HostCallTest, TestUmask) {
  MessageWriter in;
  in.Push<int>(/*value=mask=*/S_IWGRP | S_IWOTH);
  MessageReader out;
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

  MessageWriter in2;
  in2.Push<int>(/*value=mask=*/default_mode);
  MessageReader out2;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestUmask, &in2, &out2));
  ASSERT_THAT(out2, SizeIs(1));
  ASSERT_THAT(out2.next<mode_t>(), Eq(S_IWGRP | S_IWOTH));
}

// Tests enc_untrusted_inotify_init1() by initializing a new inotify instance
// from inside the enclave and verifying that a file descriptor associated with
// a new inotify event queue is returned. Only the return value, i.e. the file
// descriptor value is verified to be positive.
TEST_F(HostCallTest, TestInotifyInit1) {
  MessageWriter in;
  in.Push<int>(/*value=flags=*/IN_NONBLOCK);

  MessageReader out;
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
  MessageWriter in;
  in.Push<int>(inotify_fd);
  in.PushString(absl::GetFlag(FLAGS_test_tmpdir));

  in.Push<int>(IN_ALL_EVENTS);
  MessageReader out;
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
  EXPECT_THAT(event->mask, Eq(IN_CREATE));
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
  MessageWriter in;
  in.Push<int>(inotify_fd);
  in.Push<int>(wd);
  MessageReader out;
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
  MessageWriter in;

  MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestSchedYield, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // Should only contain return value.
  EXPECT_THAT(out.next<int>(), Eq(0));
}

// Tests enc_untrusted_sched_getaffinity by calling it inside and outside of the
// enclave, verifying that the bitmask is the same and verifying that the
// return value is 0.
TEST_F(HostCallTest, TestSchedGetAffinity) {
  cpu_set_t mask;
  sched_getaffinity(getpid(), sizeof(cpu_set_t), &mask);

  absl::flat_hash_set<int> cpus_set;

  for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
    if (CPU_ISSET(cpu, &mask)) {
      cpus_set.insert(cpu);
    }
  }

  MessageWriter in;
  in.Push<pid_t>(getpid());
  in.Push<uint64_t>(static_cast<uint64_t>(sizeof(cpu_set_t)));
  MessageReader out;

  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestSchedGetAffinity, &in, &out));
  EXPECT_THAT(out.next<int>(), Eq(0));

  // Number of cpus set should be the same, we add one since the message reader
  // also contains the return code.
  EXPECT_THAT(out.size(), Eq(cpus_set.size() + 1));
  while (out.hasNext()) {
    EXPECT_TRUE(cpus_set.contains(out.next<int>()));
  }
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

  MessageWriter in;
  in.Push<int>(/*value=fd=*/fd);

  MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestIsAtty, &in, &out));
  ASSERT_THAT(out, SizeIs(2));  // Should contain return value and errno.
  EXPECT_THAT(out.next<int>(), Eq(0));   // Check return value.
  EXPECT_THAT(out.next<int>(), ENOTTY);  // Check errno.
}

// Tests enc_untrusted_usleep() by sleeping for 1s, then ensuring that the
// return value is 0, and that at least 1 second passed during the usleep
// enclave call.
TEST_F(HostCallTest, TestUSleep) {
  MessageWriter in;

  // Push the sleep duration as unsigned int instead of useconds_t, storing
  // it as useconds_t causes a segfault when popping the argument from the
  // stack on the trusted side.
  in.Push<unsigned int>(/*value=usec=*/1000000);
  MessageReader out;

  absl::Time start = absl::Now();
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestUSleep, &in, &out));
  absl::Time end = absl::Now();

  auto duration = absl::ToInt64Milliseconds(end - start);

  ASSERT_THAT(out, SizeIs(1));  // Should only contain return value.
  EXPECT_THAT(out.next<int>(), Eq(0));
  EXPECT_GE(duration, 1000);
  EXPECT_LE(duration, 1600);
}

// Tests enc_untrusted_fstat() by creating a file and get stat of it, ensuring
// that the return value is 0 and returned stat contains expected value.
TEST_F(HostCallTest, TestFstat) {
  std::string path =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/test_file.tmp");

  // Make sure the file does not exist.
  if (access(path.c_str(), F_OK) == 0) {
    ASSERT_NE(unlink(path.c_str()), -1);
  }

  int fd = creat(path.c_str(), DEFFILEMODE);
  platform::storage::FdCloser fd_closer(fd);
  ASSERT_GE(fd, 0);
  ASSERT_NE(access(path.c_str(), F_OK), -1);
  MessageWriter in;

  in.Push<int>(fd);
  MessageReader out;

  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestFstat, &in, &out));
  ASSERT_THAT(out, SizeIs(14));  // Contains return value and 13 result stat
                                 // attributes.
  ASSERT_THAT(out.next<int>(), Eq(0));

  struct stat st, result_st;
  stat(path.c_str(), &st);
  LoadStatFromMessageReader(&out, &result_st);
  ASSERT_THAT(EqualsStat(&result_st, &st), Eq(true));
  EXPECT_NE(unlink(path.c_str()), -1);
}

// Tests enc_untrusted_lstat() by creating a file and get the stat from its
// symlinked path, ensuring that the return value is 0 and returned stat
// contains expected value.
TEST_F(HostCallTest, TestLstat) {
  std::string path =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/test_file.tmp");
  std::string sym_path =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/test_symlink.tmp");

  // Make sure the file does not exist.
  if (access(path.c_str(), F_OK) == 0) {
    ASSERT_NE(unlink(path.c_str()), -1);
  }

  int fd = creat(path.c_str(), DEFFILEMODE);
  platform::storage::FdCloser fd_closer(fd);
  ASSERT_GE(fd, 0);
  ASSERT_NE(access(path.c_str(), F_OK), -1);
  ASSERT_NE(symlink(path.c_str(), sym_path.c_str()), -1);
  MessageWriter in;

  in.PushString(sym_path);
  MessageReader out;

  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestLstat, &in, &out));
  ASSERT_THAT(out, SizeIs(14));  // Contains return value and 13 result stat
                                 // attributes.
  ASSERT_THAT(out.next<int>(), Eq(0));  // Check return value.

  struct stat st, result_st;
  lstat(sym_path.c_str(), &st);
  LoadStatFromMessageReader(&out, &result_st);
  ASSERT_THAT(EqualsStat(&result_st, &st), Eq(true));
  EXPECT_NE(unlink(path.c_str()), -1);
}

// Tests enc_untrusted_stat() by creating a file and get stat of it, ensuring
// that the return value is 0 and returned stat contains expected value.
TEST_F(HostCallTest, TestStat) {
  std::string path =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/test_file.tmp");

  // Make sure the file does not exist.
  if (access(path.c_str(), F_OK) == 0) {
    ASSERT_NE(unlink(path.c_str()), -1);
  }

  int fd = creat(path.c_str(), DEFFILEMODE);
  platform::storage::FdCloser fd_closer(fd);
  ASSERT_GE(fd, 0);
  ASSERT_NE(access(path.c_str(), F_OK), -1);
  MessageWriter in;

  in.PushString(path);
  MessageReader out;

  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestStat, &in, &out));
  ASSERT_THAT(out, SizeIs(14));  // Contains return value and 13 result stat
                                 // attributes.
  ASSERT_THAT(out.next<int>(), Eq(0));

  struct stat st, result_st;
  stat(path.c_str(), &st);
  LoadStatFromMessageReader(&out, &result_st);
  ASSERT_THAT(EqualsStat(&result_st, &st), Eq(true));
  EXPECT_NE(unlink(path.c_str()), -1);
}

// Tests enc_untrusted_statfs() by creating a file and confirming the file
// system it's on is not read-only.
TEST_F(HostCallTest, TestStatFs) {
  std::string path =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/test_file.tmp");

  // Make sure the file does not exist.
  if (access(path.c_str(), F_OK) == 0) {
    ASSERT_NE(unlink(path.c_str()), -1);
  }

  int fd = creat(path.c_str(), DEFFILEMODE);
  platform::storage::FdCloser fd_closer(fd);
  ASSERT_GE(fd, 0);
  ASSERT_NE(access(path.c_str(), F_OK), -1);
  MessageWriter in;

  in.PushString(path);
  MessageReader out;

  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestStatFs, &in, &out));
  ASSERT_THAT(out, SizeIs(17));  // Contains return value and 16 result statfs
                                 // attributes.
  ASSERT_THAT(out.next<int>(), Eq(0));  // Success return value.

  struct statfs st, result_st;
  statfs(path.c_str(), &st);
  LoadStatFsFromMessageReader(&out, &result_st);
  ASYLO_ASSERT_OK(CheckStatFs(&result_st, &st));
  EXPECT_NE(unlink(path.c_str()), -1);
}

// Tests enc_untrusted_pread64() by reading a non-empty file, ensuring that the
// return value matches the input length and returned buffer contains the
// expected characters.
TEST_F(HostCallTest, TestPread64) {
  MessageWriter in;

  std::string path =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/test_file.tmp");
  std::string content = "hello";

  // Make sure the file does not exist.
  if (access(path.c_str(), F_OK) == 0) {
    EXPECT_NE(unlink(path.c_str()), -1);
  }

  int fd = open(path.c_str(), O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
  platform::storage::FdCloser fd_closer(fd);

  ASSERT_GE(fd, 0);
  ASSERT_NE(access(path.c_str(), F_OK), -1);
  ASSERT_THAT(write(fd, content.c_str(), content.length()),
              Eq(content.length()));
  off_t offset = 1;
  int len = 2;

  in.Push<int>(fd);
  in.Push<int>(len);
  in.Push<off_t>(offset);
  MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestPread64, &in, &out));
  ASSERT_THAT(out, SizeIs(2));  // Should contain return value and buffer.
  ASSERT_THAT(out.next<int>(), Eq(len));
  char *buf = out.next().As<char>();
  // Read is not expected to put eof at the end of buffer.
  buf[len] = '\0';
  EXPECT_STREQ(buf, content.substr(offset, len).c_str());
}

// Tests enc_untrusted_pwrite64() by writing to a non-empty file, ensuring that
// the return value matches the input length and file is written as expected.
TEST_F(HostCallTest, TestPwrite64) {
  MessageWriter in;

  std::string path =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/test_file.tmp");
  std::string content = "hello!";
  std::string message_write = " world!abc";

  // Make sure the file does not exist.
  if (access(path.c_str(), F_OK) == 0) {
    EXPECT_NE(unlink(path.c_str()), -1);
  }

  int fd = open(path.c_str(), O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
  platform::storage::FdCloser fd_closer(fd);

  ASSERT_GE(fd, 0);
  ASSERT_NE(access(path.c_str(), F_OK), -1);
  ASSERT_THAT(write(fd, content.c_str(), content.length()),
              Eq(content.length()));
  off_t offset = 5;
  int len = 7;

  in.Push<int>(fd);
  in.PushString(message_write);
  in.Push<int>(len);
  in.Push<off_t>(offset);
  MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestPwrite64, &in, &out));

  ASSERT_THAT(out, SizeIs(1));  // Should only contain return value.
  ASSERT_THAT(out.next<int>(), Eq(len));
  char read_buf[20];
  // The write operation inserts first 7 characters of ' world!abc' from offset
  // 5(the '!' character) to the file, the result should be 'hello world!'.
  EXPECT_THAT(pread64(fd, read_buf, 20, 0), Eq(12));
  read_buf[12] = '\0';
  EXPECT_THAT(read_buf, StrEq("hello world!"));
}

// Tests enc_untrusted_wait() by forking the current process, and having the
// child process sleep for 5 seconds, then exit. The parent process performs a
// wait, and once the wait completes, we make sure that the wait returns the pid
// of the child process.
TEST_F(HostCallTest, TestWait) {
  pid_t pid = fork();  // child process to wait on
  if (pid == 0) {
    sleep(1);
    _exit(0);
  } else {
    int returnpid = -1;
    while (returnpid != pid) {
      // We do not push the empty status pointer on the stack since we would
      // need to create one in the enclave anyways.
      MessageWriter in;
      MessageReader out;
      ASYLO_ASSERT_OK(client_->EnclaveCall(kTestWait, &in, &out));
      ASSERT_THAT(out,
                  SizeIs(1));  // Should only contain return value.
      returnpid = out.next<int>();
    }

    EXPECT_THAT(returnpid, Eq(pid));
  }
}

// Tests enc_untrusted_sysconf() by querying for a named value from inside the
// enclave using enc_untrusted_sysconf() and comparing the value obtained for
// the same name value on the host using a native sysconf() call.
TEST_F(HostCallTest, TestSysconf) {
  MessageWriter in;
  in.Push<int>(/*value=name=*/_SC_NPROCESSORS_ONLN);

  MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestSysconf, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // Should only contain return value.
  ASSERT_THAT(out.next<int64_t>(), Eq(sysconf(_SC_NPROCESSORS_ONLN)));
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

  MessageWriter in;
  in.Push<int>(fd);

  MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestClose, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // should only contain return value.
  EXPECT_THAT(out.next<int>(), Eq(0));
}

// Tries closing a non-existent file handle by calling enc_untrusted_close()
// from inside the enclave.
TEST_F(HostCallTest, TestCloseNonExistentFile) {
  MessageWriter in;
  in.Push<int>(/*value=fd=*/123456);

  MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestClose, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // should only contain return value.
  EXPECT_THAT(out.next<int>(), Eq(-1));
}

// Tests enc_untrusted_realloc() by doing the following -
// - Allocating and populating a location using malloc on the untrusted side
// with the sttring "hello".
// - Expanding malloc'd space by calling enc_untrusted_realloc().
// - Appending the first string with "world" on the untrusted side.
// - Verifying the combined string for correctness.
TEST_F(HostCallTest, TestRealloc) {
  const std::string hello = "hello";
  const std::string world = "world";
  void *ptr1 = malloc(hello.size());
  memcpy(ptr1, hello.c_str(), hello.size());

  MessageWriter in;
  in.Push(reinterpret_cast<uint64_t>(ptr1));
  in.Push(static_cast<uint64_t>(hello.size() + world.size() + 1));

  MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestRealloc, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // Should only contain return value.
  void *ptr2 = out.next<void *>();
  memcpy(reinterpret_cast<char *>(ptr2) + hello.size(), world.c_str(),
         world.size() + 1);
  ASSERT_THAT(reinterpret_cast<char *>(ptr2), StrEq(hello + world));
  free(ptr2);
}

// Tests enc_untrusted_sleep() by sleeping for 1s, then ensuring that the
// return value is 0, and that at least 1 second passed during the sleep
// enclave call.
TEST_F(HostCallTest, TestSleep) {
  MessageWriter in;

  in.Push<uint32_t>(/*value=seconds=*/1);
  MessageReader out;

  absl::Time start = absl::Now();
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestSleep, &in, &out));
  absl::Time end = absl::Now();

  auto duration = absl::ToInt64Nanoseconds(end - start);

  ASSERT_THAT(out, SizeIs(1));  // Should only contain return value.
  EXPECT_THAT(out.next<int>(), Eq(0));
  // Allow some inprecision on sleep time inside the enclave call
  EXPECT_GE(duration, 0.995 * kNanosecondsPerSecond);
  EXPECT_LE(duration,
            1.6 * kNanosecondsPerSecond);  // Allow sufficient time padding for
                                           // EnclaveCall to perform
                                           // enc_untrusted_sleep() and return
                                           // from the enclave.
}

// Tests enc_untrusted_nanosleep() by sleeping for 0.5 seconds, ensuring that
// the return value is 0, and that at least 0.5 seconds passed during the
// enclave call.
TEST_F(HostCallTest, TestNanosleep) {
  MessageWriter in;
  struct timespec klinux_req;
  klinux_req.tv_sec = 0;
  klinux_req.tv_nsec = 0.5 * kNanosecondsPerSecond;  // 0.5 seconds.

  in.Push<struct timespec>(klinux_req);

  MessageReader out;

  absl::Time start = absl::Now();
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestNanosleep, &in, &out));
  absl::Time end = absl::Now();

  auto duration = absl::ToInt64Nanoseconds(end - start);

  ASSERT_THAT(out, SizeIs(2));  // Should contain return value and klinux_rem.
  EXPECT_THAT(out.next<int>(), Eq(0));
  EXPECT_GE(duration, 0.5 * kNanosecondsPerSecond);
  EXPECT_LE(duration,
            1.1 * kNanosecondsPerSecond);  // Allow sufficient time padding for
                                           // EnclaveCall to perform
                                           // enc_untrusted_nanosleep() and
                                           // return from the enclave.

  struct timespec klinux_rem = out.next<struct timespec>();
  EXPECT_THAT(klinux_rem.tv_sec, Eq(0));
  EXPECT_THAT(klinux_rem.tv_nsec, Eq(0));
}

// Tests enc_untrusted_clock_gettime() by calling the function from inside the
// enclave, doing some work (sleep 1 second), then calling the function
// again and verifying the time elapsed.
TEST_F(HostCallTest, TestClockGettimeMonotonicDifference) {
  MessageWriter in1, in2;
  MessageReader out1, out2;
  struct timespec start, end;

  in1.Push<int64_t>(/*value=clk_id=*/CLOCK_MONOTONIC);
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestClockGettime, &in1, &out1));
  ASSERT_THAT(out1, SizeIs(2));  // Should contain return value and start.
  EXPECT_THAT(out1.next<int>(), Eq(0));

  start = out1.next<struct timespec>();
  sleep(1);

  in2.Push<int64_t>(/*value=clk_id=*/CLOCK_MONOTONIC);
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestClockGettime, &in2, &out2));
  ASSERT_THAT(out2, SizeIs(2));  // Should contain return value and end.
  EXPECT_THAT(out2.next<int>(), Eq(0));

  end = out2.next<struct timespec>();

  uint64_t diff = TimeSpecDiffInNanoseconds(&end, &start);
  EXPECT_GE(diff, kNanosecondsPerSecond);
  EXPECT_LE(diff, kNanosecondsPerSecond * 1.6);
}

// Tests the host clock against the enclave's idea of real time.
TEST_F(HostCallTest, TestClockGettimeRealTimeVsHost) {
  MessageWriter in;
  MessageReader out;
  struct timespec ts;

  uint64_t host_time_ns = absl::GetCurrentTimeNanos();
  EXPECT_LT(kNanosecondsPerSecond, host_time_ns);

  in.Push<int64_t>(/*value=clk_id=*/CLOCK_REALTIME);
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestClockGettime, &in, &out));
  ASSERT_THAT(out, SizeIs(2));  // Should contain return value and time.
  EXPECT_THAT(out.next<int>(), Eq(0));

  ts = out.next<struct timespec>();
  uint64_t enc_time_ns = TimeSpecToNanoseconds(&ts);
  EXPECT_LT(kNanosecondsPerSecond, enc_time_ns);

  int64_t delta = enc_time_ns - host_time_ns;
  if (delta < 0) delta = -delta;
  // Verify the clock time got inside the enclave is within two seconds from
  // the host time, to compensate for the time to exit the enclave.
  EXPECT_LE(delta, kNanosecondsPerSecond * 2);
}

// Tests enc_untrusted_bind() by calling the function from inside the enclave
// and verifying the return value.
TEST_F(HostCallTest, TestBind) {
  int socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  ASSERT_THAT(socket_fd, Gt(0));

  std::string sockpath =
      absl::StrCat("/tmp/", absl::ToUnixNanos(absl::Now()), ".sock");

  struct sockaddr_un klinux_sock_un;
  memset(&klinux_sock_un, 0, sizeof(struct sockaddr_un));
  klinux_sock_un.sun_family = AF_UNIX;
  strncpy(klinux_sock_un.sun_path, sockpath.c_str(),
          sizeof(klinux_sock_un.sun_path) - 1);

  MessageWriter in;
  in.Push<int>(socket_fd);
  in.Push<struct sockaddr_un>(klinux_sock_un);

  MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestBind, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // Should only contain the return value.
  EXPECT_THAT(out.next<int>(), Eq(0));
}

// Tests enc_untrusted_connect() by calling the function from inside the
// enclave and verifying the return value, then using sendmsg to send a message
// to the connected socket and verifying its return value.
TEST_F(HostCallTest, TestConnect) {
  int socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  ASSERT_THAT(socket_fd, Gt(0));

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

  // Create another local socket and ensure that it is valid (fd > 0).
  int client_sock = socket(AF_UNIX, SOCK_STREAM, 0);
  EXPECT_THAT(client_sock, Gt(0));

  // Attempt to connect the new socket to the local address using
  // enc_untrusted_connect(). This call will only succeed if the listen is
  // successful.
  MessageWriter in;
  in.Push<int>(client_sock);
  in.Push<struct sockaddr_un>(sa);

  MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestConnect, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // Should only contain the return value.
  EXPECT_THAT(out.next<int>(), Not(Eq(-1)));

  int connection_socket = accept(socket_fd, nullptr, nullptr);

  constexpr char kMsg[] = "sendmsg message.";
  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));

  struct iovec msg_iov[1];
  memset(msg_iov, 0, sizeof(*msg_iov));
  msg_iov[0].iov_base = reinterpret_cast<void *>(const_cast<char *>(kMsg));
  msg_iov[0].iov_len = sizeof(kMsg);
  msg.msg_iov = msg_iov;
  msg.msg_iovlen = 1;

  EXPECT_THAT(sendmsg(connection_socket, &msg, 0), Eq(sizeof(kMsg)));

  close(socket_fd);
  close(client_sock);
  close(connection_socket);
}

// Tests enc_untrusted_getsockname() by creating and binding a socket with a
// path, then calling the function and verifying the path value.
TEST_F(HostCallTest, TestGetSockname) {
  int socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  ASSERT_THAT(socket_fd, Gt(0));

  std::string sockpath =
      absl::StrCat("/tmp/", absl::ToUnixNanos(absl::Now()), ".sock");

  // Create a local socket address and bind the socket to it.
  sockaddr_un sa = {};
  sa.sun_family = AF_UNIX;
  strncpy(&sa.sun_path[0], sockpath.c_str(), sizeof(sa.sun_path) - 1);
  ASSERT_THAT(
      bind(socket_fd, reinterpret_cast<struct sockaddr *>(&sa), sizeof(sa)),
      Not(Eq(-1)));

  MessageWriter in;
  in.Push<int>(socket_fd);
  MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestGetSockname, &in, &out));
  ASSERT_THAT(out,
              SizeIs(2));  // Should contain the return value and sockaddr.
  EXPECT_THAT(out.next<int>(), Eq(0));  // Check return value.
  auto sock_un = out.next<struct sockaddr_un>();
  EXPECT_THAT(sock_un.sun_family, Eq(AF_UNIX));
  EXPECT_THAT(sock_un.sun_path, StrEq(sockpath));
}

// Tests enc_untrusted_accept() by creating two sockets, calling
// enc_untrusted_accept() and sending a message across using send() and
// verifying the length of message received by the other socket.
TEST_F(HostCallTest, TestAccept) {
  int server_sock = socket(AF_UNIX, SOCK_STREAM, 0);
  ASSERT_THAT(server_sock, Gt(0));
  int client_sock = socket(AF_UNIX, SOCK_STREAM, 0);
  ASSERT_THAT(client_sock, Gt(0));

  std::string sockpath =
      absl::StrCat("/tmp/", absl::ToUnixNanos(absl::Now()), ".sock");

  // Create a local socket address and bind the socket to it.
  sockaddr_un sa = {};
  sa.sun_family = AF_UNIX;
  strncpy(&sa.sun_path[0], sockpath.c_str(), sizeof(sa.sun_path) - 1);
  ASSERT_THAT(
      bind(server_sock, reinterpret_cast<struct sockaddr *>(&sa), sizeof(sa)),
      Not(Eq(-1)));
  ASSERT_THAT(listen(server_sock, 8), Not(Eq(-1)));

  // Attempt to connect the new socket to the local address. This call
  // will only succeed if the listen is successful.
  ASSERT_THAT(connect(client_sock, reinterpret_cast<struct sockaddr *>(&sa),
                      sizeof(sa)),
              Not(Eq(-1)));

  MessageWriter in;
  in.Push<int>(server_sock);
  MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestAccept, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // Should only contain return value.
  int connection_socket = out.next<int>();
  EXPECT_THAT(connection_socket, Gt(0));

  std::string msg = "Hello world!";
  EXPECT_THAT(send(connection_socket, msg.c_str(), msg.length(), 0),
              Eq(msg.length()));

  close(server_sock);
  close(client_sock);
  close(connection_socket);
}

// Tests enc_untrusted_select() by performing the following -
// 1. Creating a file, registering the file descriptor for read operation with
// the host call (adding to readfds).
// 2. Creating a new thread that sleeps for certain time (to let the main thread
// enter the enclave), then writes to the file.
// 3. Calling the host call from the main thread with a large enough timeout and
// expecting the write to occur so that data is available in the file to read,
// and the activity is captured by select.
// 4. Verifying the return value and FD_ISSET for the file descriptor.
TEST_F(HostCallTest, TestSelect) {
  std::string test_file =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/test_file.tmp");

  int fd =
      open(test_file.c_str(), O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
  platform::storage::FdCloser fd_closer(fd);
  ASSERT_GE(fd, 0);
  ASSERT_NE(access(test_file.c_str(), F_OK), -1);

  fd_set rfds;
  FD_ZERO(&rfds);
  FD_SET(fd, &rfds);

  MessageWriter in;
  in.Push<int>(/*value=nfds=*/fd + 1);
  in.Push<fd_set>(/*value=readfds=*/rfds);
  MessageReader out;

  std::thread write_thread([fd]() {
    sleep(2);  // Allow enough time for other thread to enter the enclave and
               // call select.
    std::string writebuf = "stuff being written";
    EXPECT_THAT(write(fd, writebuf.c_str(), writebuf.length() + 1), Gt(0));
  });
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestSelect, &in, &out));
  write_thread.join();

  ASSERT_THAT(out, SizeIs(2));  // Should contain return value and readfds.
  EXPECT_THAT(out.next<int>(), Gt(0));  // Check return value.
  rfds = out.next<fd_set>();
  EXPECT_THAT(FD_ISSET(fd, &rfds), Gt(0));

  EXPECT_NE(unlink(test_file.c_str()), -1);
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
  std::string file_content = "test contents";
  ASSERT_THAT(write(fd, file_content.c_str(), file_content.length() + 1),
              Eq(file_content.length() + 1));

  MessageWriter in;
  in.Push<int>(fd);

  MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestFsync, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // Should only contain return value.
  EXPECT_THAT(out.next<int>(), Eq(0));
  EXPECT_NE(unlink(test_file.c_str()), -1);
}

// Tests enc_untrusted_getsockopt() by comparing the return and optval values
// from enc_untrusted_getsockopt() and getsockopt() on the host.
TEST_F(HostCallTest, TestGetSockOpt) {
  for (int family : {AF_INET, AF_INET6}) {
    if ((family == AF_INET && !ipv4_supported_) ||
        (family == AF_INET6 && !ipv6_supported_)) {
      continue;
    }

    // Create a TCP socket (SOCK_STREAM) with specified IP Family.
    int socket_fd = socket(family, SOCK_STREAM, IPPROTO_TCP);
    ASSERT_THAT(socket_fd, Gt(0)) << strerror(errno) << AddressFamily(family);

    int optval_expected = -1;
    socklen_t optlen_expected = sizeof(optval_expected);
    EXPECT_THAT(getsockopt(socket_fd, SOL_SOCKET, SO_KEEPALIVE,
                           &optval_expected, &optlen_expected),
                Eq(0))
        << strerror(errno) << AddressFamily(family);

    MessageWriter in;
    in.Push<int>(socket_fd);
    MessageReader out;
    ASYLO_ASSERT_OK(client_->EnclaveCall(kTestGetSockOpt, &in, &out))
        << AddressFamily(family);
    // Should contain return value and optval.
    ASSERT_THAT(out, SizeIs(2)) << AddressFamily(family);
    EXPECT_THAT(out.next<int>(), Eq(0)) << AddressFamily(family);
    EXPECT_THAT(out.next<int>(), Eq(optval_expected)) << AddressFamily(family);
  }
}

// Tests enc_untrusted_getaddrinfo() by calling the method inside the enclave
// and getaddrinfo() on the host and comparing the values of hostnames obtained.
TEST_F(HostCallTest, TestGetAddrInfo) {
  std::string node("localhost");  // We can't have something like www.google.com
                                  // here as that could resolve to different
                                  // lookups in addrinfo each time.
  std::vector<std::string> expected_hostnames, actual_hostnames;

  // Call getaddrinfo() on the host.
  struct addrinfo *host_result;
  EXPECT_THAT(getaddrinfo(node.c_str(), nullptr, nullptr, &host_result), Eq(0));

  // Loop over all returned results and do inverse lookup.
  for (struct addrinfo *res = host_result; res != nullptr; res = res->ai_next) {
    char hostname[NI_MAXHOST];
    EXPECT_THAT(getnameinfo(res->ai_addr, res->ai_addrlen, hostname, NI_MAXHOST,
                            nullptr, 0, 0),
                Eq(0));
    if (*hostname != '\0')
      expected_hostnames.emplace_back(std::string(hostname));
  }
  freeaddrinfo(host_result);

  // Call enc_untrusted_getaddrinfo().
  MessageWriter in;
  in.PushString(node);
  MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestGetAddrInfo, &in, &out));
  ASSERT_THAT(
      out,
      SizeIs(1 + expected_hostnames
                     .size()));  // Should contain return value and sockaddrs
                                 // (converted to klinux_sockaddr) from addrinfo
                                 // linked list inside the enclave.
  EXPECT_THAT(out.next<int>(), Eq(0));  // Check return value.

  while (out.hasNext()) {
    auto klinux_sockaddr_buffer = out.next();
    char hostname[NI_MAXHOST];
    EXPECT_THAT(
        getnameinfo(reinterpret_cast<sockaddr *>(klinux_sockaddr_buffer.data()),
                    klinux_sockaddr_buffer.size(), hostname, NI_MAXHOST,
                    nullptr, 0, 0),
        Eq(0));
    if (*hostname != '\0') actual_hostnames.emplace_back(std::string(hostname));
  }

  EXPECT_THAT(actual_hostnames, SizeIs(expected_hostnames.size()));
  for (const auto &actual_hostname : actual_hostnames) {
    EXPECT_THAT(std::find(expected_hostnames.begin(), expected_hostnames.end(),
                          actual_hostname),
                Not(Eq(expected_hostnames.end())));
  }
}

// Tests enc_untrusted_poll() by comparing the return value and pollfd obtained
// from calling the function from inside the enclave and native poll() on the
// host.
TEST_F(HostCallTest, TestPoll) {
  struct pollfd fds_in[2], fds_expected[2];
  // Watch stdin for input.
  fds_in[0].fd = STDIN_FILENO;
  fds_in[0].events = POLLIN;
  fds_expected[0].fd = STDIN_FILENO;
  fds_expected[0].events = POLLIN;
  // Watch stdout for ability to write.
  fds_in[1].fd = STDOUT_FILENO;
  fds_in[1].events = POLLOUT;
  fds_expected[1].fd = STDOUT_FILENO;
  fds_expected[1].events = POLLOUT;

  ASSERT_THAT(poll(fds_expected, 2, 1000), Not(Eq(-1)));

  MessageWriter in;
  in.PushByCopy(/*value=fds=*/Extent{reinterpret_cast<void *>(fds_in),
                                     2 * sizeof(struct pollfd)});
  in.Push(/*value=nfds=*/2);
  in.Push(/*value=timeout=*/1000);
  MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestPoll, &in, &out));
  ASSERT_THAT(out, SizeIs(2));  // Should contain return value and pollfd array.
  EXPECT_THAT(out.next<int>(), Gt(0));

  struct pollfd *fds_out = out.next().As<pollfd>();
  EXPECT_THAT(fds_out[0].revents, Eq(fds_expected[0].revents));
  EXPECT_THAT(fds_out[1].revents, Eq(fds_expected[1].revents));
}

// Tests enc_untrusted_utime() by updating the access and modification times of
// a file from inside the enclave and verifying on the host that stat reflects
// the updated access and modification times.
TEST_F(HostCallTest, TestUtime) {
  std::string test_file =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/test_file.tmp");
  int fd =
      open(test_file.c_str(), O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
  platform::storage::FdCloser fd_closer(fd);
  ASSERT_GE(fd, 0);
  ASSERT_NE(access(test_file.c_str(), F_OK), -1);

  struct utimbuf times {};
  constexpr time_t modtime_expected = 12345678;
  constexpr time_t actime_expected = 87654321;
  times.modtime = modtime_expected;
  times.actime = actime_expected;

  MessageWriter in;
  in.PushString(test_file);
  in.Push<struct utimbuf>(times);
  MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestUtime, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // Should only contain the return value.
  EXPECT_THAT(out.next<int>(), Eq(0));

  struct stat statbuf {};
  EXPECT_THAT(stat(test_file.c_str(), &statbuf), Eq(0));
  EXPECT_THAT(statbuf.st_atim.tv_sec, Eq(actime_expected));
  EXPECT_THAT(statbuf.st_atim.tv_nsec, Eq(0));
  EXPECT_THAT(statbuf.st_mtim.tv_sec, Eq(modtime_expected));
  EXPECT_THAT(statbuf.st_mtim.tv_nsec, Eq(0));
}

// Tests enc_untrusted_getrusage() by making the call from inside the enclave
// and on the host, and ensuring that the difference for rusage.ru_utime and
// rusage.ru_stime between host and enclave versions is less than a second.
TEST_F(HostCallTest, GetRusageTest) {
  struct rusage usage_expected {};
  ASSERT_THAT(getrusage(RUSAGE_SELF, &usage_expected), Eq(0));

  MessageWriter in;
  in.Push<int>(RUSAGE_SELF);
  MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestGetRusage, &in, &out));
  ASSERT_THAT(out,
              SizeIs(2));  // Should contain the return value and struct rusage.
  EXPECT_THAT(out.next<int>(), Eq(0));

  struct rusage usage_actual = out.next<struct rusage>();

  uint64_t diff_utime = TimeValDiffInMicroseconds(&usage_actual.ru_utime,
                                                  &usage_expected.ru_utime);
  EXPECT_LE(diff_utime, kMicrosecondsPerSecond);

  uint64_t diff_stime = TimeValDiffInMicroseconds(&usage_actual.ru_stime,
                                                  &usage_expected.ru_stime);
  EXPECT_LE(diff_stime, kMicrosecondsPerSecond);
}

}  // namespace
}  // namespace host_call
}  // namespace asylo
