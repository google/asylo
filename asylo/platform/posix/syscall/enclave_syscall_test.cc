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

#include "asylo/platform/posix/syscall/enclave_syscall.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/platform/posix/syscall/enclave_syscall_helper.h"
#include "asylo/platform/system_call/sysno.h"

using testing::Exactly;
using testing::Return;

namespace asylo {
namespace system_call {
namespace {

class MockEnclaveSyscallHelper : public EnclaveSyscallHelper {
 public:
  MOCK_METHOD(int64_t, DispatchSyscall,
              (int sysno, uint64_t args[], size_t nargs), (override));
};

class MockIOManager : public asylo::io::IOManager {
 public:
  virtual ~MockIOManager() = default;

  MOCK_METHOD(int, Access, (const char* path, int mode), (override));
  MOCK_METHOD(int, Close, (int fd), (override));
  MOCK_METHOD(int, Open, (const char* path, int flags, mode_t mode),
              (override));
  MOCK_METHOD(int, Dup, (int oldfd), (override));
  MOCK_METHOD(int, Dup2, (int oldfd, int newfd), (override));
  MOCK_METHOD(int, Pipe, (int pipefd[2], int flags), (override));
  MOCK_METHOD(int, Select,
              (int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds,
               struct timeval* timeout),
              (override));
  MOCK_METHOD(int, Poll, (struct pollfd * fds, nfds_t nfds, int timeout),
              (override));
  MOCK_METHOD(int, EpollCreate, (int size), (override));
  MOCK_METHOD(int, EpollCtl,
              (int epfd, int op, int fd, struct epoll_event* event),
              (override));
  MOCK_METHOD(int, EpollWait,
              (int epfd, struct epoll_event* events, int maxevents,
               int timeout),
              (override));
  MOCK_METHOD(int, EventFd, (unsigned int initval, int flags), (override));
  MOCK_METHOD(int, InotifyInit, (bool non_block), (override));
  MOCK_METHOD(int, InotifyAddWatch,
              (int fd, const char* pathname, uint32_t mask), (override));
  MOCK_METHOD(int, InotifyRmWatch, (int fd, int wd), (override));
  MOCK_METHOD(int, Read, (int fd, char* buf, size_t count), (override));
  MOCK_METHOD(int, Write, (int fd, const char* buf, size_t count), (override));
  MOCK_METHOD(int, Chown, (const char* path, uid_t owner, gid_t group),
              (override));
  MOCK_METHOD(int, FChOwn, (int fd, uid_t owner, gid_t group), (override));
  MOCK_METHOD(int, Link, (const char* from, const char* to), (override));
  MOCK_METHOD(int, Unlink, (const char* pathname), (override));
  MOCK_METHOD(ssize_t, ReadLink, (const char* path, char* buf, size_t bufsize),
              (override));
  MOCK_METHOD(int, SymLink, (const char* from, const char* to), (override));
  MOCK_METHOD(int, Truncate, (const char* path, off_t length), (override));
  MOCK_METHOD(int, FTruncate, (int fd, off_t length), (override));
  MOCK_METHOD(int, Stat, (const char* pathname, struct stat* stat_buffer),
              (override));
  MOCK_METHOD(int, LStat, (const char* pathname, struct stat* stat_buffer),
              (override));
  MOCK_METHOD(int, StatFs, (const char* pathname, struct statfs* statfs_buffer),
              (override));
  MOCK_METHOD(int, FStat, (int fd, struct stat* stat_buffer), (override));
  MOCK_METHOD(int, FStatFs, (int fd, struct statfs* statfs_buffer), (override));
  MOCK_METHOD(int, ChMod, (const char* pathname, mode_t mode), (override));
  MOCK_METHOD(int, FChMod, (int fd, mode_t mode), (override));
  MOCK_METHOD(int, LSeek, (int fd, off_t offset, int whence), (override));
  MOCK_METHOD(int, FCntl, (int fd, int cmd, int64_t arg), (override));
  MOCK_METHOD(int, FSync, (int fd), (override));
  MOCK_METHOD(int, FDataSync, (int fd), (override));
  MOCK_METHOD(int, FLock, (int fd, int operation), (override));
  MOCK_METHOD(int, Ioctl, (int fd, int request, void* argp), (override));
  MOCK_METHOD(int, Mkdir, (const char* pathname, mode_t mode), (override));
  MOCK_METHOD(int, RmDir, (const char* pathname), (override));
  MOCK_METHOD(int, Rename, (const char* oldpath, const char* newpath),
              (override));
  MOCK_METHOD(int, Utime, (const char* filename, const struct utimbuf* times),
              (override));
  MOCK_METHOD(int, Utimes,
              (const char* filename, const struct timeval times[2]),
              (override));
  MOCK_METHOD(ssize_t, Writev, (int fd, const struct iovec* iov, int iovcnt),
              (override));
  MOCK_METHOD(ssize_t, Readv, (int fd, const struct iovec* iov, int iovcnt),
              (override));
  MOCK_METHOD(ssize_t, PRead, (int fd, void* buf, size_t count, off_t offset),
              (override));
  MOCK_METHOD(mode_t, Umask, (mode_t mask), (override));
  MOCK_METHOD(int, GetRLimit, (int resource, struct rlimit* rlim), (override));
  MOCK_METHOD(int, SetRLimit, (int resource, const struct rlimit* rlim),
              (override));
  MOCK_METHOD(int, SetSockOpt,
              (int sockfd, int level, int option_name, const void* option_value,
               socklen_t option_len),
              (override));
  MOCK_METHOD(int, Connect,
              (int sockfd, const struct sockaddr* addr, socklen_t addrlen),
              (override));
  MOCK_METHOD(int, Shutdown, (int sockfd, int how), (override));
  MOCK_METHOD(ssize_t, Send,
              (int sockfd, const void* buf, size_t len, int flags), (override));
  MOCK_METHOD(int, Socket, (int domain, int type, int protocol), (override));
  MOCK_METHOD(int, GetSockOpt,
              (int sockfd, int level, int optname, void* optval,
               socklen_t* optlen),
              (override));
  MOCK_METHOD(int, Accept,
              (int sockfd, struct sockaddr* addr, socklen_t* addrlen),
              (override));
  MOCK_METHOD(int, Bind,
              (int sockfd, const struct sockaddr* addr, socklen_t addrlen),
              (override));
  MOCK_METHOD(int, Listen, (int sockfd, int backlog), (override));
  MOCK_METHOD(ssize_t, SendMsg,
              (int sockfd, const struct msghdr* msg, int flags), (override));
  MOCK_METHOD(ssize_t, RecvMsg, (int sockfd, struct msghdr* msg, int flags),
              (override));
  MOCK_METHOD(int, GetSockName,
              (int sockfd, struct sockaddr* addr, socklen_t* addrlen),
              (override));
  MOCK_METHOD(int, GetPeerName,
              (int sockfd, struct sockaddr* addr, socklen_t* addrlen),
              (override));
  MOCK_METHOD(ssize_t, RecvFrom,
              (int sockfd, void* buf, size_t len, int flags,
               struct sockaddr* src_addr, socklen_t* addrlen),
              (override));
};

struct EnclaveSyscallTestParams {
  int sysno;
  int nargs;
  int retval;
  uint64_t args[6];
};

class EnclaveSyscallTest
    : public testing::TestWithParam<EnclaveSyscallTestParams> {
 protected:
  MockEnclaveSyscallHelper* helper;
  MockIOManager* io_manager;

  EnclaveSyscallTest()
      : helper(new MockEnclaveSyscallHelper), io_manager(new MockIOManager) {}

  ~EnclaveSyscallTest() override {
    delete helper;
    delete io_manager;
  }
};

TEST_F(EnclaveSyscallTest, EnclaveSyscallReturnsErrorInvalidSysno) {
  int bad_sysno = 1000;
  int unimplemented_sysno = 313;

  EXPECT_EQ(-1,
            EnclaveSyscallWithDeps(bad_sysno, nullptr, 0, helper, io_manager));

  EXPECT_EQ(-1, EnclaveSyscallWithDeps(unimplemented_sysno, nullptr, 0, helper,
                                       io_manager));
}

TEST_P(EnclaveSyscallTest, EnclaveSyscallMakesDirectSyscall) {
  EnclaveSyscallTestParams params = GetParam();

  EXPECT_CALL(*helper, DispatchSyscall(params.sysno, params.args, params.nargs))
      .WillOnce(Return(params.retval));

  EXPECT_EQ(params.retval,
            EnclaveSyscallWithDeps(params.sysno, params.args, params.nargs,
                                   helper, io_manager));
}

const EnclaveSyscallTestParams direct_syscall_params[] = {
    {asylo::system_call::kSYS_getpid, 0, 1, {}},
    {asylo::system_call::kSYS_getgid, 0, 2, {}},
    {asylo::system_call::kSYS_getuid, 0, 3, {}},
    {asylo::system_call::kSYS_getegid, 0, 4, {}},
    {asylo::system_call::kSYS_geteuid, 0, 5, {}},
    {asylo::system_call::kSYS_getppid, 0, 6, {}},
    {asylo::system_call::kSYS_setsid, 0, 7, {}},
    {asylo::system_call::kSYS_getitimer, 2, 8, {1, 2}},
    {asylo::system_call::kSYS_setitimer, 3, 9, {1, 2, 3}},
    {asylo::system_call::kSYS_getrusage, 2, 10, {1, 2}},
    {asylo::system_call::kSYS_gettimeofday, 2, 11, {1, 2}},
    {asylo::system_call::kSYS_nanosleep, 2, 13, {1, 2}},
    {asylo::system_call::kSYS_sched_getaffinity, 3, 14, {1, 2, 3}},
    {asylo::system_call::kSYS_sched_yield, 0, 15, {}},
    {asylo::system_call::kSYS_syslog, 3, 16, {1, 2, 3}},
    {asylo::system_call::kSYS_times, 1, 17, {1}},
    {asylo::system_call::kSYS_uname, 1, 18, {1}}};

INSTANTIATE_TEST_SUITE_P(AllDirectSyscalls, EnclaveSyscallTest,
                         testing::ValuesIn(direct_syscall_params));

TEST_F(EnclaveSyscallTest, EnclaveSyscallAccess) {
  const char* path = "asdf";
  int mode = 0;

  uint64_t args[] = {reinterpret_cast<uint64_t>(path),
                     static_cast<uint64_t>(mode)};

  EXPECT_CALL(*io_manager, Access(path, mode)).WillOnce(Return(19));

  EXPECT_EQ(19, EnclaveSyscallWithDeps(asylo::system_call::kSYS_access, args, 2,
                                       helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallClose) {
  int fd = 1;

  uint64_t args[] = {static_cast<uint64_t>(fd)};

  EXPECT_CALL(*io_manager, Close(fd)).WillOnce(Return(20));

  EXPECT_EQ(20, EnclaveSyscallWithDeps(asylo::system_call::kSYS_close, args, 1,
                                       helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallOpen) {
  const char* path = "asdf";
  int flags = 1;
  mode_t mode = 2;

  uint64_t args[] = {reinterpret_cast<uint64_t>(path),
                     static_cast<uint64_t>(flags), mode};

  EXPECT_CALL(*io_manager, Open(path, flags, mode)).WillOnce(Return(21));

  EXPECT_EQ(21, EnclaveSyscallWithDeps(asylo::system_call::kSYS_open, args, 3,
                                       helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallDup) {
  int oldfd = 1;

  uint64_t args[] = {static_cast<uint64_t>(oldfd)};

  EXPECT_CALL(*io_manager, Dup(oldfd)).WillOnce(Return(22));

  EXPECT_EQ(22, EnclaveSyscallWithDeps(asylo::system_call::kSYS_dup, args, 1,
                                       helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallDup2) {
  int oldfd = 1;
  int newfd = 2;

  uint64_t args[] = {static_cast<uint64_t>(oldfd),
                     static_cast<uint64_t>(newfd)};

  EXPECT_CALL(*io_manager, Dup2(oldfd, newfd)).WillOnce(Return(23));

  EXPECT_EQ(23, EnclaveSyscallWithDeps(asylo::system_call::kSYS_dup2, args, 2,
                                       helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallPipe) {
  int pipefd[] = {1, 2};

  uint64_t args[] = {reinterpret_cast<uint64_t>(&pipefd)};

  EXPECT_CALL(*io_manager, Pipe(pipefd, 0)).WillOnce(Return(24));

  EXPECT_EQ(24, EnclaveSyscallWithDeps(asylo::system_call::kSYS_pipe, args, 1,
                                       helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallPipe2) {
  int pipefd[] = {1, 2};
  int flags = 3;

  uint64_t args[] = {reinterpret_cast<uint64_t>(&pipefd),
                     static_cast<uint64_t>(flags)};

  EXPECT_CALL(*io_manager, Pipe(pipefd, flags)).WillOnce(Return(25));

  EXPECT_EQ(25, EnclaveSyscallWithDeps(asylo::system_call::kSYS_pipe2, args, 2,
                                       helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallSelect) {
  int ndfs = 1;
  fd_set* readfds = nullptr;
  fd_set* writefds = nullptr;
  fd_set* exceptfds = nullptr;
  struct timeval* timeout = nullptr;

  uint64_t args[] = {static_cast<uint64_t>(ndfs),
                     reinterpret_cast<uint64_t>(readfds),
                     reinterpret_cast<uint64_t>(writefds),
                     reinterpret_cast<uint64_t>(exceptfds),
                     reinterpret_cast<uint64_t>(timeout)};

  EXPECT_CALL(*io_manager, Select(ndfs, readfds, writefds, exceptfds, timeout))
      .WillOnce(Return(26));

  EXPECT_EQ(26, EnclaveSyscallWithDeps(asylo::system_call::kSYS_select, args, 5,
                                       helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallPoll) {
  struct pollfd* fds = nullptr;
  nfds_t nfds = 1;
  int timeout = 2;

  uint64_t args[] = {reinterpret_cast<uint64_t>(fds),
                     static_cast<uint64_t>(nfds),
                     static_cast<uint64_t>(timeout)};

  EXPECT_CALL(*io_manager, Poll(fds, nfds, timeout)).WillOnce(Return(27));

  EXPECT_EQ(27, EnclaveSyscallWithDeps(asylo::system_call::kSYS_poll, args, 3,
                                       helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallEPollCreate) {
  int size = 1;

  uint64_t args[] = {static_cast<uint64_t>(size)};

  EXPECT_CALL(*io_manager, EpollCreate(size)).WillOnce(Return(28));

  EXPECT_EQ(28, EnclaveSyscallWithDeps(asylo::system_call::kSYS_epoll_create,
                                       args, 1, helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallEPollCtl) {
  int epfd = 1;
  int op = 2;
  int fd = 3;
  struct epoll_event* event = nullptr;

  uint64_t args[] = {static_cast<uint64_t>(epfd), static_cast<uint64_t>(op),
                     static_cast<uint64_t>(fd),
                     reinterpret_cast<uint64_t>(event)};

  EXPECT_CALL(*io_manager, EpollCtl(epfd, op, fd, event)).WillOnce(Return(29));

  EXPECT_EQ(29, EnclaveSyscallWithDeps(asylo::system_call::kSYS_epoll_ctl, args,
                                       4, helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallEPollWait) {
  int epfd = 1;
  struct epoll_event* events = nullptr;
  int maxevents = 2;
  int timeout = 3;

  uint64_t args[] = {
      static_cast<uint64_t>(epfd), reinterpret_cast<uint64_t>(events),
      static_cast<uint64_t>(maxevents), static_cast<uint64_t>(timeout)};

  EXPECT_CALL(*io_manager, EpollWait(epfd, events, maxevents, timeout))
      .WillOnce(Return(30));

  EXPECT_EQ(30, EnclaveSyscallWithDeps(asylo::system_call::kSYS_epoll_wait,
                                       args, 4, helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallEventFd) {
  int initval = 1;

  uint64_t args[] = {static_cast<uint64_t>(initval)};

  EXPECT_CALL(*io_manager, EventFd(initval, 0)).WillOnce(Return(31));

  EXPECT_EQ(31, EnclaveSyscallWithDeps(asylo::system_call::kSYS_eventfd, args,
                                       1, helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallEventFd2) {
  int initval = 1;
  int flags = 2;

  uint64_t args[] = {static_cast<uint64_t>(initval),
                     static_cast<uint64_t>(flags)};

  EXPECT_CALL(*io_manager, EventFd(initval, flags)).WillOnce(Return(32));

  EXPECT_EQ(32, EnclaveSyscallWithDeps(asylo::system_call::kSYS_eventfd2, args,
                                       2, helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallInotifyInit) {
  uint64_t args[] = {};

  EXPECT_CALL(*io_manager, InotifyInit(false)).WillOnce(Return(33));

  EXPECT_EQ(33, EnclaveSyscallWithDeps(asylo::system_call::kSYS_inotify_init,
                                       args, 0, helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallInotifyInit1) {
  bool non_block = true;
  uint64_t args[] = {non_block};

  EXPECT_CALL(*io_manager, InotifyInit(non_block)).WillOnce(Return(34));

  EXPECT_EQ(34, EnclaveSyscallWithDeps(asylo::system_call::kSYS_inotify_init1,
                                       args, 1, helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallInotifyAddWatch) {
  int fd = 0;
  const char* pathname = "Test";
  uint64_t mask = 2;

  uint64_t args[] = {static_cast<uint64_t>(fd),
                     reinterpret_cast<uint64_t>(pathname), mask};

  EXPECT_CALL(*io_manager, InotifyAddWatch(fd, pathname, mask))
      .WillOnce(Return(35));

  EXPECT_EQ(35,
            EnclaveSyscallWithDeps(asylo::system_call::kSYS_inotify_add_watch,
                                   args, 3, helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallInotifyRmWatch) {
  int fd = 0;
  int wd = 1;

  uint64_t args[] = {static_cast<uint64_t>(fd), static_cast<uint64_t>(wd)};

  EXPECT_CALL(*io_manager, InotifyRmWatch(fd, wd)).WillOnce(Return(36));

  EXPECT_EQ(36,
            EnclaveSyscallWithDeps(asylo::system_call::kSYS_inotify_rm_watch,
                                   args, 2, helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallRead) {
  int fd = 0;
  char* buf = nullptr;
  size_t count = 2;

  uint64_t args[] = {static_cast<uint64_t>(fd), reinterpret_cast<uint64_t>(buf),
                     count};

  EXPECT_CALL(*io_manager, Read(fd, buf, count)).WillOnce(Return(37));

  EXPECT_EQ(37, EnclaveSyscallWithDeps(asylo::system_call::kSYS_read, args, 3,
                                       helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallWrite) {
  int fd = 0;
  const char* buf = "Test";
  size_t count = 2;

  uint64_t args[] = {static_cast<uint64_t>(fd), reinterpret_cast<uint64_t>(buf),
                     count};

  EXPECT_CALL(*io_manager, Write(fd, buf, count)).WillOnce(Return(38));

  EXPECT_EQ(38, EnclaveSyscallWithDeps(asylo::system_call::kSYS_write, args, 3,
                                       helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallChown) {
  const char* path = "/path/to";
  uid_t owner = 1;
  gid_t group = 2;

  uint64_t args[] = {reinterpret_cast<uint64_t>(path), owner, group};

  EXPECT_CALL(*io_manager, Chown(path, owner, group)).WillOnce(Return(39));

  EXPECT_EQ(39, EnclaveSyscallWithDeps(asylo::system_call::kSYS_chown, args, 3,
                                       helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallFchown) {
  int fd = 0;
  uid_t owner = 1;
  gid_t group = 2;

  uint64_t args[] = {static_cast<uint64_t>(fd), owner, group};

  EXPECT_CALL(*io_manager, FChOwn(fd, owner, group)).WillOnce(Return(40));

  EXPECT_EQ(40, EnclaveSyscallWithDeps(asylo::system_call::kSYS_fchown, args, 3,
                                       helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallLink) {
  const char* from = "/from";
  const char* to = "/to";

  uint64_t args[] = {reinterpret_cast<uint64_t>(from),
                     reinterpret_cast<uint64_t>(to)};

  EXPECT_CALL(*io_manager, Link(from, to)).WillOnce(Return(41));

  EXPECT_EQ(41, EnclaveSyscallWithDeps(asylo::system_call::kSYS_link, args, 2,
                                       helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallUnlink) {
  const char* path = "/path";

  uint64_t args[] = {reinterpret_cast<uint64_t>(path)};

  EXPECT_CALL(*io_manager, Unlink(path)).WillOnce(Return(42));

  EXPECT_EQ(42, EnclaveSyscallWithDeps(asylo::system_call::kSYS_unlink, args, 1,
                                       helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallReadLink) {
  const char* path = "/path";
  char* buf = nullptr;
  size_t count = 2;

  uint64_t args[] = {reinterpret_cast<uint64_t>(path),
                     reinterpret_cast<uint64_t>(buf), count};

  EXPECT_CALL(*io_manager, ReadLink(path, buf, count)).WillOnce(Return(43));

  EXPECT_EQ(43, EnclaveSyscallWithDeps(asylo::system_call::kSYS_readlink, args,
                                       3, helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallSymLink) {
  const char* from = "/from";
  const char* to = "/to";

  uint64_t args[] = {reinterpret_cast<uint64_t>(from),
                     reinterpret_cast<uint64_t>(to)};

  EXPECT_CALL(*io_manager, SymLink(from, to)).WillOnce(Return(44));

  EXPECT_EQ(44, EnclaveSyscallWithDeps(asylo::system_call::kSYS_symlink, args,
                                       2, helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallTruncate) {
  const char* path = "/path";
  off_t length = 1;

  uint64_t args[] = {reinterpret_cast<uint64_t>(path),
                     static_cast<uint64_t>(length)};

  EXPECT_CALL(*io_manager, Truncate(path, length)).WillOnce(Return(45));

  EXPECT_EQ(45, EnclaveSyscallWithDeps(asylo::system_call::kSYS_truncate, args,
                                       2, helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallFTruncate) {
  int fd = 0;
  off_t length = 1;

  uint64_t args[] = {static_cast<uint64_t>(fd), static_cast<uint64_t>(length)};

  EXPECT_CALL(*io_manager, FTruncate(fd, length)).WillOnce(Return(46));

  EXPECT_EQ(46, EnclaveSyscallWithDeps(asylo::system_call::kSYS_ftruncate, args,
                                       2, helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallStat) {
  const char* path = "/path";
  struct stat* stat_buffer = nullptr;

  uint64_t args[] = {reinterpret_cast<uint64_t>(path),
                     reinterpret_cast<uint64_t>(stat_buffer)};

  EXPECT_CALL(*io_manager, Stat(path, stat_buffer)).WillOnce(Return(47));

  EXPECT_EQ(47, EnclaveSyscallWithDeps(asylo::system_call::kSYS_stat, args, 2,
                                       helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallLStat) {
  const char* path = "/path";
  struct stat* stat_buffer = nullptr;

  uint64_t args[] = {reinterpret_cast<uint64_t>(path),
                     reinterpret_cast<uint64_t>(stat_buffer)};

  EXPECT_CALL(*io_manager, LStat(path, stat_buffer)).WillOnce(Return(48));

  EXPECT_EQ(48, EnclaveSyscallWithDeps(asylo::system_call::kSYS_lstat, args, 2,
                                       helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallStatFs) {
  const char* path = "/path";
  struct statfs* statfs_buffer = nullptr;

  uint64_t args[] = {reinterpret_cast<uint64_t>(path),
                     reinterpret_cast<uint64_t>(statfs_buffer)};

  EXPECT_CALL(*io_manager, StatFs(path, statfs_buffer)).WillOnce(Return(49));

  EXPECT_EQ(49, EnclaveSyscallWithDeps(asylo::system_call::kSYS_statfs, args, 2,
                                       helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallFStat) {
  int fd = 0;
  struct stat* stat_buffer = nullptr;

  uint64_t args[] = {static_cast<uint64_t>(fd),
                     reinterpret_cast<uint64_t>(stat_buffer)};

  EXPECT_CALL(*io_manager, FStat(fd, stat_buffer)).WillOnce(Return(50));

  EXPECT_EQ(50, EnclaveSyscallWithDeps(asylo::system_call::kSYS_fstat, args, 2,
                                       helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallFStatFs) {
  int fd = 0;
  struct statfs* statfs_buffer = nullptr;

  uint64_t args[] = {static_cast<uint64_t>(fd),
                     reinterpret_cast<uint64_t>(statfs_buffer)};

  EXPECT_CALL(*io_manager, FStatFs(fd, statfs_buffer)).WillOnce(Return(51));

  EXPECT_EQ(51, EnclaveSyscallWithDeps(asylo::system_call::kSYS_fstatfs, args,
                                       2, helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallChmod) {
  const char* path = "/path";
  mode_t mode = 1;

  uint64_t args[] = {reinterpret_cast<uint64_t>(path), mode};

  EXPECT_CALL(*io_manager, ChMod(path, mode)).WillOnce(Return(52));

  EXPECT_EQ(52, EnclaveSyscallWithDeps(asylo::system_call::kSYS_chmod, args, 2,
                                       helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallFChmod) {
  int fd = 0;
  mode_t mode = 1;

  uint64_t args[] = {static_cast<uint64_t>(fd), mode};

  EXPECT_CALL(*io_manager, FChMod(fd, mode)).WillOnce(Return(53));

  EXPECT_EQ(53, EnclaveSyscallWithDeps(asylo::system_call::kSYS_fchmod, args, 2,
                                       helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallLSeek) {
  int fd = 0;
  off_t offset = 1;
  int whence = 2;

  uint64_t args[] = {static_cast<uint64_t>(fd), static_cast<uint64_t>(offset),
                     static_cast<uint64_t>(whence)};

  EXPECT_CALL(*io_manager, LSeek(fd, offset, whence)).WillOnce(Return(54));

  EXPECT_EQ(54, EnclaveSyscallWithDeps(asylo::system_call::kSYS_lseek, args, 3,
                                       helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallFCntl) {
  int fd = 0;
  int cmd = 1;
  int64_t arg = 2;

  uint64_t args[] = {static_cast<uint64_t>(fd), static_cast<uint64_t>(cmd),
                     static_cast<uint64_t>(arg)};

  EXPECT_CALL(*io_manager, FCntl(fd, cmd, arg)).WillOnce(Return(55));

  EXPECT_EQ(55, EnclaveSyscallWithDeps(asylo::system_call::kSYS_fcntl, args, 3,
                                       helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallFSync) {
  int fd = 0;

  uint64_t args[] = {static_cast<uint64_t>(fd)};

  EXPECT_CALL(*io_manager, FSync(fd)).WillOnce(Return(56));

  EXPECT_EQ(56, EnclaveSyscallWithDeps(asylo::system_call::kSYS_fsync, args, 1,
                                       helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallFDataSync) {
  int fd = 0;

  uint64_t args[] = {static_cast<uint64_t>(fd)};

  EXPECT_CALL(*io_manager, FDataSync(fd)).WillOnce(Return(57));

  EXPECT_EQ(57, EnclaveSyscallWithDeps(asylo::system_call::kSYS_fdatasync, args,
                                       1, helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallFLock) {
  int fd = 0;
  int operation = 1;

  uint64_t args[] = {static_cast<uint64_t>(fd),
                     static_cast<uint64_t>(operation)};

  EXPECT_CALL(*io_manager, FLock(fd, operation)).WillOnce(Return(58));

  EXPECT_EQ(58, EnclaveSyscallWithDeps(asylo::system_call::kSYS_flock, args, 2,
                                       helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallIoctl) {
  int fd = 0;
  int request = 1;
  void* argp = nullptr;

  uint64_t args[] = {static_cast<uint64_t>(fd), static_cast<uint64_t>(request),
                     reinterpret_cast<uint64_t>(argp)};

  EXPECT_CALL(*io_manager, Ioctl(fd, request, argp)).WillOnce(Return(59));

  EXPECT_EQ(59, EnclaveSyscallWithDeps(asylo::system_call::kSYS_ioctl, args, 3,
                                       helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallMkdir) {
  const char* path = "/path";
  mode_t mode = 1;

  uint64_t args[] = {reinterpret_cast<uint64_t>(path), mode};

  EXPECT_CALL(*io_manager, Mkdir(path, mode)).WillOnce(Return(60));

  EXPECT_EQ(60, EnclaveSyscallWithDeps(asylo::system_call::kSYS_mkdir, args, 2,
                                       helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallRmdir) {
  const char* path = "/path";

  uint64_t args[] = {reinterpret_cast<uint64_t>(path)};

  EXPECT_CALL(*io_manager, RmDir(path)).WillOnce(Return(61));

  EXPECT_EQ(61, EnclaveSyscallWithDeps(asylo::system_call::kSYS_rmdir, args, 1,
                                       helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallRename) {
  const char* oldpath = "/path";
  const char* newpath = "/newpath";

  uint64_t args[] = {reinterpret_cast<uint64_t>(oldpath),
                     reinterpret_cast<uint64_t>(newpath)};

  EXPECT_CALL(*io_manager, Rename(oldpath, newpath)).WillOnce(Return(62));

  EXPECT_EQ(62, EnclaveSyscallWithDeps(asylo::system_call::kSYS_rename, args, 2,
                                       helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallUtime) {
  const char* filename = "/filename";
  const struct utimbuf* times = nullptr;

  uint64_t args[] = {reinterpret_cast<uint64_t>(filename),
                     reinterpret_cast<uint64_t>(times)};

  EXPECT_CALL(*io_manager, Utime(filename, times)).WillOnce(Return(63));

  EXPECT_EQ(63, EnclaveSyscallWithDeps(asylo::system_call::kSYS_utime, args, 2,
                                       helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallUtimes) {
  const char* filename = "/filename";
  const struct timeval times[2] = {};

  uint64_t args[] = {reinterpret_cast<uint64_t>(filename),
                     reinterpret_cast<uint64_t>(times)};

  EXPECT_CALL(*io_manager, Utimes(filename, times)).WillOnce(Return(64));

  EXPECT_EQ(64, EnclaveSyscallWithDeps(asylo::system_call::kSYS_utimes, args, 2,
                                       helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallWritev) {
  int fd = 0;
  const struct iovec* iov = nullptr;
  int iovcnt = 2;

  uint64_t args[] = {static_cast<uint64_t>(fd), reinterpret_cast<uint64_t>(iov),
                     static_cast<uint64_t>(iovcnt)};

  EXPECT_CALL(*io_manager, Writev(fd, iov, iovcnt)).WillOnce(Return(65));

  EXPECT_EQ(65, EnclaveSyscallWithDeps(asylo::system_call::kSYS_writev, args, 3,
                                       helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallReadv) {
  int fd = 0;
  const struct iovec* iov = nullptr;
  int iovcnt = 2;

  uint64_t args[] = {static_cast<uint64_t>(fd), reinterpret_cast<uint64_t>(iov),
                     static_cast<uint64_t>(iovcnt)};

  EXPECT_CALL(*io_manager, Readv(fd, iov, iovcnt)).WillOnce(Return(66));

  EXPECT_EQ(66, EnclaveSyscallWithDeps(asylo::system_call::kSYS_readv, args, 3,
                                       helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallPRead) {
  int fd = 0;
  void* buf = nullptr;
  size_t count = 2;
  off_t offset = 3;

  uint64_t args[] = {static_cast<uint64_t>(fd), reinterpret_cast<uint64_t>(buf),
                     count, static_cast<uint64_t>(offset)};

  EXPECT_CALL(*io_manager, PRead(fd, buf, count, offset)).WillOnce(Return(67));

  EXPECT_EQ(67, EnclaveSyscallWithDeps(asylo::system_call::kSYS_pread64, args,
                                       4, helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallUmask) {
  mode_t mask = 0;

  uint64_t args[] = {mask};

  EXPECT_CALL(*io_manager, Umask(mask)).WillOnce(Return(68));

  EXPECT_EQ(68, EnclaveSyscallWithDeps(asylo::system_call::kSYS_umask, args, 1,
                                       helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallGetRLimit) {
  int resource = 0;
  struct rlimit* rlim = nullptr;

  uint64_t args[] = {static_cast<uint64_t>(resource),
                     reinterpret_cast<uint64_t>(rlim)};

  EXPECT_CALL(*io_manager, GetRLimit(resource, rlim)).WillOnce(Return(69));

  EXPECT_EQ(69, EnclaveSyscallWithDeps(asylo::system_call::kSYS_getrlimit, args,
                                       2, helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallSetRLimit) {
  int resource = 0;
  const struct rlimit* rlim = nullptr;

  uint64_t args[] = {static_cast<uint64_t>(resource),
                     reinterpret_cast<uint64_t>(rlim)};

  EXPECT_CALL(*io_manager, SetRLimit(resource, rlim)).WillOnce(Return(70));

  EXPECT_EQ(70, EnclaveSyscallWithDeps(asylo::system_call::kSYS_setrlimit, args,
                                       2, helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallSetSockOpt) {
  int sockfd = 0;
  int level = 1;
  int option_name = 2;
  const void* option_value = nullptr;
  socklen_t option_len = 5;

  uint64_t args[] = {static_cast<uint64_t>(sockfd),
                     static_cast<uint64_t>(level),
                     static_cast<uint64_t>(option_name),
                     reinterpret_cast<uint64_t>(option_value), option_len};

  EXPECT_CALL(*io_manager,
              SetSockOpt(sockfd, level, option_name, option_value, option_len))
      .WillOnce(Return(71));

  EXPECT_EQ(71, EnclaveSyscallWithDeps(asylo::system_call::kSYS_setsockopt,
                                       args, 5, helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallConnect) {
  int sockfd = 0;
  const struct sockaddr* addr = nullptr;
  socklen_t addrlen = 2;

  uint64_t args[] = {static_cast<uint64_t>(sockfd),
                     reinterpret_cast<uint64_t>(addr), addrlen};

  EXPECT_CALL(*io_manager, Connect(sockfd, addr, addrlen)).WillOnce(Return(72));

  EXPECT_EQ(72, EnclaveSyscallWithDeps(asylo::system_call::kSYS_connect, args,
                                       3, helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallShutdown) {
  int sockfd = 0;
  int how = 1;

  uint64_t args[] = {static_cast<uint64_t>(sockfd), static_cast<uint64_t>(how)};

  EXPECT_CALL(*io_manager, Shutdown(sockfd, how)).WillOnce(Return(73));

  EXPECT_EQ(73, EnclaveSyscallWithDeps(asylo::system_call::kSYS_shutdown, args,
                                       2, helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallSendto) {
  int sockfd = 0;
  const void* buf = nullptr;
  size_t len = 2;
  int flags = 3;

  uint64_t args[] = {static_cast<uint64_t>(sockfd),
                     reinterpret_cast<uint64_t>(buf),
                     len,
                     static_cast<uint64_t>(flags),
                     0,
                     0};

  EXPECT_CALL(*io_manager, Send(sockfd, buf, len, flags)).WillOnce(Return(74));

  EXPECT_EQ(74, EnclaveSyscallWithDeps(asylo::system_call::kSYS_sendto, args, 6,
                                       helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallSocket) {
  int domain = 0;
  int type = 1;
  int protocol = 2;

  uint64_t args[] = {static_cast<uint64_t>(domain), static_cast<uint64_t>(type),
                     static_cast<uint64_t>(protocol)};

  EXPECT_CALL(*io_manager, Socket(domain, type, protocol)).WillOnce(Return(75));

  EXPECT_EQ(75, EnclaveSyscallWithDeps(asylo::system_call::kSYS_socket, args, 3,
                                       helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallGetSockOpt) {
  int sockfd = 0;
  int level = 1;
  int optname = 2;
  void* optval = nullptr;
  socklen_t* optlen = nullptr;

  uint64_t args[] = {
      static_cast<uint64_t>(sockfd), static_cast<uint64_t>(level),
      static_cast<uint64_t>(optname), reinterpret_cast<uint64_t>(optval),
      reinterpret_cast<uint64_t>(optlen)};

  EXPECT_CALL(*io_manager, GetSockOpt(sockfd, level, optname, optval, optlen))
      .WillOnce(Return(76));

  EXPECT_EQ(76, EnclaveSyscallWithDeps(asylo::system_call::kSYS_getsockopt,
                                       args, 5, helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallAccept) {
  int sockfd = 0;
  struct sockaddr* addr = nullptr;
  socklen_t* addrlen = nullptr;

  uint64_t args[] = {static_cast<uint64_t>(sockfd),
                     reinterpret_cast<uint64_t>(addr),
                     reinterpret_cast<uint64_t>(addrlen)};

  EXPECT_CALL(*io_manager, Accept(sockfd, addr, addrlen)).WillOnce(Return(77));

  EXPECT_EQ(77, EnclaveSyscallWithDeps(asylo::system_call::kSYS_accept, args, 3,
                                       helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallBind) {
  int sockfd = 0;
  const struct sockaddr* addr = nullptr;
  socklen_t addrlen = 2;

  uint64_t args[] = {static_cast<uint64_t>(sockfd),
                     reinterpret_cast<uint64_t>(addr), addrlen};

  EXPECT_CALL(*io_manager, Bind(sockfd, addr, addrlen)).WillOnce(Return(78));

  EXPECT_EQ(78, EnclaveSyscallWithDeps(asylo::system_call::kSYS_bind, args, 3,
                                       helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallListen) {
  int sockfd = 0;
  int backlog = 1;

  uint64_t args[] = {static_cast<uint64_t>(sockfd),
                     static_cast<uint64_t>(backlog)};

  EXPECT_CALL(*io_manager, Listen(sockfd, backlog)).WillOnce(Return(79));

  EXPECT_EQ(79, EnclaveSyscallWithDeps(asylo::system_call::kSYS_listen, args, 2,
                                       helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallSendMsg) {
  int sockfd = 0;
  const struct msghdr* msg = nullptr;
  int flags = 2;

  uint64_t args[] = {static_cast<uint64_t>(sockfd),
                     reinterpret_cast<uint64_t>(msg),
                     static_cast<uint64_t>(flags)};

  EXPECT_CALL(*io_manager, SendMsg(sockfd, msg, flags)).WillOnce(Return(80));

  EXPECT_EQ(80, EnclaveSyscallWithDeps(asylo::system_call::kSYS_sendmsg, args,
                                       3, helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallRecvMsg) {
  int sockfd = 0;
  struct msghdr* msg = nullptr;
  int flags = 2;

  uint64_t args[] = {static_cast<uint64_t>(sockfd),
                     reinterpret_cast<uint64_t>(msg),
                     static_cast<uint64_t>(flags)};

  EXPECT_CALL(*io_manager, RecvMsg(sockfd, msg, flags)).WillOnce(Return(81));

  EXPECT_EQ(81, EnclaveSyscallWithDeps(asylo::system_call::kSYS_recvmsg, args,
                                       3, helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallGetSockName) {
  int sockfd = 0;
  struct sockaddr* addr = nullptr;
  socklen_t* addrlen = nullptr;

  uint64_t args[] = {static_cast<uint64_t>(sockfd),
                     reinterpret_cast<uint64_t>(addr),
                     reinterpret_cast<uint64_t>(addrlen)};

  EXPECT_CALL(*io_manager, GetSockName(sockfd, addr, addrlen))
      .WillOnce(Return(82));

  EXPECT_EQ(82, EnclaveSyscallWithDeps(asylo::system_call::kSYS_getsockname,
                                       args, 3, helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallGetPeerName) {
  int sockfd = 0;
  struct sockaddr* addr = nullptr;
  socklen_t* addrlen = nullptr;

  uint64_t args[] = {static_cast<uint64_t>(sockfd),
                     reinterpret_cast<uint64_t>(addr),
                     reinterpret_cast<uint64_t>(addrlen)};

  EXPECT_CALL(*io_manager, GetPeerName(sockfd, addr, addrlen))
      .WillOnce(Return(83));

  EXPECT_EQ(83, EnclaveSyscallWithDeps(asylo::system_call::kSYS_getpeername,
                                       args, 3, helper, io_manager));
}

TEST_F(EnclaveSyscallTest, EnclaveSyscallRecvFrom) {
  int sockfd = 0;
  void* buf = nullptr;
  size_t len = 2;
  int flags = 3;
  struct sockaddr* src_addr = nullptr;
  socklen_t* addrlen = nullptr;

  uint64_t args[] = {static_cast<uint64_t>(sockfd),
                     reinterpret_cast<uint64_t>(buf),
                     len,
                     static_cast<uint64_t>(flags),
                     reinterpret_cast<uint64_t>(src_addr),
                     reinterpret_cast<uint64_t>(addrlen)};

  EXPECT_CALL(*io_manager, RecvFrom(sockfd, buf, len, flags, src_addr, addrlen))
      .WillOnce(Return(84));

  EXPECT_EQ(84, EnclaveSyscallWithDeps(asylo::system_call::kSYS_recvfrom, args,
                                       6, helper, io_manager));
}

}  // namespace
}  // namespace system_call
}  // namespace asylo
