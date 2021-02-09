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

#include "asylo/platform/system_call/metadata.h"

#include <sys/poll.h>
#include <sys/syscall.h>

#include <string>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"

namespace asylo {
namespace system_call {
namespace {

using testing::Eq;
using testing::StrEq;

// Summarize a system call encoding as a string.
std::string Summarize(int sysno) {
  std::string result;
  SystemCallDescriptor syscall{sysno};

  absl::StrAppend(&result, syscall.name(), "/", syscall.parameter_count());
  std::vector<std::string> args(syscall.parameter_count());
  for (int i = 0; i < syscall.parameter_count(); i++) {
    ParameterDescriptor param = syscall.parameter(i);
    args[i] = std::string(param.name());

    // Format a scalar type summary.
    if (param.is_scalar()) {
      absl::StrAppend(&args[i], ": ", param.is_signed() ? "s" : "u",
                      8 * param.size());
    } else if (param.is_pointer()) {
      // Format a pointer type summary.
      if (param.is_in() && param.is_out()) {
        absl::StrAppend(&args[i], ": in/out");
      } else if (param.is_in()) {
        absl::StrAppend(&args[i], ": in");
      } else if (param.is_out()) {
        absl::StrAppend(&args[i], ": out");
      }

      if (param.in_string()) {
        absl::StrAppend(&args[i], " string");
      } else if (param.is_fixed()) {
        absl::StrAppend(&args[i], " fixed[", param.size(), "]");
      } else if (param.is_bounded()) {
        absl::StrAppend(&args[i], " bounded[",
                        syscall.parameter(param.size()).name(), "]");
      }
    }
  }

  absl::StrAppend(&result, "(", absl::StrJoin(args, ", "), ")");
  return result;
}

TEST(MetaDataTest, CoherenceCheck) {
  for (int i = 0; i <= LastSystemCall(); i++) {
    SystemCallDescriptor syscall(i);
    for (int j = 0; j < syscall.parameter_count(); j++) {
      ParameterDescriptor parameter = syscall.parameter(j);

      // Ensure that a parameter specified as a bound is a scalar type.
      if (parameter.is_bounded()) {
        EXPECT_TRUE(parameter.bounding_parameter().is_scalar());
      }

      // Ensure that a parameter marked as 'out' is not a constant.
      if (parameter.is_const()) {
        EXPECT_FALSE(parameter.is_out());
      }

      // Ensure that a void * parameter is has either a specified bound or a is
      // marked as an uninterpreted scalar parameter.
      if (parameter.is_void_ptr()) {
        EXPECT_TRUE(parameter.is_bounded() || parameter.is_scalar());
      }
    }
  }
}

TEST(MetaDataTest, ValidSystemCallDescriptor) {
  EXPECT_TRUE(SystemCallDescriptor{SYS_dup}.is_valid());
  EXPECT_THAT(SystemCallDescriptor{SYS_dup}.name().data(), StrEq("dup"));
  EXPECT_THAT(SystemCallDescriptor{SYS_dup}.parameter_count(), Eq(1));

  EXPECT_TRUE(SystemCallDescriptor{SYS_dup2}.is_valid());
  EXPECT_THAT(SystemCallDescriptor{SYS_dup2}.name().data(), StrEq("dup2"));
  EXPECT_THAT(SystemCallDescriptor{SYS_dup2}.parameter_count(), Eq(2));

  EXPECT_TRUE(SystemCallDescriptor{SYS_dup3}.is_valid());
  EXPECT_THAT(SystemCallDescriptor{SYS_dup3}.name().data(), StrEq("dup3"));
  EXPECT_THAT(SystemCallDescriptor{SYS_dup3}.parameter_count(), Eq(3));

  EXPECT_TRUE(SystemCallDescriptor{SYS_getuid}.is_valid());
  EXPECT_THAT(SystemCallDescriptor{SYS_getuid}.name().data(), StrEq("getuid"));
  EXPECT_THAT(SystemCallDescriptor{SYS_getuid}.parameter_count(), Eq(0));

  EXPECT_TRUE(SystemCallDescriptor{SYS_read}.is_valid());
  EXPECT_THAT(SystemCallDescriptor{SYS_read}.name().data(), StrEq("read"));
  EXPECT_THAT(SystemCallDescriptor{SYS_read}.parameter_count(), Eq(3));
}

TEST(MetaDataTest, ValidParameterDescriptor) {
  SystemCallDescriptor dup{SYS_dup};
  EXPECT_THAT(dup.parameter(0).name().data(), StrEq("fildes"));
  EXPECT_THAT(dup.parameter(0).type().data(), StrEq("unsigned int"));
  EXPECT_TRUE(dup.parameter(0).is_scalar());
  EXPECT_FALSE(dup.parameter(0).is_pointer());

  SystemCallDescriptor dup2{SYS_dup2};
  EXPECT_THAT(dup2.parameter(0).name().data(), StrEq("oldfd"));
  EXPECT_THAT(dup2.parameter(0).type().data(), StrEq("unsigned int"));
  EXPECT_TRUE(dup2.parameter(0).is_scalar());
  EXPECT_FALSE(dup2.parameter(0).is_pointer());
  EXPECT_THAT(dup2.parameter(1).name().data(), StrEq("newfd"));
  EXPECT_THAT(dup2.parameter(1).type().data(), StrEq("unsigned int"));
  EXPECT_TRUE(dup2.parameter(1).is_scalar());
  EXPECT_FALSE(dup2.parameter(1).is_pointer());

  SystemCallDescriptor dup3{SYS_dup3};
  EXPECT_THAT(dup3.parameter(0).name().data(), StrEq("oldfd"));
  EXPECT_THAT(dup3.parameter(0).type().data(), StrEq("unsigned int"));
  EXPECT_TRUE(dup3.parameter(0).is_scalar());
  EXPECT_FALSE(dup3.parameter(0).is_pointer());
  EXPECT_THAT(dup3.parameter(1).name().data(), StrEq("newfd"));
  EXPECT_THAT(dup3.parameter(1).type().data(), StrEq("unsigned int"));
  EXPECT_TRUE(dup3.parameter(1).is_scalar());
  EXPECT_FALSE(dup3.parameter(1).is_pointer());
  EXPECT_THAT(dup3.parameter(2).name().data(), StrEq("flags"));
  EXPECT_THAT(dup3.parameter(2).type().data(), StrEq("int"));
  EXPECT_TRUE(dup3.parameter(2).is_scalar());
  EXPECT_FALSE(dup3.parameter(2).is_pointer());
}

TEST(MetaDataTest, InvalidSystemCallDescriptor) {
  EXPECT_FALSE(SystemCallDescriptor{-1}.is_valid());
  EXPECT_FALSE(SystemCallDescriptor{1000}.is_valid());
  EXPECT_FALSE(SystemCallDescriptor{SYS_reboot}.is_valid());
}

TEST(MetaDataTest, InvalidSystemCallParameter) {
  EXPECT_FALSE(SystemCallDescriptor{-1}.parameter(0).is_valid());
  EXPECT_FALSE(SystemCallDescriptor{1000}.parameter(0).is_valid());
  EXPECT_FALSE(SystemCallDescriptor{SYS_getpid}.parameter(0).is_valid());
  EXPECT_FALSE(SystemCallDescriptor{SYS_reboot}.parameter(0).is_valid());
  EXPECT_FALSE(SystemCallDescriptor{SYS_dup}.parameter(-1).is_valid());
  EXPECT_FALSE(SystemCallDescriptor{SYS_dup}.parameter(1).is_valid());
}

TEST(MetaDataTest, ParameterElementSizeTest) {
  SystemCallDescriptor poll_des{SYS_poll};
  ParameterDescriptor bounding_param =
      poll_des.parameter(0).bounding_parameter();
  EXPECT_TRUE(poll_des.is_valid());
  EXPECT_TRUE(poll_des.parameter(0).is_bounded());
  EXPECT_TRUE(poll_des.parameter(0).is_pointer());
  EXPECT_THAT(poll_des.parameter(0).element_size(), Eq(sizeof(struct pollfd)));
  EXPECT_THAT(poll_des.parameter(0).size(),
              Eq(1));  // Bounded to parameter at index 1 (nfds).
  EXPECT_TRUE(bounding_param.is_valid());
  EXPECT_THAT(bounding_param.index(), Eq(1));
  EXPECT_THAT(bounding_param.is_const(), Eq(true));
}

TEST(MetaDataTest, Summarize) {
  // int dup(int oldfd);
  EXPECT_THAT(Summarize(SYS_dup), StrEq("dup/1(fildes: u32)"));

  // int dup2(int oldfd, int newfd);
  EXPECT_THAT(Summarize(SYS_dup2), StrEq("dup2/2(oldfd: u32, newfd: u32)"));
  // int dup3(int oldfd, int newfd, int flags);

  EXPECT_THAT(Summarize(SYS_dup3),
              StrEq("dup3/3(oldfd: u32, newfd: u32, flags: s32)"));

  // int creat(const char *pathname, mode_t mode);
  EXPECT_THAT(Summarize(SYS_creat),
              StrEq("creat/2(pathname: in string, mode: u16)"));

  // int link(const char *oldpath, const char *newpath);
  EXPECT_THAT(Summarize(SYS_link),
              StrEq("link/2(oldname: in string, newname: in string)"));

  // int mkdir(const char *pathname, mode_t mode);
  EXPECT_THAT(Summarize(SYS_mkdir),
              StrEq("mkdir/2(pathname: in string, mode: u16)"));

  // int rename(const char *oldpath, const char *newpath);
  EXPECT_THAT(Summarize(SYS_rename),
              StrEq("rename/2(oldname: in string, newname: in string)"));

  // int rmdir(const char *pathname);
  EXPECT_THAT(Summarize(SYS_rmdir), StrEq("rmdir/1(pathname: in string)"));

  // int symlink(const char *target, const char *linkpath);
  EXPECT_THAT(Summarize(SYS_symlink),
              StrEq("symlink/2(oldname: in string, newname: in string)"));

  // int truncate(const char *path, off_t length);
  EXPECT_THAT(Summarize(SYS_truncate),
              StrEq("truncate/2(path: in string, length: s64)"));

  // int unlink(const char *pathname);
  EXPECT_THAT(Summarize(SYS_unlink), StrEq("unlink/1(pathname: in string)"));

  // int poll(struct pollfd *fds, nfds_t nfds, int timeout);
  EXPECT_THAT(
      Summarize(SYS_poll),
      StrEq("poll/3(fds: in/out bounded[nfds], nfds: u64, timeout: s32)"));

  // int select(int nfds, fd_set *readfds, fd_set *writefds,
  //            fd_set *exceptfds, struct timeval *timeout);
  EXPECT_THAT(
      Summarize(SYS_select),
      StrEq(
          "select/5(nfds: s32, readfds: in/out fixed[128], writefds: in/out "
          "fixed[128], exceptfds: in/out fixed[128], timeout: in fixed[16])"));

  // int access(const char *pathname, int mode);
  EXPECT_THAT(Summarize(SYS_access),
              StrEq("access/2(filename: in string, mode: s32)"));

  // int open(const char *pathname, int flags, mode_t mode);
  EXPECT_THAT(Summarize(SYS_open),
              StrEq("open/3(filename: in string, flags: s32, mode: u16)"));

  // int close(int fd);
  EXPECT_THAT(Summarize(SYS_close), StrEq("close/1(fd: u32)"));

  // int pipe2(int pipefd[2], int flags);
  EXPECT_THAT(Summarize(SYS_pipe2),
              StrEq("pipe2/2(fildes: out fixed[8], flags: s32)"));

  // ssize_t read(int fd, void *buf, size_t count);
  EXPECT_THAT(Summarize(SYS_read),
              StrEq("read/3(fd: u32, buf: out bounded[count], count: u64)"));

  // ssize_t readlink(const char *pathname, char *buf, size_t bufsiz);
  EXPECT_THAT(Summarize(SYS_readlink),
              StrEq("readlink/3(path: in string, buf: out bounded[bufsiz], "
                    "bufsiz: s32)"));

  // int chdir(const char *path);
  EXPECT_THAT(Summarize(SYS_chdir), StrEq("chdir/1(filename: in string)"));

  // int fstat(int fd, struct stat *statbuf);
  EXPECT_THAT(Summarize(SYS_fstat),
              StrEq("fstat/2(fd: u32, statbuf: out fixed[144])"));

  // int fstatfs(int fd, struct statfs *statbuf);
  EXPECT_THAT(Summarize(SYS_fstatfs),
              StrEq("fstatfs/2(fd: s32, statbuf: out fixed[120])"));
}

}  // namespace
}  // namespace system_call
}  // namespace asylo
