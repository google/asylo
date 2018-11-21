/*
 *
 * Copyright 2018 Asylo authors
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

#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <regex.h>
#include <sched.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <algorithm>

#include "absl/container/flat_hash_set.h"
#include "absl/strings/str_cat.h"
#include "asylo/util/logging.h"
#include "asylo/platform/common/bridge_proto_serializer.h"
#include "asylo/platform/posix/syscalls_test.pb.h"
#include "asylo/platform/storage/utils/fd_closer.h"
#include "asylo/test/util/enclave_test_application.h"
#include "asylo/util/posix_error_space.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"

namespace asylo {

// A collection of tests exercising delegated system calls.
class SyscallsEnclave : public EnclaveTestCase {
 public:
  SyscallsEnclave() = default;

  Status Run(const EnclaveInput &input, EnclaveOutput *output) {
    if (!input.HasExtension(syscalls_test_input)) {
      return Status(error::GoogleError::INVALID_ARGUMENT,
                    "Missing input extension");
    }
    SyscallsTestInput test_input = input.GetExtension(syscalls_test_input);
    if (!test_input.has_test_target()) {
      return Status(error::GoogleError::INVALID_ARGUMENT,
                    "Missing test_target");
    }

    SyscallsTestOutput output_ret;
    if (test_input.test_target() == "sysconf(_SC_NPROCESSORS_CONF)") {
      return RunSysconfTest(output, _SC_NPROCESSORS_CONF);
    } else if (test_input.test_target() == "sysconf(_SC_NPROCESSORS_ONLN)") {
      return RunSysconfTest(output, _SC_NPROCESSORS_ONLN);
    } else if (test_input.test_target() == "sysconf(_SC_PAGESIZE)") {
      return RunSysconfTest(output, _SC_PAGESIZE);
    } else if (test_input.test_target() == "getpid") {
      return RunGetPidTest(output);
    } else if (test_input.test_target() == "unlink") {
      return RunUnlinkTest(test_input.path_name());
    } else if (test_input.test_target() == "fcntl") {
      return RunFcntlTest(test_input.path_name());
    } else if (test_input.test_target() == "mkdir") {
      return RunMkdirTest(test_input.path_name());
    } else if (test_input.test_target() == "dup") {
      return RunDupTest(test_input.path_name());
    } else if (test_input.test_target() == "gethostname") {
      return RunGetHostNameTest(output);
    } else if (test_input.test_target() == "link") {
      return RunLinkTest(test_input.path_name());
    } else if (test_input.test_target() == "getcwd") {
      return RunGetCwdTest(test_input.provide_buffer(),
                           test_input.buffer_size(), output);
    } else if (test_input.test_target() == "umask") {
      return RunUmaskTest(test_input.path_name());
    } else if (test_input.test_target() == "getuid") {
      return RunGetUidTest(output);
    } else if (test_input.test_target() == "geteuid") {
      return RunGetEuidTest(output);
    } else if (test_input.test_target() == "getgid") {
      return RunGetGidTest(output);
    } else if (test_input.test_target() == "getegid") {
      return RunGetEgidTest(output);
    } else if (test_input.test_target() == "getppid") {
      return RunGetPpidTest(output);
    } else if (test_input.test_target() == "sched_getaffinity") {
      return RunSchedGetAffinityTest(output);
    } else if (test_input.test_target() == "sched_getaffinity failure") {
      return RunSchedGetAffinityFailureTest(output);
    } else if (test_input.test_target() == "CPU_SET macros") {
      return RunCpuSetMacrosTest(output);
    } else if (test_input.test_target() == "stat") {
      return RunStatTest(test_input.path_name(), output);
    } else if (test_input.test_target() == "fstat") {
      return RunFStatTest(test_input.path_name(), output);
    } else if (test_input.test_target() == "lstat") {
      return RunLStatTest(test_input.path_name(), output);
    } else if (test_input.test_target() == "uname") {
      return RunUnameTest(output);
    } else if (test_input.test_target() == "writev") {
      return RunWritevTest(test_input.path_name());
    } else if (test_input.test_target() == "readv") {
      return RunReadvTest(test_input.path_name());
    } else if (test_input.test_target() == "rlimit nofile") {
      return RunRlimitNoFileTest(test_input.path_name());
    } else if (test_input.test_target() == "rlimit low nofile") {
      return RunRlimitLowNoFileTest(test_input.path_name());
    } else if (test_input.test_target() == "rlimit invalid nofile") {
      return RunRlimitInvalidNoFileTest(test_input.path_name());
    } else if (test_input.test_target() == "chmod") {
      return RunChModTest(test_input.path_name());
    } else if (test_input.test_target() == "getifaddrs") {
      return RunGetIfAddrsTest(output);
    } else if (test_input.test_target() == "truncate") {
      return RunTruncateTest(test_input.path_name());
    } else if (test_input.test_target() == "mmap") {
      return RunMmapTest();
    }

    LOG(ERROR) << "Failed to identify test to execute.";

    regex_t regex;
    if (regcomp(&regex, "", 0)) {
      return Status(error::GoogleError::INTERNAL, "recomp error");
    }
    regfree(&regex);

    return Status::OkStatus();
  }

 private:
  void EncodeErrnoValueInTestOutput(int errno_value,
                                    SyscallsTestOutput *test_output) {
    test_output->clear_errno_syscall_value();
    switch (errno_value) {
      case 0:
        test_output->set_errno_syscall_value(SyscallsTestOutput::ERRNO_ZERO);
        break;
      case EINVAL:
        test_output->set_errno_syscall_value(SyscallsTestOutput::ERRNO_EINVAL);
        break;
      default:
        test_output->set_errno_syscall_value(SyscallsTestOutput::UNSUPPORTED);
    }
  }

  // Encodes a cpu_set_t in the bit_mask_syscall_outptr field of a
  // SyscallsTestOutput protobuf.
  void EncodeCpuSetInTestOutput(cpu_set_t &mask,
                                SyscallsTestOutput *test_output) {
    test_output->clear_bit_mask_syscall_outptr();
    for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
      int word_num = cpu / (8 * sizeof(uint64_t));
      int bit_num = cpu % (8 * sizeof(uint64_t));
      if (bit_num == 0) {
        test_output->add_bit_mask_syscall_outptr(0);
      }
      if (CPU_ISSET(cpu, &mask)) {
        *test_output->mutable_bit_mask_syscall_outptr()->Mutable(word_num) |=
            static_cast<uint64_t>(1) << bit_num;
      }
    }
  }

  // Encodes a struct stat in the stat_buffer_syscall_return field of a
  // SyscallsTestOutput protobuf.
  void EncodeStatBufferInTestOutput(const struct stat &stat_buffer,
                                    SyscallsTestOutput *test_output) {
    using google::protobuf::int64;

    SyscallsTestOutput::StatValue *proto_stat_buffer =
        test_output->mutable_stat_buffer_syscall_return();

    proto_stat_buffer->set_st_dev(static_cast<int64>(stat_buffer.st_dev));
    proto_stat_buffer->set_st_ino(static_cast<int64>(stat_buffer.st_ino));
    proto_stat_buffer->set_st_mode(static_cast<int64>(stat_buffer.st_mode));
    proto_stat_buffer->set_st_nlink(static_cast<int64>(stat_buffer.st_nlink));
    proto_stat_buffer->set_st_uid(static_cast<int64>(stat_buffer.st_uid));
    proto_stat_buffer->set_st_gid(static_cast<int64>(stat_buffer.st_gid));
    proto_stat_buffer->set_st_rdev(static_cast<int64>(stat_buffer.st_rdev));
    proto_stat_buffer->set_st_size(static_cast<int64>(stat_buffer.st_size));
    proto_stat_buffer->set_st_atime_val(
        static_cast<int64>(stat_buffer.st_atime));
    proto_stat_buffer->set_st_mtime_val(
        static_cast<int64>(stat_buffer.st_mtime));
    proto_stat_buffer->set_st_ctime_val(
        static_cast<int64>(stat_buffer.st_ctime));
    proto_stat_buffer->set_st_blksize(
        static_cast<int64>(stat_buffer.st_blksize));
    proto_stat_buffer->set_st_blocks(static_cast<int64>(stat_buffer.st_blocks));
  }

  // Encodes a struct utsname in the utsname_syscall_return field of a
  // SyscallsTestOutput protobuf.
  void EncodeUtsNameInTestOutput(struct utsname &utsname_buf,
                                 SyscallsTestOutput *test_output) {
    SyscallsTestOutput::UtsName *proto_utsname =
        test_output->mutable_utsname_syscall_return();

    proto_utsname->set_sysname(utsname_buf.sysname,
                               sizeof(utsname_buf.sysname));
    proto_utsname->set_nodename(utsname_buf.nodename,
                                sizeof(utsname_buf.nodename));
    proto_utsname->set_release(utsname_buf.release,
                               sizeof(utsname_buf.release));
    proto_utsname->set_version(utsname_buf.version,
                               sizeof(utsname_buf.version));
    proto_utsname->set_machine(utsname_buf.machine,
                               sizeof(utsname_buf.machine));
    proto_utsname->set_domainname(utsname_buf.domainname,
                                  sizeof(utsname_buf.domainname));
  }

  StatusOr<int> OpenFile(const std::string &path, int flags, mode_t mode) {
    if (path.empty()) {
      return Status(error::GoogleError::INVALID_ARGUMENT, "File path is empty");
    }
    int fd = open(path.c_str(), flags, mode);
    if (fd < 0) {
      return Status(
          static_cast<error::GoogleError>(errno),
          absl::StrCat("Open path ", path, " failed: ", strerror(errno)));
    }
    return fd;
  }

  Status ReadFile(int fd, char *buf, int size) {
    int read_bytes = 0;
    while (read_bytes < size) {
      int rc = read(fd, buf + read_bytes, size - read_bytes);
      read_bytes += rc;
      if (read_bytes > size || rc < 0) {
        return Status(
            static_cast<error::PosixError>(errno),
            absl::StrCat("Failed to read from file, error:", strerror(errno)));
      }
    }
    if (read_bytes != size) {
      return Status(error::GoogleError::INTERNAL,
                    "Bytes read from file does not match specified size");
    }
    return Status::OkStatus();
  }

  Status RunSysconfTest(EnclaveOutput *output, int name) {
    SyscallsTestOutput output_ret;
    output_ret.set_int_syscall_return(sysconf(name));
    if (output) {
      output->MutableExtension(syscalls_test_output)->CopyFrom(output_ret);
    }
    return Status::OkStatus();
  }

  Status RunGetPidTest(EnclaveOutput *output) {
    SyscallsTestOutput output_ret;
    output_ret.set_int_syscall_return(getpid());
    if (output) {
      output->MutableExtension(syscalls_test_output)->CopyFrom(output_ret);
    }
    return Status::OkStatus();
  }

  Status RunUnlinkTest(const std::string &path) {
    int fd;
    ASYLO_ASSIGN_OR_RETURN(fd, OpenFile(path, O_CREAT | O_RDWR, 0644));
    close(fd);
    if (unlink(path.c_str()) == -1) {
      return Status(
          static_cast<error::PosixError>(errno),
          absl::StrCat("Unlink file ", path, "failed: ", strerror(errno)));
    }
    fd = open(path.c_str(), O_RDWR);
    if (fd >= 0) {
      close(fd);
      return Status(
          error::GoogleError::INTERNAL,
          absl::StrCat("File ", path, " is still available after unlink"));
    }
    return Status::OkStatus();
  }

  Status RunFcntlTest(const std::string &path) {
    int fd;
    ASYLO_ASSIGN_OR_RETURN(fd, OpenFile(path, O_CREAT | O_RDWR, 0644));
    platform::storage::FdCloser fd_closer(fd);

    // TEST F_SETFL and F_GETFL.
    if (fcntl(fd, F_SETFL, O_NONBLOCK | O_APPEND) == -1) {
      close(fd);
      return Status(error::GoogleError::INTERNAL,
                    absl::StrCat("Fcntl set flags for file ", path,
                                 " failed: ", strerror(errno)));
    }
    int flags = fcntl(fd, F_GETFL);
    if (!(flags & O_NONBLOCK) || !(flags & O_APPEND)) {
      return Status(error::GoogleError::INTERNAL,
                    absl::StrCat("Fcntl get flags of file ", path,
                                 " returned unexpected result: ", flags));
    }

    // TEST F_SETFD and F_GETFD.
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1) {
      close(fd);
      return Status(error::GoogleError::INTERNAL,
                    absl::StrCat("Fcntl set FD flags for file ", path,
                                 "failed: ", strerror(errno)));
    }
    int fd_flags = fcntl(fd, F_GETFD);
    if (!(fd_flags & FD_CLOEXEC)) {
      return Status(
          error::GoogleError::INTERNAL,
          absl::StrCat("Fcntl get FD flags for file ", path,
                       "returned unexpected result: ", strerror(errno)));
    }

    // Test F_DUPFD.
    const std::string message = path;
    size_t rc = write(fd, message.c_str(), message.size());
    if (rc != message.size()) {
      return Status(
          static_cast<error::GoogleError>(errno),
          absl::StrCat("Write to file:", path, " failed: ", strerror(errno)));
    }

    int dup_fd = fcntl(fd, F_DUPFD, -1);
    if (dup_fd != -1 || errno != EINVAL) {
      return Status(error::GoogleError::INTERNAL,
                    "fcntl F_DUPFD with negative arg succeeded");
    }

    static constexpr int kMaxOpenFiles = 1024;
    dup_fd = fcntl(fd, F_DUPFD, kMaxOpenFiles);
    if (dup_fd != -1 || errno != EINVAL) {
      return Status(error::GoogleError::INTERNAL,
                    "fcntl F_DUPFD with over ranged arg succeeded");
    }

    dup_fd = fcntl(fd, F_DUPFD, fd);
    if (dup_fd == -1) {
      return Status(
          static_cast<error::GoogleError>(errno),
          absl::StrCat("fcntl dup fd:", fd, " failed: ", strerror(errno)));
    }
    if (dup_fd <= fd) {
      return Status(error::GoogleError::INTERNAL,
                    absl::StrCat("fcntl dup fd:", dup_fd,
                                 " is smaller than or equal to arg:", fd));
    }
    return CompareFiles(fd, dup_fd, message.size());
  }

  Status RunMkdirTest(const std::string &path) {
    if (path.empty()) {
      return Status(error::GoogleError::INVALID_ARGUMENT, "File path not set");
    }

    // Test that trying to mkdir() in registered random path fails.
    std::string random_path = "/dev/random";
    if (mkdir(random_path.c_str(), 0644) != -1) {
      return Status(error::GoogleError::INTERNAL,
                    absl::StrCat("Mkdir in registered random path:",
                                 random_path, "should be forbidden."));
    }

    if (mkdir(path.c_str(), 0644) == -1) {
      return Status(static_cast<error::PosixError>(errno),
                    absl::StrCat("Mkdir:", path, " failed: ", strerror(errno)));
    }
    return Status::OkStatus();
  }

  Status RunDupTest(const std::string &path) {
    const std::string message = path;
    int fd;
    ASYLO_ASSIGN_OR_RETURN(fd, OpenFile(path, O_CREAT | O_RDWR, 0644));
    platform::storage::FdCloser fd_closer(fd);
    ssize_t rc = write(fd, message.c_str(), message.size());
    if (rc != message.size()) {
      return Status(
          static_cast<error::GoogleError>(errno),
          absl::StrCat("Write to file:", path, " failed: ", strerror(errno)));
    }

    // Test dup.
    int dup_fd = dup(fd);
    if (dup_fd == -1) {
      return Status(static_cast<error::GoogleError>(errno),
                    absl::StrCat("dup fd:", fd, " failed: ", strerror(errno)));
    }
    if (dup_fd == fd) {
      return Status(
          error::GoogleError::INTERNAL,
          absl::StrCat("dup fd:", dup_fd, " is the same as original fd:", fd));
    }
    ASYLO_RETURN_IF_ERROR(CompareFiles(fd, dup_fd, message.size()));

    // Test dup2 with a used file descriptor.
    int dup2_fd = dup2(fd, dup_fd);
    if (dup2_fd != dup_fd) {
      return Status(static_cast<error::GoogleError>(errno),
                    absl::StrCat("dup2 fd:", fd, " to fd:", dup_fd,
                                 " failed: ", strerror(errno)));
    }
    ASYLO_RETURN_IF_ERROR(CompareFiles(fd, dup2_fd, message.size()));

    // Test dup2 with a different file descriptor.
    int newfd = 1000;
    dup2_fd = dup2(fd, newfd);
    if (dup2_fd != newfd) {
      return Status(static_cast<error::GoogleError>(errno),
                    absl::StrCat("dup2 fd:", fd, " to fd:", newfd,
                                 " failed: ", strerror(errno)));
    }
    ASYLO_RETURN_IF_ERROR(CompareFiles(fd, dup2_fd, message.size()));

    // Test whether we can still read from one of the file descriptors after
    // closing the other.
    if (close(fd) == -1) {
      return Status(
          static_cast<error::GoogleError>(errno),
          absl::StrCat("close fd:", fd, " failed: ", strerror(errno)));
    }
    char buf[1024];
    rc = read(newfd, buf, sizeof(buf));
    if (rc >= sizeof(buf) || rc < 0) {
      return Status(static_cast<error::GoogleError>(errno),
                    absl::StrCat("Read from newfd:", newfd,
                                 " failed after closing fd: ", fd,
                                 " error:", strerror(errno)));
    }

    return Status::OkStatus();
  }

  Status CompareFiles(int fd1, int fd2, int size) {
    if (lseek(fd1, 0, SEEK_SET) == -1) {
      return Status(static_cast<error::GoogleError>(errno),
                    absl::StrCat("Moving to beginning of fd:", fd1,
                                 " failed: ", strerror(errno)));
    }
    char buf1[1024];
    ASYLO_RETURN_IF_ERROR(ReadFile(fd1, buf1, size));

    if (lseek(fd2, 0, SEEK_SET) == -1) {
      return Status(static_cast<error::GoogleError>(errno),
                    absl::StrCat("Moving to beginning of fd:", fd2,
                                 " failed: ", strerror(errno)));
    }
    char buf2[1024];
    ASYLO_RETURN_IF_ERROR(ReadFile(fd2, buf2, size));

    if (memcmp(buf1, buf2, size) != 0) {
      return Status(
          error::GoogleError::INTERNAL,
          absl::StrCat("Fd:", fd1, " and fd:", fd2, " are different"));
    }
    return Status::OkStatus();
  }

  Status RunGetHostNameTest(EnclaveOutput *output) {
    char buf[1024];
    if (gethostname(buf, sizeof(buf)) == -1) {
      return Status(static_cast<error::GoogleError>(errno),
                    absl::StrCat("gethostname failed:", strerror(errno)));
    }
    SyscallsTestOutput output_ret;
    output_ret.set_string_syscall_return(std::string(buf));
    if (output) {
      output->MutableExtension(syscalls_test_output)->CopyFrom(output_ret);
    }
    return Status::OkStatus();
  }

  Status RunLinkTest(const std::string &path) {
    if (path.empty()) {
      return Status(error::GoogleError::INVALID_ARGUMENT, "File path not set");
    }
    const std::string from_path = std::string(path) + "from";
    const std::string to_path = std::string(path) + "to";
    int from_fd;
    ASYLO_ASSIGN_OR_RETURN(from_fd,
                           OpenFile(from_path, O_CREAT | O_RDWR, 0644));

    platform::storage::FdCloser from_fd_closer(from_fd);
    size_t rc = write(from_fd, path.c_str(), path.size());
    if (rc != path.size()) {
      return Status(static_cast<error::PosixError>(errno),
                    absl::StrCat("Failed to write to file:", from_path,
                                 " error:", strerror(errno)));
    }
    if (link(from_path.c_str(), to_path.c_str()) == -1) {
      return Status(static_cast<error::GoogleError>(errno),
                    absl::StrCat("Link path ", from_path, " to ", to_path,
                                 " failed: ", strerror(errno)));
    }
    int to_fd;
    ASYLO_ASSIGN_OR_RETURN(to_fd, OpenFile(to_path, O_RDWR, 0));
    platform::storage::FdCloser to_fd_closer(to_fd);

    char buf[1024];
    ASYLO_RETURN_IF_ERROR(ReadFile(to_fd, buf, path.size()));
    if (memcmp(buf, path.c_str(), path.size()) != 0) {
      return Status(
          error::GoogleError::INTERNAL,
          absl::StrCat("The content:", buf, " from linked path:", to_path,
                       " is different from the original path:", from_path));
    }
    return Status::OkStatus();
  }

  Status RunGetCwdTest(bool provide_buffer, int32_t buffer_size,
                       EnclaveOutput *output) {
    char stack_buffer[PATH_MAX];
    char *buf = getcwd(provide_buffer ? stack_buffer : nullptr,
                       std::min(buffer_size, PATH_MAX));
    if (!buf) {
      return Status(static_cast<error::GoogleError>(errno),
                    absl::StrCat("getcwd failed:", strerror(errno)));
    }
    SyscallsTestOutput output_ret;
    output_ret.set_string_syscall_return(std::string(buf));
    if (output) {
      output->MutableExtension(syscalls_test_output)->CopyFrom(output_ret);
    }
    return Status::OkStatus();
  }

  Status RunUmaskTest(const std::string &path) {
    umask(S_IWGRP | S_IWOTH);
    if (mkdir(path.c_str(), 0777) == -1) {
      return Status(static_cast<error::GoogleError>(errno),
                    absl::StrCat("mkdir failed:", strerror(errno)));
    }
    struct stat st;
    if (stat(path.c_str(), &st) == -1) {
      return Status(static_cast<error::GoogleError>(errno),
                    absl::StrCat("stat failed:", strerror(errno)));
    }
    if (st.st_mode & S_IWGRP || st.st_mode & S_IWOTH) {
      return Status(error::GoogleError::INTERNAL,
                    "Mkdir creates a directory with masked file modes");
    }
    const std::string file_path = path + "OpenWithUmask";
    int fd;
    ASYLO_ASSIGN_OR_RETURN(fd,
                           OpenFile(file_path.c_str(), O_CREAT | O_RDWR, 0777));
    platform::storage::FdCloser fd_closer(fd);
    if (fstat(fd, &st) == -1) {
      return Status(static_cast<error::GoogleError>(errno),
                    absl::StrCat("fstat failed:", strerror(errno)));
    }
    if (st.st_mode & S_IWGRP || st.st_mode & S_IWOTH) {
      return Status(error::GoogleError::INTERNAL,
                    "Open creates a file with masked file modes");
    }
    return Status::OkStatus();
  }

  Status RunGetUidTest(EnclaveOutput *output) {
    SyscallsTestOutput output_ret;
    output_ret.set_int_syscall_return(getuid());
    if (output) {
      output->MutableExtension(syscalls_test_output)->CopyFrom(output_ret);
    }
    return Status::OkStatus();
  }

  Status RunGetEuidTest(EnclaveOutput *output) {
    SyscallsTestOutput output_ret;
    output_ret.set_int_syscall_return(geteuid());
    if (output) {
      output->MutableExtension(syscalls_test_output)->CopyFrom(output_ret);
    }
    return Status::OkStatus();
  }

  Status RunGetGidTest(EnclaveOutput *output) {
    SyscallsTestOutput output_ret;
    output_ret.set_int_syscall_return(getgid());
    if (output) {
      output->MutableExtension(syscalls_test_output)->CopyFrom(output_ret);
    }
    return Status::OkStatus();
  }

  Status RunGetEgidTest(EnclaveOutput *output) {
    SyscallsTestOutput output_ret;
    output_ret.set_int_syscall_return(getegid());
    if (output) {
      output->MutableExtension(syscalls_test_output)->CopyFrom(output_ret);
    }
    return Status::OkStatus();
  }

  Status RunGetPpidTest(EnclaveOutput *output) {
    SyscallsTestOutput output_ret;
    output_ret.set_int_syscall_return(getppid());
    if (output) {
      output->MutableExtension(syscalls_test_output)->CopyFrom(output_ret);
    }
    return Status::OkStatus();
  }

  Status RunSchedGetAffinityTest(EnclaveOutput *output) {
    SyscallsTestOutput output_ret;
    pid_t my_pid = getpid();
    cpu_set_t mask;

    output_ret.set_int_syscall_return(
        sched_getaffinity(my_pid, sizeof(cpu_set_t), &mask));
    output_ret.clear_bit_mask_syscall_outptr();

    // Translate from enclave cpu_set_t to bit_mask_syscall_outptr.
    EncodeCpuSetInTestOutput(mask, &output_ret);

    if (output) {
      output->MutableExtension(syscalls_test_output)->CopyFrom(output_ret);
    }
    return Status::OkStatus();
  }

  Status RunSchedGetAffinityFailureTest(EnclaveOutput *output) {
    SyscallsTestOutput output_ret;
    pid_t my_pid = getpid();
    cpu_set_t mask;
    size_t bad_cpu_set_size = sizeof(cpu_set_t) / 2;

    output_ret.set_int_syscall_return(
        sched_getaffinity(my_pid, bad_cpu_set_size, &mask));

    EncodeErrnoValueInTestOutput(errno, &output_ret);

    if (output) {
      output->MutableExtension(syscalls_test_output)->CopyFrom(output_ret);
    }
    return Status::OkStatus();
  }

  Status RunCpuSetMacrosTest(EnclaveOutput *output) {
    SyscallsTestOutput output_ret;
    cpu_set_t mask;

    // Test CPU_ZERO by zero-ing a mask and checking that each bit is unset.
    CPU_ZERO(&mask);
    for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
      if (CPU_ISSET(cpu, &mask)) {
        return Status(error::GoogleError::INTERNAL,
                      absl::StrCat("CPU ", cpu, " is set after CPU_ZERO."));
      }
    }

    // Test CPU_SET by setting a pre-determined set of bits and checking that
    // they are precisely the ones set.

    const absl::flat_hash_set<int> test_cpu_set_cpus(
        {1, 2, 5, 14, 42, 132, 429});
    CPU_ZERO(&mask);
    for (int cpu : test_cpu_set_cpus) {
      CPU_SET(cpu, &mask);
    }
    for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
      if (!CPU_ISSET(cpu, &mask) && test_cpu_set_cpus.count(cpu)) {
        return Status(error::GoogleError::INTERNAL,
                      absl::StrCat("CPU ", cpu, " is not set after CPU_SET."));
      } else if (CPU_ISSET(cpu, &mask) && !test_cpu_set_cpus.count(cpu)) {
        return Status(error::GoogleError::INTERNAL,
                      absl::StrCat("CPU ", cpu, " is set without CPU_SET."));
      }
    }

    // Test CPU_CLR by setting a pre-determined set of bits and unsetting a
    // pre-determined subset, then checking that the subset of bits are all
    // unset.

    const absl::flat_hash_set<int> test_cpu_clr_cpus_to_set(
        {1, 2, 5, 14, 42, 132, 429});
    const absl::flat_hash_set<int> test_cpu_clr_cpus_to_clear({2, 5, 132});
    CPU_ZERO(&mask);
    for (int cpu : test_cpu_clr_cpus_to_set) {
      CPU_SET(cpu, &mask);
    }
    for (int cpu : test_cpu_clr_cpus_to_clear) {
      CPU_CLR(cpu, &mask);
    }
    for (int cpu : test_cpu_clr_cpus_to_set) {
      if (CPU_ISSET(cpu, &mask) && test_cpu_clr_cpus_to_clear.count(cpu)) {
        return Status(error::GoogleError::INTERNAL,
                      absl::StrCat("CPU ", cpu, " is set after CPU_CLR."));
      } else if (!CPU_ISSET(cpu, &mask) &&
                 !test_cpu_clr_cpus_to_clear.count(cpu)) {
        return Status(
            error::GoogleError::INTERNAL,
            absl::StrCat("CPU ", cpu, " is not set without CPU_CLR."));
      }
    }

    // Test CPU_ISSET by setting a pre-determined set of bits and checking that
    // precisely the ones that should be set are.
    CPU_ZERO(&mask);
    for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
      if (cpu % 10 == 1 || cpu % 10 == 3 || cpu % 10 == 7 || cpu % 10 == 9) {
        CPU_SET(cpu, &mask);
      }
    }
    for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
      bool expected_value =
          (cpu % 10 == 1 || cpu % 10 == 3 || cpu % 10 == 7 || cpu % 10 == 9);
      if (static_cast<bool>(CPU_ISSET(cpu, &mask)) != expected_value) {
        return Status(
            error::GoogleError::INTERNAL,
            absl::StrCat("CPU_ISSET(", cpu, ") returns ", !expected_value,
                         "but should return ", expected_value, "."));
      }
    }

    // Test CPU_COUNT by setting a pre-determined set of bits and checking that
    // CPU_COUNT returns the expected cardinality.
    const int test_cpu_count_cpus[] = {1, 2, 5, 14, 42, 132, 429};
    const int test_cpu_count_expected_count = 7;
    CPU_ZERO(&mask);
    for (int cpu : test_cpu_count_cpus) {
      CPU_SET(cpu, &mask);
    }
    const int cpu_count = CPU_COUNT(&mask);
    if (cpu_count != test_cpu_count_expected_count) {
      return Status(
          error::GoogleError::INTERNAL,
          absl::StrCat("CPU_COUNT returns ", cpu_count, " but should return ",
                       test_cpu_count_expected_count, "."));
    }

    // Test CPU_EQUAL by comparing a pre-determined bitset to itself.
    const int test_cpu_equal_cpus[] = {1, 2, 5, 14, 42, 132, 429};
    const int test_cpu_equal_cpus_different[] = {1,  2,  3,   6,   11,
                                                 23, 47, 106, 235, 551};
    CPU_ZERO(&mask);
    for (int cpu : test_cpu_equal_cpus) {
      CPU_SET(cpu, &mask);
    }
    if (!CPU_EQUAL(&mask, &mask)) {
      return Status(
          error::GoogleError::INTERNAL,
          absl::StrCat("CPU_EQUAL claims a mask is not equal to itself."));
    }

    cpu_set_t different_mask;
    CPU_ZERO(&different_mask);
    for (int cpu : test_cpu_equal_cpus_different) {
      CPU_SET(cpu, &different_mask);
    }
    if (CPU_EQUAL(&mask, &different_mask)) {
      return Status(
          error::GoogleError::INTERNAL,
          absl::StrCat("CPU_EQUAL claims two different masks are equal."));
    }

    if (output) {
      output->MutableExtension(syscalls_test_output)->CopyFrom(output_ret);
    }
    return Status::OkStatus();
  }

  Status RunStatTest(const std::string &path, EnclaveOutput *output) {
    SyscallsTestOutput output_ret;

    struct stat stat_buffer;
    output_ret.set_int_syscall_return(stat(path.c_str(), &stat_buffer));

    EncodeStatBufferInTestOutput(stat_buffer, &output_ret);

    if (output) {
      output->MutableExtension(syscalls_test_output)->CopyFrom(output_ret);
    }
    return Status::OkStatus();
  }

  Status RunFStatTest(const std::string &path, EnclaveOutput *output) {
    SyscallsTestOutput output_ret;

    int fd = open(path.c_str(), O_RDONLY);
    if (fd == -1) {
      return Status(static_cast<error::GoogleError>(errno),
                    absl::StrCat("open failed:", strerror(errno)));
    }

    struct stat stat_buffer;
    output_ret.set_int_syscall_return(fstat(fd, &stat_buffer));

    if (close(fd) == -1) {
      return Status(static_cast<error::GoogleError>(errno),
                    absl::StrCat("close failed:", strerror(errno)));
    }

    EncodeStatBufferInTestOutput(stat_buffer, &output_ret);

    if (output) {
      output->MutableExtension(syscalls_test_output)->CopyFrom(output_ret);
    }
    return Status::OkStatus();
  }

  Status RunLStatTest(const std::string &path, EnclaveOutput *output) {
    SyscallsTestOutput output_ret;

    struct stat stat_buffer;
    output_ret.set_int_syscall_return(lstat(path.c_str(), &stat_buffer));

    EncodeStatBufferInTestOutput(stat_buffer, &output_ret);

    if (output) {
      output->MutableExtension(syscalls_test_output)->CopyFrom(output_ret);
    }
    return Status::OkStatus();
  }

  Status RunUnameTest(EnclaveOutput *output) {
    SyscallsTestOutput output_ret;
    struct utsname utsname_buf;

    int ret = uname(&utsname_buf);
    output_ret.set_int_syscall_return(ret);

    if (ret == 0) {
      EncodeUtsNameInTestOutput(utsname_buf, &output_ret);
    } else {
      EncodeErrnoValueInTestOutput(errno, &output_ret);
    }

    if (output) {
      output->MutableExtension(syscalls_test_output)->CopyFrom(output_ret);
    }
    return Status::OkStatus();
  }

  Status RunWritevTest(const std::string &path) {
    int fd;
    ASYLO_ASSIGN_OR_RETURN(fd, OpenFile(path, O_CREAT | O_RDWR, 0644));
    platform::storage::FdCloser fd_closer(fd);
    constexpr int num_messages = 2;
    const std::string message1 = "First writev message";
    const std::string message2 = "Second writev message";
    const std::string message = message1 + message2;
    struct iovec iov[num_messages];
    memset(iov, 0, sizeof(iov));
    iov[0].iov_base = const_cast<char *>(message1.c_str());
    iov[1].iov_base = const_cast<char *>(message2.c_str());
    iov[0].iov_len = message1.size();
    iov[1].iov_len = message2.size();
    int size = message.size();
    ssize_t rc = writev(fd, iov, num_messages);
    if (rc != size) {
      return Status(static_cast<error::PosixError>(errno),
                    absl::StrCat("writev return:", rc,
                                 " does not match message size:", size));
    }

    if (lseek(fd, 0, SEEK_SET) == -1) {
      return Status(static_cast<error::PosixError>(errno),
                    absl::StrCat("Moving to beginning of fd:", fd,
                                 " failed: ", strerror(errno)));
    }

    char buf[1024];
    ASYLO_RETURN_IF_ERROR(ReadFile(fd, buf, size));
    if (memcmp(buf, message.c_str(), message.size()) != 0) {
      return Status(error::GoogleError::INTERNAL,
                    absl::StrCat("Message read from fd:", fd, ":", buf,
                                 " is different from the message of writev."));
    }
    return Status::OkStatus();
  }

  Status RunReadvTest(const std::string &path) {
    int fd;
    ASYLO_ASSIGN_OR_RETURN(fd, OpenFile(path, O_CREAT | O_RDWR, 0644));
    platform::storage::FdCloser fd_closer(fd);
    constexpr int num_messages = 2;
    const std::string message1 = "First readv message";
    const std::string message2 = "Second readv message";
    const std::string message = message1 + message2;
    ssize_t rc = write(fd, message.c_str(), message.size());
    if (rc != message.size()) {
      return Status(error::GoogleError::INTERNAL,
                    "Bytes written to file does not match message size");
    }
    if (lseek(fd, 0, SEEK_SET) == -1) {
      return Status(static_cast<error::PosixError>(errno),
                    absl::StrCat("Moving to beginning of fd:", fd,
                                 " failed: ", strerror(errno)));
    }
    struct iovec iov[num_messages];
    memset(iov, 0, sizeof(iov));
    char buf1[message1.size()];
    char buf2[message2.size()];
    iov[0].iov_base = reinterpret_cast<void *>(buf1);
    iov[1].iov_base = reinterpret_cast<void *>(buf2);
    iov[0].iov_len = message1.size();
    iov[1].iov_len = message2.size();
    rc = readv(fd, iov, num_messages);
    if (rc != message.size()) {
      return Status(
          error::GoogleError::INTERNAL,
          absl::StrCat("readv return:", rc,
                       " does not match message size:", message.size()));
    }
    if (memcmp(reinterpret_cast<char *>(iov[0].iov_base), message1.c_str(),
               iov[0].iov_len) ||
        memcmp(reinterpret_cast<char *>(iov[1].iov_base), message2.c_str(),
               iov[1].iov_len)) {
      return Status(error::GoogleError::INTERNAL,
                    "Messages from readv do not match the expected message.");
    }
    return Status::OkStatus();
  }

  Status RunRlimitNoFileTest(const std::string &path) {
    constexpr int soft_limit = 100;
    constexpr int hard_limit = 200;
    struct rlimit set_limit;
    set_limit.rlim_cur = soft_limit;
    set_limit.rlim_max = hard_limit;
    if (setrlimit(RLIMIT_NOFILE, &set_limit) != 0) {
      return Status(static_cast<error::PosixError>(errno),
                    absl::StrCat("setrlimit failed:", strerror(errno)));
    }
    struct rlimit get_limit;
    if (getrlimit(RLIMIT_NOFILE, &get_limit) != 0) {
      return Status(static_cast<error::PosixError>(errno),
                    absl::StrCat("getrlimit failed:", strerror(errno)));
    }
    if (get_limit.rlim_cur != soft_limit || get_limit.rlim_max != hard_limit) {
      return Status(error::GoogleError::INTERNAL,
                    "The file descriptor number limit from getrlimit is "
                    "different from the value set");
    }
    return Status::OkStatus();
  }

  Status RunRlimitLowNoFileTest(const std::string &path) {
    constexpr int file_descriptor_used = 3;
    struct rlimit set_limit;
    // Set the fd limit to 3, no file descriptor should be available now, since
    // the first 3 are for stdin, stdout, and stderr.
    set_limit.rlim_cur = file_descriptor_used;
    set_limit.rlim_max = file_descriptor_used;
    if (setrlimit(RLIMIT_NOFILE, &set_limit) != 0) {
      return Status(static_cast<error::PosixError>(errno),
                    absl::StrCat("setrlimit failed:", strerror(errno)));
    }
    auto fd_or_error = OpenFile(path, O_CREAT | O_RDWR, 0644);
    if (fd_or_error.ok()) {
      return Status(error::GoogleError::INTERNAL,
                    absl::StrCat("File descriptor: ", fd_or_error.ValueOrDie(),
                                 " is used while the rlimit is set to: ",
                                 file_descriptor_used));
    }
    return Status::OkStatus();
  }

  Status RunRlimitInvalidNoFileTest(const std::string &path) {
    struct rlimit get_limit;
    if (getrlimit(RLIMIT_NOFILE, &get_limit) != 0) {
      return Status(static_cast<error::PosixError>(errno),
                    absl::StrCat("getrlimit failed:", strerror(errno)));
    }
    int old_soft_limit = get_limit.rlim_cur;
    int old_hard_limit = get_limit.rlim_max;

    constexpr int invalid_limit = 2;
    struct rlimit set_limit;
    set_limit.rlim_cur = invalid_limit;
    set_limit.rlim_max = invalid_limit;
    // There are already 3 file descriptors open: stdin, stdout, stderr, setting
    // the limit to 2 should not succeed.
    if (setrlimit(RLIMIT_NOFILE, &set_limit) != -1) {
      return Status(error::GoogleError::INTERNAL,
                    "setrlimit to limit lower than current used file "
                    "descriptors unexpectedly succeeded");
    }
    // Checks that the limit is unchanged after a failed setrlimit.
    if (getrlimit(RLIMIT_NOFILE, &get_limit) != 0) {
      return Status(static_cast<error::PosixError>(errno),
                    absl::StrCat("getrlimit failed:", strerror(errno)));
    }

    // setrlimit should fail if the soft limit is higher than the hard limit.
    set_limit.rlim_cur = 200;
    set_limit.rlim_max = 100;
    if (setrlimit(RLIMIT_NOFILE, &set_limit) != -1) {
      return Status(error::GoogleError::INTERNAL,
                    "setrlimit with soft limit higher than hard limit "
                    "unexpectedly succeeded");
    }

    // setrlimit should fail if the limit is set to be greater than the maximum
    // allowed file descriptor number inside the enclave.
    set_limit.rlim_cur = 2000;
    set_limit.rlim_max = 2000;
    if (setrlimit(RLIMIT_NOFILE, &set_limit) != -1) {
      return Status(error::GoogleError::INTERNAL,
                    "setrlimit with limit higher than the maximum allowed "
                    "unexpectedly succeeded");
    }

    if (get_limit.rlim_cur != old_soft_limit ||
        get_limit.rlim_max != old_hard_limit) {
      return Status(error::GoogleError::INTERNAL,
                    absl::StrCat("NOFILE limit has changed after a series of"
                                 "failed setrlimits. Original soft limit: ",
                                 old_soft_limit,
                                 " current soft limit: ", get_limit.rlim_cur,
                                 " original hard limit: ", old_hard_limit,
                                 " current hard limit: ", get_limit.rlim_max));
    }

    // Lower the hard limit first, and verify that increasing the hard limit
    // should fail.
    set_limit.rlim_cur = 100;
    set_limit.rlim_max = 100;
    if (setrlimit(RLIMIT_NOFILE, &set_limit) != 0) {
      return Status(static_cast<error::PosixError>(errno),
                    absl::StrCat("setrlimit failed:", strerror(errno)));
    }
    set_limit.rlim_cur = 200;
    set_limit.rlim_max = 200;
    if (setrlimit(RLIMIT_NOFILE, &set_limit) != -1) {
      return Status(
          error::GoogleError::INTERNAL,
          "setrlimit to increase the hard limit unexpectedly succeeded");
    }

    return Status::OkStatus();
  }

  Status RunChModTest(const std::string &path) {
    if (chmod(path.c_str(), 0644) != 0) {
      return Status(static_cast<error::PosixError>(errno),
                    absl::StrCat("chmod failed: ", strerror(errno)));
    }
    return Status::OkStatus();
  }

  Status RunGetIfAddrsTest(EnclaveOutput *output) {
    struct ifaddrs *front = nullptr;
    int ret = getifaddrs(&front);
    char *serialized_ifaddrs = nullptr;
    size_t len;
    asylo::SerializeIfAddrs(front, &serialized_ifaddrs, &len);
    freeifaddrs(front);
    SyscallsTestOutput output_ret;
    output_ret.set_serialized_proto_return(std::string(serialized_ifaddrs, len));
    output_ret.set_int_syscall_return(ret);
    if (output) {
      output->MutableExtension(syscalls_test_output)->CopyFrom(output_ret);
    }
    return Status::OkStatus();
  }

  Status RunTruncateTest(const std::string &path) {
    int fd;
    ASYLO_ASSIGN_OR_RETURN(fd, OpenFile(path, O_CREAT | O_RDWR, 0644));
    platform::storage::FdCloser fd_closer(fd);
    const std::string message1 = "First message ";
    const std::string message2 = "Second message ";
    const std::string message3 = "Third message";
    const std::string message = message1 + message2 + message3;
    ssize_t rc = write(fd, message.c_str(), message.size());
    if (rc != message.size()) {
      return Status(
          static_cast<error::PosixError>(errno),
          absl::StrCat("write returns: ", rc,
                       " does not match message size: ", message.size()));
    }

    // First call truncate to truncate the file to the size of message1 +
    // message2.
    std::string truncated_message = message1 + message2;
    if (truncate(path.c_str(), truncated_message.size()) != 0) {
      return Status(
          static_cast<error::PosixError>(errno),
          absl::StrCat("Truncate file: ", path, " failed: ", strerror(errno)));
    }
    if (lseek(fd, 0, SEEK_SET) == -1) {
      return Status(static_cast<error::GoogleError>(errno),
                    absl::StrCat("Moving to beginning of fd:", fd,
                                 " failed: ", strerror(errno)));
    }
    char buf1[1024];
    rc = read(fd, buf1, message.size());
    if (rc != truncated_message.size() ||
        memcmp(buf1, truncated_message.c_str(), truncated_message.size()) !=
            0) {
      return Status(
          error::GoogleError::INTERNAL,
          absl::StrCat("Message read from truncated file is: ", buf1,
                       " and does not match expected: ", truncated_message));
    }

    // Now call ftruncate to truncate the file to the size of only message1.
    truncated_message = message1;
    if (ftruncate(fd, truncated_message.size()) != 0) {
      return Status(
          static_cast<error::PosixError>(errno),
          absl::StrCat("Ftruncate file: ", fd, " failed: ", strerror(errno)));
    }
    if (lseek(fd, 0, SEEK_SET) == -1) {
      return Status(static_cast<error::GoogleError>(errno),
                    absl::StrCat("Moving to beginning of fd:", fd,
                                 " failed: ", strerror(errno)));
    }
    char buf2[1024];
    rc = read(fd, buf2, message.size());
    if (rc != truncated_message.size() ||
        memcmp(buf2, truncated_message.c_str(), truncated_message.size()) !=
            0) {
      return Status(
          error::GoogleError::INTERNAL,
          absl::StrCat("Message read from truncated file is: ", buf1,
                       " and does not match expected: ", truncated_message));
    }
    return Status::OkStatus();
  }

  Status RunMmapTest() {
    // use mmap to allocate an aligned block of 10000 bytes.
    void *ptr = mmap(nullptr, 10000, PROT_READ | PROT_WRITE,
                     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (ptr == MAP_FAILED) {
      return Status(static_cast<error::PosixError>(errno),
                    "mmap(MAP_ANONYMOUS) failed");
    }
    intptr_t address = reinterpret_cast<intptr_t>(ptr);
    if ((address & 4095) != 0) {
      return Status(error::GoogleError::INTERNAL,
                    "mmap(MAP_ANONYMOUS) returned non-page-aligned memory");
    }
    char *cptr = static_cast<char*>(ptr);
    if (std::count(cptr, cptr + 10000, '\0') != 10000) {
      return Status(error::GoogleError::INTERNAL,
                    "mmap(MAP_ANONYMOUS) returned uninitialized memory");
    }
    if (munmap(ptr, 10000) != 0) {
      return Status(static_cast<error::PosixError>(errno),
                    "munmap() failed");
    }
    return Status::OkStatus();
  }
};

TrustedApplication *BuildTrustedApplication() { return new SyscallsEnclave; }

}  // namespace asylo
