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

#include <dirent.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <iostream>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/strings/str_cat.h"
#include "asylo/test/misc/syscalls_test.pb.h"
#include "asylo/test/util/enclave_test.h"

// Enables gtest to print a struct stat on failure. This function needs to be in
// the global namespace to override gtest's default PrintTo function in ADL
// ordering.
void PrintTo(const struct stat &stat_buffer, std::ostream *output_stream) {
  *output_stream << absl::StrCat(
      "struct stat { st_dev = ", stat_buffer.st_dev,
      " , st_ino = ", stat_buffer.st_ino, " , st_mode = ", stat_buffer.st_mode,
      " , st_nlink = ", stat_buffer.st_nlink,
      " , st_uid = ", stat_buffer.st_uid, " , st_gid = ", stat_buffer.st_gid,
      " , st_rdev = ", stat_buffer.st_rdev,
      " , st_size = ", stat_buffer.st_size,
      " , st_atime = ", stat_buffer.st_atime,
      " , st_mtime = ", stat_buffer.st_mtime,
      " , st_ctime = ", stat_buffer.st_ctime,
      " , st_blksize = ", stat_buffer.st_blksize,
      " , st_blocks = ", stat_buffer.st_blocks, " }");
}

namespace asylo {
namespace {

const char *kCustomHostName = "CustomHostName";
const char *kCustomWorkingDirectory = "/tmp/testworkingdir";

// Invokes a system call from inside the enclave and returns its output (if
// needed).
bool RunEnclaveSyscall(EnclaveClient *client, const std::string &tested_syscall,
                       const std::string &file_path, bool provide_buffer,
                       int32_t buffer_size, SyscallsTestOutput *test_output) {
  EnclaveInput enclave_input;
  SyscallsTestInput *test_input =
      enclave_input.MutableExtension(syscalls_test_input);
  test_input->set_test_target(tested_syscall);
  if (!file_path.empty()) {
    test_input->set_path_name(file_path);
  }
  test_input->set_provide_buffer(provide_buffer);
  test_input->set_buffer_size(buffer_size);

  EnclaveOutput enclave_output;
  Status test_status = client->EnterAndRun(enclave_input, &enclave_output);
  if (!test_status.ok()) {
    LOG(ERROR) << "In test of " << tested_syscall << ": " << test_status;
    return false;
  }
  if (test_output) {
    if (!enclave_output.HasExtension(syscalls_test_output)) {
      return false;
    }
    *test_output = enclave_output.GetExtension(syscalls_test_output);
  }
  return true;
}

// Extracts a cpu_set_t from the bit_mask_syscall_outptr field of a
// SyscallsTestOutput protobuf.
void ExtractCpuSetFromTestOutput(const SyscallsTestOutput &test_output,
                                 cpu_set_t *mask) {
  CPU_ZERO(mask);
  int cpu = 0;
  for (const uint64_t &word : test_output.bit_mask_syscall_outptr()) {
    for (uint64_t bit_field = 1; bit_field != 0; bit_field <<= 1) {
      if (word & bit_field) {
        CPU_SET(cpu, mask);
      }
      ++cpu;
    }
  }
}

// Extracts a struct stat from the stat_buffer_syscall_return field of a
// SyscallsTestOutput protobuf.
void ExtractStatBufferFromTestOutput(const SyscallsTestOutput &test_output,
                                     struct stat *stat_buffer) {
  const SyscallsTestOutput::StatValue &proto_stat_buffer =
      test_output.stat_buffer_syscall_return();

  stat_buffer->st_dev = static_cast<dev_t>(proto_stat_buffer.st_dev());
  stat_buffer->st_ino = static_cast<ino_t>(proto_stat_buffer.st_ino());
  stat_buffer->st_mode = static_cast<mode_t>(proto_stat_buffer.st_mode());
  stat_buffer->st_nlink = static_cast<nlink_t>(proto_stat_buffer.st_nlink());
  stat_buffer->st_uid = static_cast<uid_t>(proto_stat_buffer.st_uid());
  stat_buffer->st_gid = static_cast<gid_t>(proto_stat_buffer.st_gid());
  stat_buffer->st_rdev = static_cast<dev_t>(proto_stat_buffer.st_rdev());
  stat_buffer->st_size = static_cast<off_t>(proto_stat_buffer.st_size());
  stat_buffer->st_atime = static_cast<time_t>(proto_stat_buffer.st_atime_val());
  stat_buffer->st_mtime = static_cast<time_t>(proto_stat_buffer.st_mtime_val());
  stat_buffer->st_ctime = static_cast<time_t>(proto_stat_buffer.st_ctime_val());
  stat_buffer->st_blksize =
      static_cast<blksize_t>(proto_stat_buffer.st_blksize());
  stat_buffer->st_blocks = static_cast<blkcnt_t>(proto_stat_buffer.st_blocks());
}

// Compares two struct stat objects, returning |true| if they are equal, and
// |false| otherwise.
MATCHER_P(EqualsStat, rhs_stat_buffer, "") {
  return (arg.st_dev == rhs_stat_buffer.st_dev) &&
         (arg.st_ino == rhs_stat_buffer.st_ino) &&
         (arg.st_mode == rhs_stat_buffer.st_mode) &&
         (arg.st_nlink == rhs_stat_buffer.st_nlink) &&
         (arg.st_uid == rhs_stat_buffer.st_uid) &&
         (arg.st_gid == rhs_stat_buffer.st_gid) &&
         (arg.st_rdev == rhs_stat_buffer.st_rdev) &&
         (arg.st_size == rhs_stat_buffer.st_size) &&
         (arg.st_atime == rhs_stat_buffer.st_atime) &&
         (arg.st_mtime == rhs_stat_buffer.st_mtime) &&
         (arg.st_ctime == rhs_stat_buffer.st_ctime) &&
         (arg.st_blksize == rhs_stat_buffer.st_blksize) &&
         (arg.st_blocks == rhs_stat_buffer.st_blocks);
}

// class that runs syscall tests with default enclave config.
class SyscallsTest : public EnclaveTest {
 protected:
  bool RunSyscallInsideEnclave(const std::string &tested_syscall,
                               const std::string &file_path,
                               SyscallsTestOutput *test_output) {
    return RunEnclaveSyscall(client_, tested_syscall, file_path, false, 0,
                             test_output);
  }

  bool RunSyscallInsideEnclave(const std::string &tested_syscall,
                               bool provide_buffer, int32_t buffer_size,
                               SyscallsTestOutput *test_output) {
    return RunEnclaveSyscall(client_, tested_syscall, "", provide_buffer,
                             buffer_size, test_output);
  }
};

// class that runs syscall tests with custom enclave config.
class CustomConfigSyscallsTest : public EnclaveTest {
 protected:
  void SetUp() override {
    config_.set_host_name(kCustomHostName);
    config_.set_current_working_directory(kCustomWorkingDirectory);
    EnclaveTest::SetUp();
  }

  bool RunSyscallInsideEnclave(const std::string &tested_syscall,
                               const std::string &file_path,
                               SyscallsTestOutput *test_output) {
    return RunEnclaveSyscall(client_, tested_syscall, file_path, false, 0,
                             test_output);
  }

  bool RunSyscallInsideEnclave(const std::string &tested_syscall,
                               bool provide_buffer, int32_t buffer_size,
                               SyscallsTestOutput *test_output) {
    return RunEnclaveSyscall(client_, tested_syscall, "", provide_buffer,
                             buffer_size, test_output);
  }
};

// Tests sysconf(). Currently only the parameter _SC_NPROCESSORS_ONLN is
// implemented in the enclave. This test checks whether
// sysconf(_SC_NPROCESSORS_ONLN) inside enclave gives the same result as outside
// the enclave.
TEST_F(SyscallsTest, Sysconf) {
  SyscallsTestOutput test_output;
  ASSERT_TRUE(RunSyscallInsideEnclave("sysconf", "", &test_output));
  ASSERT_TRUE(test_output.has_int_syscall_return());
  EXPECT_EQ(test_output.int_syscall_return(), sysconf(_SC_NPROCESSORS_ONLN));
}

// Tests getpid() by comparing the return value of getpid() inside/outside the
// enclave.
TEST_F(SyscallsTest, GetPid) {
  SyscallsTestOutput test_output;
  ASSERT_TRUE(RunSyscallInsideEnclave("getpid", "", &test_output));
  ASSERT_TRUE(test_output.has_int_syscall_return());
  EXPECT_EQ(test_output.int_syscall_return(), getpid());
}

// Tests unlink(). Opens a file, closes it and unlinks it. Then checks whether
// it's still available.
TEST_F(SyscallsTest, Unlink) {
  EXPECT_TRUE(RunSyscallInsideEnclave("unlink", FLAGS_test_tmpdir + "/unlink",
                                      nullptr));
}

// Tests fcntl() with F_GETFL and F_SETFL. Sets the file flags with F_SETFL,
// then uses F_GETFL to check whether it's set correctly.
TEST_F(SyscallsTest, Fcntl) {
  EXPECT_TRUE(
      RunSyscallInsideEnclave("fcntl", FLAGS_test_tmpdir + "/fcntl", nullptr));
}

// Tests mkdir(). Calls mkdir() inside enclave to create a directory. And checks
// the existence of the directory outside enclave.
TEST_F(SyscallsTest, Mkdir) {
  EXPECT_TRUE(
      RunSyscallInsideEnclave("mkdir", FLAGS_test_tmpdir + "/mkdir", nullptr));
  DIR *directory = opendir((FLAGS_test_tmpdir + "/mkdir").c_str());
  EXPECT_TRUE(directory);
  closedir(directory);
}

// Tests dup() and dup2(). Calls dup() and dup2() on a file descriptor, and
// checks whether the new file descriptor behaves the same as the original one.
TEST_F(SyscallsTest, Dup) {
  EXPECT_TRUE(
      RunSyscallInsideEnclave("dup", FLAGS_test_tmpdir + "/dup", nullptr));
}

// Tests gethostname() with default settings. Calls gethostname() inside
// enclave, and compares the result with the value outside enclave.
TEST_F(SyscallsTest, GetHostName) {
  SyscallsTestOutput test_output;
  ASSERT_TRUE(RunSyscallInsideEnclave("gethostname", "", &test_output));
  ASSERT_TRUE(test_output.has_string_syscall_return());
  char buf[1024];
  ASSERT_EQ(gethostname(buf, sizeof(buf)), 0);
  EXPECT_EQ(test_output.string_syscall_return(), buf);
}

// Tests gethostname() with custom settings. Sets host name config before
// loading enclave, Calls gethostname() inside enclave, and compares the result
// with the value set.
TEST_F(CustomConfigSyscallsTest, GetHostName) {
  SyscallsTestOutput test_output;
  ASSERT_TRUE(RunSyscallInsideEnclave("gethostname", "", &test_output));
  ASSERT_TRUE(test_output.has_string_syscall_return());
  EXPECT_EQ(test_output.string_syscall_return(), kCustomHostName);
}

// Tests link(). Calls link() inside enclave, writes to the old path, and reads
// from the new path to check whether they are the same.
TEST_F(SyscallsTest, Link) {
  EXPECT_TRUE(
      RunSyscallInsideEnclave("link", FLAGS_test_tmpdir + "/link", nullptr));
}

// Tests getcwd() with default settings. Calls getcwd() inside enclave and
// compares the result with the value outside enclave.
TEST_F(SyscallsTest, GetCwd) {
  SyscallsTestOutput test_output;
  ASSERT_TRUE(RunSyscallInsideEnclave("getcwd", true, PATH_MAX, &test_output));
  ASSERT_TRUE(test_output.has_string_syscall_return());
  char buf[PATH_MAX];
  ASSERT_NE(getcwd(buf, sizeof(buf)), nullptr);
  EXPECT_EQ(test_output.string_syscall_return(), buf);
}

// Tests getcwd() with default settings. Calls getcwd() inside enclave with 0
// buffer size and verifies the call fails.
TEST_F(SyscallsTest, GetCwdNoSize) {
  ASSERT_FALSE(RunSyscallInsideEnclave("getcwd", true, 0, nullptr));
}

// Tests getcwd() with default settings. Calls getcwd() inside enclave with no
// buffer and compares the result with the value outside the enclave.
TEST_F(SyscallsTest, GetCwdNoBuffer) {
  SyscallsTestOutput test_output;
  ASSERT_TRUE(RunSyscallInsideEnclave("getcwd", false, PATH_MAX, &test_output));
  ASSERT_TRUE(test_output.has_string_syscall_return());
  char buf[PATH_MAX];
  ASSERT_NE(getcwd(buf, sizeof(buf)), nullptr);
  EXPECT_EQ(test_output.string_syscall_return(), buf);
}

// Tests getcwd() with default settings. Calls getcwd() inside enclave with no
// buffer or size and compares the result with the value outside the enclave.
TEST_F(SyscallsTest, GetCwdNoBufferNoSize) {
  SyscallsTestOutput test_output;
  ASSERT_TRUE(RunSyscallInsideEnclave("getcwd", false, 0, &test_output));
  ASSERT_TRUE(test_output.has_string_syscall_return());
  char buf[PATH_MAX];
  ASSERT_NE(getcwd(buf, sizeof(buf)), nullptr);
  EXPECT_EQ(test_output.string_syscall_return(), buf);
}

// Tests getcwd() with custom settings. Sets working directory config before
// loading enclave, calls getcwd() inside enclave, and compares the result
// with the value set.
TEST_F(CustomConfigSyscallsTest, GetCwd) {
  SyscallsTestOutput test_output;
  ASSERT_TRUE(RunSyscallInsideEnclave("getcwd", "", &test_output));
  ASSERT_TRUE(test_output.has_string_syscall_return());
  EXPECT_EQ(test_output.string_syscall_return(), kCustomWorkingDirectory);
}

// Tests getcwd() with custom settings. Sets working directory config before
// loading enclave, calls getcwd() inside enclave with insufficient buffer size,
// and verifies the call fails.
TEST_F(CustomConfigSyscallsTest, GetCwdInsufficientSize) {
  ASSERT_FALSE(RunSyscallInsideEnclave(
      "getcwd", true, strlen(kCustomWorkingDirectory), nullptr));
}

// Tests getcwd() with custom settings. Sets working directory config before
// loading enclave, calls getcwd() inside enclave with no buffer and
// insufficient buffer size, and verifies the call fails.
TEST_F(CustomConfigSyscallsTest, GetCwdNoBufferInsufficientSize) {
  ASSERT_FALSE(RunSyscallInsideEnclave(
      "getcwd", false, strlen(kCustomWorkingDirectory), nullptr));
}

// Tests umask() by masking file modes and call open/mkdir to create new path
// with masked file modes, and check whether the mode exists in the new path.
TEST_F(SyscallsTest, Umask) {
  ASSERT_TRUE(
      RunSyscallInsideEnclave("umask", FLAGS_test_tmpdir + "/umask", nullptr));
}

// Tests getuid() by comparing the return value of getuid() inside/outside the
// enclave.
TEST_F(SyscallsTest, GetUid) {
  SyscallsTestOutput test_output;
  ASSERT_TRUE(RunSyscallInsideEnclave("getuid", "", &test_output));
  ASSERT_TRUE(test_output.has_int_syscall_return());
  EXPECT_EQ(test_output.int_syscall_return(), getuid());
}

// Tests geteuid() by comparing the return value of geteuid() inside/outside the
// enclave.
TEST_F(SyscallsTest, GetEuid) {
  SyscallsTestOutput test_output;
  ASSERT_TRUE(RunSyscallInsideEnclave("geteuid", "", &test_output));
  ASSERT_TRUE(test_output.has_int_syscall_return());
  EXPECT_EQ(test_output.int_syscall_return(), geteuid());
}

// Tests getgid() by comparing the return value of getgid() inside/outside the
// enclave.
TEST_F(SyscallsTest, GetGid) {
  SyscallsTestOutput test_output;
  ASSERT_TRUE(RunSyscallInsideEnclave("getgid", "", &test_output));
  ASSERT_TRUE(test_output.has_int_syscall_return());
  EXPECT_EQ(test_output.int_syscall_return(), getgid());
}

// Tests getegid() by comparing the return value of getegid() inside/outside the
// enclave.
TEST_F(SyscallsTest, GetEgid) {
  SyscallsTestOutput test_output;
  ASSERT_TRUE(RunSyscallInsideEnclave("getegid", "", &test_output));
  ASSERT_TRUE(test_output.has_int_syscall_return());
  EXPECT_EQ(test_output.int_syscall_return(), getegid());
}

// Tests getppid() by comparing the return value of getppid() inside/outside the
// enclave.
TEST_F(SyscallsTest, GetPpid) {
  SyscallsTestOutput test_output;
  ASSERT_TRUE(RunSyscallInsideEnclave("getppid", "", &test_output));
  ASSERT_TRUE(test_output.has_int_syscall_return());
  EXPECT_EQ(test_output.int_syscall_return(), getppid());
}

// Tests sched_getaffinity() by comparing the return value and value of the mask
// inside and outside the enclave.
// Transmits the mask across the enclave boundary using
// |bit_mask_syscall_outptr|.
TEST_F(SyscallsTest, SchedGetAffinity) {
  SyscallsTestOutput test_output;

  cpu_set_t host_mask;
  ASSERT_EQ(sched_getaffinity(getpid(), sizeof(cpu_set_t), &host_mask), 0);

  ASSERT_TRUE(RunSyscallInsideEnclave("sched_getaffinity", /*file_path=*/"",
                                      &test_output));

  ASSERT_TRUE(test_output.has_int_syscall_return());
  EXPECT_EQ(test_output.int_syscall_return(), 0);

  cpu_set_t enclave_mask;

  // Translate from |bit_mask_syscall_outptr| to host cpu_set_t.
  ExtractCpuSetFromTestOutput(test_output, &enclave_mask);

  EXPECT_TRUE(CPU_EQUAL(&host_mask, &enclave_mask));
}

// Tests that sched_getaffinity() returns -1 and sets |errno| to EINVAL if
// |cpusetsize| is less than |sizeof([enclave] cpu_set_t)|.
TEST_F(SyscallsTest, SchedGetAffinityFailure) {
  SyscallsTestOutput test_output;

  ASSERT_TRUE(RunSyscallInsideEnclave("sched_getaffinity failure",
                                      /*file_path=*/"", &test_output));

  ASSERT_TRUE(test_output.has_int_syscall_return());
  EXPECT_EQ(test_output.int_syscall_return(), -1);

  ASSERT_TRUE(test_output.has_errno_syscall_value());
  EXPECT_EQ(test_output.errno_syscall_value(),
            SyscallsTestOutput::ERRNO_EINVAL);
}

// Tests sched_getaffinity() as above, but changes the affinity mask beforehand.
// Transmits the mask across the enclave boundary using
// |bit_mask_syscall_outptr|.
TEST_F(SyscallsTest, SchedGetAffinityAfterSet) {
  SyscallsTestOutput test_output;

  cpu_set_t initial_mask;
  ASSERT_EQ(sched_getaffinity(getpid(), sizeof(cpu_set_t), &initial_mask), 0);

  int total_cpus = CPU_COUNT(&initial_mask);
  if (total_cpus < 2) {
    // If the affinity mask contains only one CPU, don't run the test.
    SUCCEED() << "Only one CPU in affinity mask. Not continuing with test.";
  } else {
    // Otherwise, unset every other active CPU.
    bool unset_cpu = false;
    for (int cpu = 0, cpus_so_far = 0; cpus_so_far < total_cpus; ++cpu) {
      if (CPU_ISSET(cpu, &initial_mask)) {
        if (unset_cpu) {
          CPU_CLR(cpu, &initial_mask);
        }
        unset_cpu = !unset_cpu;
        ++cpus_so_far;
      }
    }
    ASSERT_EQ(sched_setaffinity(getpid(), sizeof(cpu_set_t), &initial_mask), 0);

    cpu_set_t host_mask;
    ASSERT_EQ(sched_getaffinity(getpid(), sizeof(cpu_set_t), &host_mask), 0);
    ASSERT_TRUE(CPU_EQUAL(&initial_mask, &host_mask));

    ASSERT_TRUE(RunSyscallInsideEnclave("sched_getaffinity", /*file_path=*/"",
                                        &test_output));

    ASSERT_TRUE(test_output.has_int_syscall_return());
    EXPECT_EQ(test_output.int_syscall_return(), 0);

    cpu_set_t enclave_mask;

    // Translate from bit_mask_syscall_outptr to host cpu_set_t.
    ExtractCpuSetFromTestOutput(test_output, &enclave_mask);

    EXPECT_TRUE(CPU_EQUAL(&host_mask, &enclave_mask));
  }
}

// Tests the enclave-native implementations of the macros defined in
// http://man7.org/linux/man-pages/man3/CPU_SET.3.html#DESCRIPTION.
TEST_F(SyscallsTest, CpuSetMacros) {
  ASSERT_TRUE(RunSyscallInsideEnclave("CPU_SET macros", /*file_path=*/"",
                                      /*test_output=*/nullptr));
}

// Tests stat() by comparing the return value of stat() inside/outside the
// enclave.
TEST_F(SyscallsTest, Stat) {
  SyscallsTestOutput test_output;
  const std::string test_dir = absl::StrCat(FLAGS_test_tmpdir, "/stat");

  umask(S_IWGRP | S_IWOTH);
  ASSERT_EQ(mkdir(test_dir.c_str(), 0777), 0)
      << absl::StrCat("Failed to create ", test_dir);

  struct stat host_stat_buffer;
  ASSERT_EQ(stat(test_dir.c_str(), &host_stat_buffer), 0)
      << absl::StrCat("stat(", test_dir, ", ...) failed on host");

  ASSERT_TRUE(RunSyscallInsideEnclave("stat", test_dir, &test_output))
      << "Failed to execute stat() inside enclave";

  ASSERT_TRUE(test_output.has_int_syscall_return())
      << "int_syscall_return field not set";
  EXPECT_EQ(test_output.int_syscall_return(), 0)
      << absl::StrCat("stat(", test_dir, ", ...) failed in enclave");

  ASSERT_TRUE(test_output.has_stat_buffer_syscall_return())
      << "stat_buffer_syscall_return field not set";

  struct stat enclave_stat_buffer;
  ExtractStatBufferFromTestOutput(test_output, &enclave_stat_buffer);

  EXPECT_THAT(host_stat_buffer, EqualsStat(enclave_stat_buffer))
      << "Host stat() and enclave stat() not equal";
}

// Tests stat() by comparing the return value of stat() inside/outside the
// enclave, but calls it on a symlink to verify that it returns info about the
// link target.
TEST_F(SyscallsTest, StatOnSymlink) {
  SyscallsTestOutput test_output;
  const std::string test_dir = absl::StrCat(FLAGS_test_tmpdir, "/stat_on_symlink");
  const std::string test_link =
      absl::StrCat(FLAGS_test_tmpdir, "/stat_on_symlink_link");

  umask(S_IWGRP | S_IWOTH);
  ASSERT_EQ(mkdir(test_dir.c_str(), 0777), 0)
      << absl::StrCat("Failed to create ", test_dir);

  ASSERT_EQ(symlink(test_dir.c_str(), test_link.c_str()), 0)
      << absl::StrCat("Failed to create link ", test_link, " to ", test_dir);

  struct stat host_stat_buffer;
  ASSERT_EQ(stat(test_link.c_str(), &host_stat_buffer), 0)
      << absl::StrCat("stat(", test_link, ", ...) failed on host");

  ASSERT_TRUE(RunSyscallInsideEnclave("stat", test_link, &test_output))
      << "Failed to execute stat() inside enclave";

  ASSERT_TRUE(test_output.has_int_syscall_return())
      << "int_syscall_return field not set";
  EXPECT_EQ(test_output.int_syscall_return(), 0)
      << absl::StrCat("stat(", test_link, ", ...) failed in enclave");

  ASSERT_TRUE(test_output.has_stat_buffer_syscall_return())
      << "stat_buffer_syscall_return field not set";

  struct stat enclave_stat_buffer;
  ExtractStatBufferFromTestOutput(test_output, &enclave_stat_buffer);

  EXPECT_THAT(host_stat_buffer, EqualsStat(enclave_stat_buffer))
      << "Host stat() and enclave stat() not equal";
}

// Tests fstat() by comparing the return value of fstat() inside/outside the
// enclave.
TEST_F(SyscallsTest, FStat) {
  SyscallsTestOutput test_output;
  const std::string test_dir = absl::StrCat(FLAGS_test_tmpdir, "/fstat");

  umask(S_IWGRP | S_IWOTH);
  ASSERT_EQ(mkdir(test_dir.c_str(), 0777), 0)
      << absl::StrCat("Failed to create ", test_dir);

  int fd = open(test_dir.c_str(), O_RDONLY);
  ASSERT_NE(fd, -1) << absl::StrCat("Failed to open ", test_dir);

  struct stat host_stat_buffer;
  ASSERT_EQ(fstat(fd, &host_stat_buffer), 0)
      << absl::StrCat("fstat([fd of ", test_dir, "], ...) failed on host");

  ASSERT_EQ(close(fd), 0) << absl::StrCat("Failed to close ", test_dir);

  ASSERT_TRUE(RunSyscallInsideEnclave("fstat", test_dir, &test_output))
      << "Failed to execute fstat() inside enclave";

  ASSERT_TRUE(test_output.has_int_syscall_return())
      << "int_syscall_return field not set";
  EXPECT_EQ(test_output.int_syscall_return(), 0)
      << absl::StrCat("fstat([fd of ", test_dir, "], ...) failed in enclave");

  ASSERT_TRUE(test_output.has_stat_buffer_syscall_return())
      << "stat_buffer_syscall_return field not set";

  struct stat enclave_stat_buffer;
  ExtractStatBufferFromTestOutput(test_output, &enclave_stat_buffer);

  EXPECT_THAT(host_stat_buffer, EqualsStat(enclave_stat_buffer))
      << "Host fstat() and enclave fstat() not equal";
}

// Tests fstat() by comparing the return value of fstat() inside/outside the
// enclave, but calls it on a symlink to verify that it returns info about the
// link target.
TEST_F(SyscallsTest, FStatOnSymlink) {
  SyscallsTestOutput test_output;
  const std::string test_dir = absl::StrCat(FLAGS_test_tmpdir + "/fstat_on_symlink");
  const std::string test_link =
      absl::StrCat(FLAGS_test_tmpdir + "/fstat_on_symlink_link");

  umask(S_IWGRP | S_IWOTH);
  ASSERT_EQ(mkdir(test_dir.c_str(), 0777), 0)
      << absl::StrCat("Failed to create ", test_dir);

  ASSERT_EQ(symlink(test_dir.c_str(), test_link.c_str()), 0)
      << absl::StrCat("Failed to create link ", test_link, " to ", test_dir);

  int fd = open(test_link.c_str(), O_RDONLY);
  ASSERT_NE(fd, -1) << absl::StrCat("Failed to open ", test_link);

  struct stat host_stat_buffer;
  ASSERT_EQ(fstat(fd, &host_stat_buffer), 0)
      << absl::StrCat("fstat([fd of ", test_link, "], ...) failed on host");

  ASSERT_EQ(close(fd), 0) << absl::StrCat("Failed to close ", test_dir);

  ASSERT_TRUE(RunSyscallInsideEnclave("fstat", test_link, &test_output))
      << "Failed to execute fstat() inside enclave";

  ASSERT_TRUE(test_output.has_int_syscall_return())
      << "int_syscall_return field not set";
  EXPECT_EQ(test_output.int_syscall_return(), 0)
      << absl::StrCat("fstat([fd of ", test_link, "], ...) failed in enclave");

  ASSERT_TRUE(test_output.has_stat_buffer_syscall_return())
      << "stat_buffer_syscall_return field not set";

  struct stat enclave_stat_buffer;
  ExtractStatBufferFromTestOutput(test_output, &enclave_stat_buffer);

  EXPECT_THAT(host_stat_buffer, EqualsStat(enclave_stat_buffer))
      << "Host fstat() and enclave fstat() not equal";
}

// Tests lstat() by comparing the return value of lstat() inside/outside the
// enclave.
TEST_F(SyscallsTest, LStat) {
  SyscallsTestOutput test_output;
  const std::string test_dir = absl::StrCat(FLAGS_test_tmpdir, "/lstat");

  umask(S_IWGRP | S_IWOTH);
  ASSERT_EQ(mkdir(test_dir.c_str(), 0777), 0)
      << absl::StrCat("Failed to create ", test_dir);

  struct stat host_stat_buffer;
  ASSERT_EQ(lstat(test_dir.c_str(), &host_stat_buffer), 0)
      << absl::StrCat("lstat(", test_dir, ", ...) failed on host");

  ASSERT_TRUE(RunSyscallInsideEnclave("lstat", test_dir, &test_output))
      << "Failed to execute lstat() inside enclave";

  ASSERT_TRUE(test_output.has_int_syscall_return())
      << "int_syscall_return field not set";
  EXPECT_EQ(test_output.int_syscall_return(), 0)
      << absl::StrCat("lstat(", test_dir, ", ...) failed in enclave");

  ASSERT_TRUE(test_output.has_stat_buffer_syscall_return())
      << "stat_buffer_syscall_return field not set";

  struct stat enclave_stat_buffer;
  ExtractStatBufferFromTestOutput(test_output, &enclave_stat_buffer);

  EXPECT_THAT(host_stat_buffer, EqualsStat(enclave_stat_buffer))
      << "Host lstat() and enclave lstat() not equal";
}

// Tests lstat() by comparing the return value of lstat() inside/outside the
// enclave, but calls it on a symlink to verify that it returns info about the
// link itself, rather than the link target.
TEST_F(SyscallsTest, LStatOnSymlink) {
  SyscallsTestOutput test_output;
  const std::string test_dir = absl::StrCat(FLAGS_test_tmpdir, "/lstat_on_symlink");
  const std::string test_link =
      absl::StrCat(FLAGS_test_tmpdir, "/lstat_on_symlink_link");

  umask(S_IWGRP | S_IWOTH);
  ASSERT_EQ(mkdir(test_dir.c_str(), 0777), 0)
      << absl::StrCat("Failed to create ", test_dir);

  ASSERT_EQ(symlink(test_dir.c_str(), test_link.c_str()), 0)
      << absl::StrCat("Failed to create link ", test_link, " to ", test_dir);

  struct stat host_stat_buffer;
  ASSERT_EQ(lstat(test_link.c_str(), &host_stat_buffer), 0)
      << absl::StrCat("lstat(", test_link, ", ...) failed on host");

  ASSERT_TRUE(RunSyscallInsideEnclave("lstat", test_link, &test_output))
      << "Failed to execute lstat() inside enclave";

  ASSERT_TRUE(test_output.has_int_syscall_return())
      << "int_syscall_return field not set";
  EXPECT_EQ(test_output.int_syscall_return(), 0)
      << absl::StrCat("lstat(", test_link, ", ...) failed in enclave");

  ASSERT_TRUE(test_output.has_stat_buffer_syscall_return())
      << "stat_buffer_syscall_return field not set";

  struct stat enclave_stat_buffer;
  ExtractStatBufferFromTestOutput(test_output, &enclave_stat_buffer);

  EXPECT_THAT(host_stat_buffer, EqualsStat(enclave_stat_buffer))
      << "Host lstat() and enclave lstat() not equal";
}

// Tests writev() by write a scattered array to a file inside enclave, and then
// read from it to compare the content.
TEST_F(SyscallsTest, Writev) {
  EXPECT_TRUE(RunSyscallInsideEnclave("writev", FLAGS_test_tmpdir + "/writev",
                                      nullptr));
}

// Tests readv() by write a message to a file, and then read it to a scattered
// array by readv, compare the results.
TEST_F(SyscallsTest, Readv) {
  EXPECT_TRUE(
      RunSyscallInsideEnclave("readv", FLAGS_test_tmpdir + "/readv", nullptr));
}

}  // namespace
}  // namespace asylo
