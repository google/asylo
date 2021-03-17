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
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <limits.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pwd.h>
#include <sched.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <cstring>
#include <iostream>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/container/flat_hash_set.h"
#include "absl/flags/flag.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "asylo/platform/host_call/serializer_functions.h"
#include "asylo/platform/posix/syscalls_test.pb.h"
#include "asylo/platform/primitives/util/message.h"
#include "asylo/test/util/enclave_test.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status.h"

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

using ::testing::Eq;
using ::testing::Not;
using ::testing::UnorderedElementsAreArray;

const char *kCustomHostName = "CustomHostName";
const char *kCustomWorkingDirectory = "/tmp/testworkingdir";
const int kSinZeroPadSize = 8;

// Invokes a system call from inside the enclave and returns its output (if
// needed).
Status RunEnclaveSyscall(EnclaveClient *client,
                         const std::string &tested_syscall,
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
    return test_status;
  }
  if (test_output) {
    if (!enclave_output.HasExtension(syscalls_test_output)) {
      return Status(absl::StatusCode::kInternal, "No expected enclave output");
    }
    *test_output = enclave_output.GetExtension(syscalls_test_output);
  }
  return absl::OkStatus();
}

// Extracts a cpu_set_t from the bit_mask_syscall_outptr field of a
// SyscallsTestOutput protobuf.
void ExtractCpuSetFromTestOutput(const SyscallsTestOutput &test_output,
                                 cpu_set_t *mask) {
  CPU_ZERO(mask);
  int cpu = 0;
  for (const auto &word : test_output.bit_mask_syscall_outptr()) {
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

// Extracts a struct utsname from the utsname_syscall_return field of a
// SyscallsTestOutput protobuf.
bool ExtractUtsNameFromTestOutput(const SyscallsTestOutput &test_output,
                                  struct utsname *utsname_buf) {
  if (!test_output.has_utsname_syscall_return()) {
    return false;
  }

  const SyscallsTestOutput::UtsName &proto_utsname =
      test_output.utsname_syscall_return();

  if (proto_utsname.has_sysname()) {
    proto_utsname.sysname().copy(utsname_buf->sysname,
                                 sizeof(utsname_buf->sysname));
  } else {
    return false;
  }

  if (proto_utsname.has_nodename()) {
    proto_utsname.nodename().copy(utsname_buf->nodename,
                                  sizeof(utsname_buf->nodename));
  } else {
    return false;
  }

  if (proto_utsname.has_release()) {
    proto_utsname.release().copy(utsname_buf->release,
                                 sizeof(utsname_buf->release));
  } else {
    return false;
  }

  if (proto_utsname.has_version()) {
    proto_utsname.version().copy(utsname_buf->version,
                                 sizeof(utsname_buf->version));
  } else {
    return false;
  }

  if (proto_utsname.has_machine()) {
    proto_utsname.machine().copy(utsname_buf->machine,
                                 sizeof(utsname_buf->machine));
  } else {
    return false;
  }

  if (proto_utsname.has_domainname()) {
    proto_utsname.domainname().copy(utsname_buf->domainname,
                                    sizeof(utsname_buf->domainname));
  }  // No else { return false; } because |domainname| isn't required.

  return true;
}

// Compares two struct utsname objects, returning |true| if they are equal, and
// |false| otherwise.
MATCHER_P(EqualsUtsName, rhs_utsname_buf, "") {
  return (strncmp(arg.sysname, rhs_utsname_buf.sysname, sizeof(arg.sysname)) ==
          0) &&
         (strncmp(arg.nodename, rhs_utsname_buf.nodename,
                  sizeof(arg.nodename)) == 0) &&
         (strncmp(arg.release, rhs_utsname_buf.release, sizeof(arg.release)) ==
          0) &&
         (strncmp(arg.version, rhs_utsname_buf.version, sizeof(arg.version)) ==
          0) &&
         (strncmp(arg.machine, rhs_utsname_buf.machine, sizeof(arg.machine)) ==
          0) &&
         (strncmp(arg.domainname, rhs_utsname_buf.domainname,
                  sizeof(arg.domainname)) == 0);
}

// Ensure that two sockaddrs are equal. This is used for verifying the output
// of getifaddrs, which returns a list of structs with sockaddr members.
bool SockaddrsEqual(const struct sockaddr *sa1, const struct sockaddr *sa2) {
  if (!sa1 || !sa2) return sa1 == sa2;
  if (sa1->sa_family != sa2->sa_family) return false;
  if (sa1->sa_family == AF_INET) {
    const struct sockaddr_in *addr1 =
        reinterpret_cast<const struct sockaddr_in *>(sa1);
    const struct sockaddr_in *addr2 =
        reinterpret_cast<const struct sockaddr_in *>(sa2);
    return (addr1->sin_family == addr2->sin_family) &&
           (addr1->sin_port == addr2->sin_port) &&
           (addr1->sin_addr.s_addr == addr2->sin_addr.s_addr) &&
           (memcmp(&(addr1->sin_zero), &(addr2->sin_zero), kSinZeroPadSize) ==
            0);
  } else if (sa1->sa_family == AF_INET6) {
    const struct sockaddr_in6 *addr1 =
        reinterpret_cast<const struct sockaddr_in6 *>(sa1);
    const struct sockaddr_in6 *addr2 =
        reinterpret_cast<const struct sockaddr_in6 *>(sa2);
    return (addr1->sin6_family == addr2->sin6_family) &&
           (addr1->sin6_port == addr2->sin6_port) &&
           (addr1->sin6_flowinfo == addr2->sin6_flowinfo) &&
           (memcmp(&(addr1->sin6_addr.s6_addr), &(addr2->sin6_addr.s6_addr),
                   sizeof(struct in6_addr)) == 0) &&
           (addr1->sin6_scope_id == addr2->sin6_scope_id);
  }
  return false;
}

// Ensure that the bits for getifaddrs we support match between the two flags
bool IfAddrsFlagsEqual(int flags1, int flags2) {
  int supported_flags = IFF_UP | IFF_BROADCAST | IFF_DEBUG | IFF_LOOPBACK |
                        IFF_POINTOPOINT | IFF_NOTRAILERS | IFF_RUNNING |
                        IFF_NOARP | IFF_PROMISC | IFF_ALLMULTI;
  return (flags1 & supported_flags) == (flags2 & supported_flags);
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

// Compares a struct passwd with the result from the passwd_syscall_return field
// of a SyscallsTestOutput protobuf. Returns true if all fields are the same.
bool ComparePassWd(const SyscallsTestOutput &test_output,
                   struct passwd *password) {
  if (!test_output.has_passwd_syscall_return() || !password) {
    return false;
  }

  const SyscallsTestOutput::PassWd &proto_passwd =
      test_output.passwd_syscall_return();

  if (!proto_passwd.has_pw_name() ||
      proto_passwd.pw_name() != password->pw_name ||
      !proto_passwd.has_pw_passwd() ||
      proto_passwd.pw_passwd() != password->pw_passwd ||
      !proto_passwd.has_pw_uid() || proto_passwd.pw_uid() != password->pw_uid ||
      !proto_passwd.has_pw_gid() || proto_passwd.pw_gid() != password->pw_gid ||
      !proto_passwd.has_pw_gecos() ||
      proto_passwd.pw_gecos() != password->pw_gecos ||
      !proto_passwd.has_pw_dir() || proto_passwd.pw_dir() != password->pw_dir ||
      !proto_passwd.has_pw_shell() ||
      proto_passwd.pw_shell() != password->pw_shell) {
    return false;
  }

  return true;
}

// class that runs syscall tests with default enclave config.
class SyscallsTest : public EnclaveTest {
 protected:
  Status RunSyscallInsideEnclave(const std::string &tested_syscall,
                                 const std::string &file_path,
                                 SyscallsTestOutput *test_output) {
    return RunEnclaveSyscall(client_, tested_syscall, file_path, false, 0,
                             test_output);
  }

  Status RunSyscallInsideEnclave(const std::string &tested_syscall,
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

  Status RunSyscallInsideEnclave(const std::string &tested_syscall,
                                 const std::string &file_path,
                                 SyscallsTestOutput *test_output) {
    return RunEnclaveSyscall(client_, tested_syscall, file_path, false, 0,
                             test_output);
  }

  Status RunSyscallInsideEnclave(const std::string &tested_syscall,
                                 bool provide_buffer, int32_t buffer_size,
                                 SyscallsTestOutput *test_output) {
    return RunEnclaveSyscall(client_, tested_syscall, "", provide_buffer,
                             buffer_size, test_output);
  }
};

//////////////////////////////////////
//            fcntl.h               //
//////////////////////////////////////

// Tests fcntl() with F_GETFL and F_SETFL. Sets the file flags with F_SETFL,
// then uses F_GETFL to check whether it's set correctly.
TEST_F(SyscallsTest, Fcntl) {
  EXPECT_THAT(
      RunSyscallInsideEnclave(
          "fcntl", absl::GetFlag(FLAGS_test_tmpdir) + "/fcntl", nullptr),
      IsOk());
}

//////////////////////////////////////
//            ifaddr.h              //
//////////////////////////////////////

MATCHER_P(MatchIfAddrs, that, "") {
  return SockaddrsEqual(arg->ifa_addr, that->ifa_addr) &&
         SockaddrsEqual(arg->ifa_netmask, that->ifa_netmask) &&
         SockaddrsEqual(arg->ifa_ifu.ifu_dstaddr, that->ifa_ifu.ifu_dstaddr) &&
         (strcmp(arg->ifa_name, that->ifa_name) == 0) &&
         IfAddrsFlagsEqual(arg->ifa_flags, that->ifa_flags) && !arg->ifa_data &&
         !that->ifa_data;
}

// Tests getifaddrs by calling it from inside the enclave and ensuring that
// the result is equivalent to what is returned by a call to getifaddrs made
// outside the enclave. There is a minor caveat: asylo doesn't support
// sockaddr types that arent AF_INET (IPv4) or AF_INET6 (IPv6) -- as a result,
// ifaddrs structs that have sockaddrs of this type are filtered out during
// serialization. As a result, we skip over any such entries while comparing
// the linked lists.
TEST_F(SyscallsTest, GetIfAddrs) {
  SyscallsTestOutput test_output;
  ASSERT_THAT(RunSyscallInsideEnclave("getifaddrs", "", &test_output), IsOk());
  ASSERT_EQ(test_output.int_syscall_return(), 0);
  ASSERT_TRUE(test_output.has_serialized_proto_return());
  struct ifaddrs *host_front = nullptr;
  int ret = getifaddrs(&host_front);
  ASSERT_EQ(ret, 0);
  struct ifaddrs *enclave_front = nullptr;
  std::string serialized_ifaddrs = test_output.serialized_proto_return();

  primitives::MessageReader reader;
  reader.Deserialize(serialized_ifaddrs.data(), serialized_ifaddrs.length());
  ASSERT_TRUE(host_call::DeserializeIfAddrs(&reader, &enclave_front, nullptr));

  // Since we cannot rely on any sort of ordering in the linked lists, we will
  // only verify that every IPv4/IPv6 entry in the enclave list also exists in
  // the host list. Furthermore, we shall verify that all IPv4/IPv6 entries in
  // the host list are indeed found in the enclave list. We shall also verify
  // that there are no duplicates in the enclave list.
  absl::flat_hash_set<struct ifaddrs *> found_in_enclave;
  std::vector<::testing::Matcher<struct ifaddrs *>> expected;
  for (struct ifaddrs *enclave_list_curr = enclave_front;
       enclave_list_curr != nullptr;
       enclave_list_curr = enclave_list_curr->ifa_next) {
    expected.push_back(MatchIfAddrs(enclave_list_curr));
  }
  std::vector<struct ifaddrs *> supported_host;
  // Make a second pass through the host list to ensure that all IPv4/IPv6
  // entries encountered are in our set.
  for (struct ifaddrs *host_list_curr = host_front; host_list_curr != nullptr;
       host_list_curr = host_list_curr->ifa_next) {
    if (host_call::IsIfAddrSupported(host_list_curr)) {
      supported_host.push_back(host_list_curr);
    }
  }
  EXPECT_THAT(supported_host.size(), Eq(expected.size())) << serialized_ifaddrs;
  EXPECT_THAT(supported_host, UnorderedElementsAreArray(expected));
  asylo::host_call::FreeDeserializedIfAddrs(enclave_front);
  freeifaddrs(host_front);
}

//////////////////////////////////////
//            net/if.h              //
//////////////////////////////////////

TEST_F(SyscallsTest, IfIndexToName) {
  EXPECT_THAT(
      RunSyscallInsideEnclave("if_indextoname", /*file_path=*/"", nullptr),
      IsOk());
}

TEST_F(SyscallsTest, IfNameToIndex) {
  EXPECT_THAT(
      RunSyscallInsideEnclave("if_nametoindex", /*file_path=*/"", nullptr),
      IsOk());
}

//////////////////////////////////////
//              pwd.h               //
//////////////////////////////////////

// Tests getpwuid() by comparing the value of the getpwuid() inside and outside
// the enclave. Transmits the passwd structure across the enclave boundary using
// |passwd_syscall_return|.
TEST_F(SyscallsTest, GetPWUid) {
  SyscallsTestOutput test_output;

  ASSERT_THAT(
      RunSyscallInsideEnclave("getpwuid", /*file_path=*/"", &test_output),
      IsOk());

  // Compare the passwd result from the enclave with the one on the host.
  EXPECT_TRUE(ComparePassWd(test_output, getpwuid(getuid())));
}

//////////////////////////////////////
//            sched.h               //
//////////////////////////////////////

// Tests the enclave-native implementations of the macros defined in
// http://man7.org/linux/man-pages/man3/CPU_SET.3.html#DESCRIPTION.
TEST_F(SyscallsTest, CpuSetMacros) {
  ASSERT_THAT(RunSyscallInsideEnclave("CPU_SET macros", /*file_path=*/"",
                                      /*test_output=*/nullptr),
              IsOk());
}

// Tests sched_getaffinity() by comparing the return value and value of the mask
// inside and outside the enclave.
// Transmits the mask across the enclave boundary using
// |bit_mask_syscall_outptr|.
TEST_F(SyscallsTest, SchedGetAffinity) {
  SyscallsTestOutput test_output;

  cpu_set_t host_mask;
  ASSERT_EQ(sched_getaffinity(getpid(), sizeof(cpu_set_t), &host_mask), 0);

  ASSERT_THAT(RunSyscallInsideEnclave("sched_getaffinity", /*file_path=*/"",
                                      &test_output),
              IsOk());

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

  ASSERT_THAT(RunSyscallInsideEnclave("sched_getaffinity failure",
                                      /*file_path=*/"", &test_output),
              IsOk());

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

    ASSERT_THAT(RunSyscallInsideEnclave("sched_getaffinity", /*file_path=*/"",
                                        &test_output),
                IsOk());

    ASSERT_TRUE(test_output.has_int_syscall_return());
    EXPECT_EQ(test_output.int_syscall_return(), 0);

    cpu_set_t enclave_mask;

    // Translate from bit_mask_syscall_outptr to host cpu_set_t.
    ExtractCpuSetFromTestOutput(test_output, &enclave_mask);

    EXPECT_TRUE(CPU_EQUAL(&host_mask, &enclave_mask));
  }
}

//////////////////////////////////////
//            stdio.h               //
//////////////////////////////////////

// Tests rename(). Calls rename() inside enclave to change the name of a file,
// and verifies the existence of the file with the new name outside the enclave.
TEST_F(SyscallsTest, Rename) {
  EXPECT_THAT(RunSyscallInsideEnclave(
                  "rename", absl::GetFlag(FLAGS_test_tmpdir), nullptr),
              IsOk());
  int fd = open((absl::GetFlag(FLAGS_test_tmpdir) + "/rename").c_str(), O_RDWR);
  EXPECT_GE(fd, 0);
  close(fd);
}

//////////////////////////////////////
//           sys/mman.h             //
//////////////////////////////////////

// Tests that mmap(MAP_ANONYMOUS) will return an initialized, block-aligned
// region of memory.
TEST_F(SyscallsTest, Mmap) {
  EXPECT_THAT(RunSyscallInsideEnclave("mmap", "", nullptr), IsOk());
}

//////////////////////////////////////
//         sys/resource.h           //
//////////////////////////////////////

// Tests getrlimit() and setrlimit() with RLIMIT_NOFILE by setting the limit and
// getting it to compare the result.
TEST_F(SyscallsTest, RlimitNoFile) {
  EXPECT_THAT(RunSyscallInsideEnclave(
                  "rlimit nofile", absl::GetFlag(FLAGS_test_tmpdir) + "/rlimit",
                  nullptr),
              IsOk());
}

// Tests setrlimit() with RLIMIT_NOFILE by setting the limit to a low number,
// and checking whether it fails to open more files than that limit to confirm
// that the limit is used correctly.
TEST_F(SyscallsTest, RlimitLowNoFile) {
  EXPECT_THAT(RunSyscallInsideEnclave(
                  "rlimit low nofile",
                  absl::GetFlag(FLAGS_test_tmpdir) + "/rlimit", nullptr),
              IsOk());
}

// Tests setrlimit() with RLIMIT_NOFILE by setting the limit to an invalid
// value, and checking that the call fails and does not change the limit.
TEST_F(SyscallsTest, RlimitInvalidNoFile) {
  EXPECT_THAT(RunSyscallInsideEnclave(
                  "rlimit invalid nofile",
                  absl::GetFlag(FLAGS_test_tmpdir) + "/rlimit", nullptr),
              IsOk());
}

//////////////////////////////////////
//          sys/socket.h            //
//////////////////////////////////////

// Tests various failure modes of getpeername(). The enclave code sets up each
// test and tests against the expected retval.
TEST_F(SyscallsTest, PeernameFailure_EBADF) {
  EXPECT_THAT(RunSyscallInsideEnclave("getpeername_ebadf", "", nullptr),
              IsOk());
}

TEST_F(SyscallsTest, PeernameFailure_EFAULT) {
  EXPECT_THAT(RunSyscallInsideEnclave("getpeername_efault", "", nullptr),
              IsOk());
}

TEST_F(SyscallsTest, PeernameFailure_EINVAL) {
  EXPECT_THAT(RunSyscallInsideEnclave("getpeername_einval", "", nullptr),
              IsOk());
}

TEST_F(SyscallsTest, PeernameFailure_ENOTCONN) {
  EXPECT_THAT(RunSyscallInsideEnclave("getpeername_enotconn", "", nullptr),
              IsOk());
}

TEST_F(SyscallsTest, PeernameFailure_ENOTSOCK) {
  EXPECT_THAT(RunSyscallInsideEnclave("getpeername_enotsock", "", nullptr),
              IsOk());
}

// Test getsockname() success scenario
TEST_F(SyscallsTest, Sockname_SUCCESS) {
  EXPECT_THAT(RunSyscallInsideEnclave("getsockname_success", "", nullptr),
              IsOk());
}

// Tests various failure modes of getsockname(). The enclave code sets up each
// test and tests against the expected retval.
TEST_F(SyscallsTest, SocknameFailure_EBADF) {
  EXPECT_THAT(RunSyscallInsideEnclave("getsockname_ebadf", "", nullptr),
              IsOk());
}

TEST_F(SyscallsTest, SocknameFailure_EFAULT) {
  EXPECT_THAT(RunSyscallInsideEnclave("getsockname_efault", "", nullptr),
              IsOk());
}

TEST_F(SyscallsTest, SocknameFailure_EINVAL) {
  EXPECT_THAT(RunSyscallInsideEnclave("getsockname_einval", "", nullptr),
              IsOk());
}

TEST_F(SyscallsTest, SocknameFailure_ENOTSOCK) {
  EXPECT_THAT(RunSyscallInsideEnclave("getsockname_enotsock", "", nullptr),
              IsOk());
}

//////////////////////////////////////
//           sys/stat.h             //
//////////////////////////////////////

// Tests chmod() by changing the mode of a file inside an enclave, and verifies
// the mode is changed correctly.
TEST_F(SyscallsTest, ChMod) {
  const std::string test_file =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/chmod");
  ASSERT_NE(open(test_file.c_str(), O_CREAT | O_RDWR, 0777), -1);
  ASSERT_THAT(RunSyscallInsideEnclave("chmod", test_file, nullptr), IsOk());
  struct stat stat_buffer;
  ASSERT_EQ(stat(test_file.c_str(), &stat_buffer), 0);
  EXPECT_EQ(stat_buffer.st_mode & 0777, 0644);
}

// Tests fchmod() by changing the mode of a file inside an enclave, and verifies
// the mode is changed correctly.
TEST_F(SyscallsTest, FChMod) {
  const std::string test_file =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/chmod");
  ASSERT_THAT(RunSyscallInsideEnclave("fchmod", test_file, nullptr), IsOk());
  struct stat stat_buffer;
  ASSERT_EQ(stat(test_file.c_str(), &stat_buffer), 0);
  EXPECT_EQ(stat_buffer.st_mode & 0777, 0644);
}

// Tests fstat() by comparing the return value of fstat() inside/outside the
// enclave.
TEST_F(SyscallsTest, FStat) {
  SyscallsTestOutput test_output;
  const std::string test_dir =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/fstat");

  umask(S_IWGRP | S_IWOTH);
  ASSERT_EQ(mkdir(test_dir.c_str(), 0777), 0)
      << absl::StrCat("Failed to create ", test_dir);

  int fd = open(test_dir.c_str(), O_RDONLY);
  ASSERT_NE(fd, -1) << absl::StrCat("Failed to open ", test_dir);

  struct stat host_stat_buffer;
  ASSERT_EQ(fstat(fd, &host_stat_buffer), 0)
      << absl::StrCat("fstat([fd of ", test_dir, "], ...) failed on host");

  ASSERT_EQ(close(fd), 0) << absl::StrCat("Failed to close ", test_dir);

  ASSERT_THAT(RunSyscallInsideEnclave("fstat", test_dir, &test_output), IsOk())
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
  const std::string test_dir =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir) + "/fstat_on_symlink");
  const std::string test_link =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir) + "/fstat_on_symlink_link");

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

  ASSERT_THAT(RunSyscallInsideEnclave("fstat", test_link, &test_output), IsOk())
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
  const std::string test_dir =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/lstat");

  umask(S_IWGRP | S_IWOTH);
  ASSERT_EQ(mkdir(test_dir.c_str(), 0777), 0)
      << absl::StrCat("Failed to create ", test_dir);

  struct stat host_stat_buffer;
  ASSERT_EQ(lstat(test_dir.c_str(), &host_stat_buffer), 0)
      << absl::StrCat("lstat(", test_dir, ", ...) failed on host");

  ASSERT_THAT(RunSyscallInsideEnclave("lstat", test_dir, &test_output), IsOk())
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
  const std::string test_dir =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/lstat_on_symlink");
  const std::string test_link =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/lstat_on_symlink_link");

  umask(S_IWGRP | S_IWOTH);
  ASSERT_EQ(mkdir(test_dir.c_str(), 0777), 0)
      << absl::StrCat("Failed to create ", test_dir);

  ASSERT_EQ(symlink(test_dir.c_str(), test_link.c_str()), 0)
      << absl::StrCat("Failed to create link ", test_link, " to ", test_dir);

  struct stat host_stat_buffer;
  ASSERT_EQ(lstat(test_link.c_str(), &host_stat_buffer), 0)
      << absl::StrCat("lstat(", test_link, ", ...) failed on host");

  ASSERT_THAT(RunSyscallInsideEnclave("lstat", test_link, &test_output), IsOk())
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

// Tests mkdir(). Calls mkdir() inside enclave to create a directory. And checks
// the existence of the directory outside enclave.
TEST_F(SyscallsTest, Mkdir) {
  EXPECT_THAT(
      RunSyscallInsideEnclave(
          "mkdir", absl::GetFlag(FLAGS_test_tmpdir) + "/mkdir", nullptr),
      IsOk());
  DIR *directory =
      opendir((absl::GetFlag(FLAGS_test_tmpdir) + "/mkdir").c_str());
  EXPECT_TRUE(directory);
  closedir(directory);
}

// Tests stat() by comparing the return value of stat() inside/outside the
// enclave.
TEST_F(SyscallsTest, Stat) {
  SyscallsTestOutput test_output;
  const std::string test_dir =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/stat");

  umask(S_IWGRP | S_IWOTH);
  ASSERT_EQ(mkdir(test_dir.c_str(), 0777), 0)
      << absl::StrCat("Failed to create ", test_dir);

  struct stat host_stat_buffer;
  ASSERT_EQ(stat(test_dir.c_str(), &host_stat_buffer), 0)
      << absl::StrCat("stat(", test_dir, ", ...) failed on host");

  ASSERT_THAT(RunSyscallInsideEnclave("stat", test_dir, &test_output), IsOk())
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
  const std::string test_dir =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/stat_on_symlink");
  const std::string test_link =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/stat_on_symlink_link");

  umask(S_IWGRP | S_IWOTH);
  ASSERT_EQ(mkdir(test_dir.c_str(), 0777), 0)
      << absl::StrCat("Failed to create ", test_dir);

  ASSERT_EQ(symlink(test_dir.c_str(), test_link.c_str()), 0)
      << absl::StrCat("Failed to create link ", test_link, " to ", test_dir);

  struct stat host_stat_buffer;
  ASSERT_EQ(stat(test_link.c_str(), &host_stat_buffer), 0)
      << absl::StrCat("stat(", test_link, ", ...) failed on host");

  ASSERT_THAT(RunSyscallInsideEnclave("stat", test_link, &test_output), IsOk())
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

// Tests umask() by masking file modes and call open/mkdir to create new path
// with masked file modes, and check whether the mode exists in the new path.
TEST_F(SyscallsTest, Umask) {
  ASSERT_THAT(
      RunSyscallInsideEnclave(
          "umask", absl::GetFlag(FLAGS_test_tmpdir) + "/umask", nullptr),
      IsOk());
}

//////////////////////////////////////
//            sys/time.h            //
//////////////////////////////////////

TEST_F(SyscallsTest, Itimer) {
  EXPECT_THAT(RunSyscallInsideEnclave("itimer", "", nullptr), IsOk());
}

//////////////////////////////////////
//            sys/uio.h             //
//////////////////////////////////////

// Tests readv() by write a message to a file, and then read it to a scattered
// array by readv, compare the results.
TEST_F(SyscallsTest, Readv) {
  EXPECT_THAT(
      RunSyscallInsideEnclave(
          "readv", absl::GetFlag(FLAGS_test_tmpdir) + "/readv", nullptr),
      IsOk());
}

// Tests writev() by write a scattered array to a file inside enclave, and then
// read from it to compare the content.
TEST_F(SyscallsTest, Writev) {
  EXPECT_THAT(
      RunSyscallInsideEnclave(
          "writev", absl::GetFlag(FLAGS_test_tmpdir) + "/writev", nullptr),
      IsOk());
}

//////////////////////////////////////
//          sys/utsname.h           //
//////////////////////////////////////

// Tests uname() by comparing the return value and value of the utsname buffer
// inside and outside the enclave. Transmits the utsname structure across the
// enclave boundary using |utsname_syscall_return|.
TEST_F(SyscallsTest, Uname) {
  SyscallsTestOutput test_output;

  struct utsname host_utsname_buf;
  ASSERT_EQ(uname(&host_utsname_buf), 0) << "Could not fetch host utsname";

  ASSERT_THAT(RunSyscallInsideEnclave("uname", /*file_path=*/"", &test_output),
              IsOk())
      << "Failed to execute uname() inside the enclave";

  ASSERT_TRUE(test_output.has_int_syscall_return())
      << "int_syscall_return field not set";
  EXPECT_EQ(test_output.int_syscall_return(), 0)
      << "uname() failed inside the enclave: "
      << (test_output.has_errno_syscall_value() ? strerror(errno)
                                                : "(no errno)");

  // Translate from |utsname_syscall_return| to host struct utsname.
  struct utsname enclave_utsname_buf;
  EXPECT_TRUE(ExtractUtsNameFromTestOutput(test_output, &enclave_utsname_buf))
      << "Failed to convert UtsName message to struct utsname";

  EXPECT_THAT(host_utsname_buf, EqualsUtsName(enclave_utsname_buf));
}


//////////////////////////////////////
//            unistd.h              //
//////////////////////////////////////

// Tests dup() and dup2(). Calls dup() and dup2() on a file descriptor, and
// checks whether the new file descriptor behaves the same as the original one.
TEST_F(SyscallsTest, Dup) {
  EXPECT_THAT(RunSyscallInsideEnclave(
                  "dup", absl::GetFlag(FLAGS_test_tmpdir) + "/dup", nullptr),
              IsOk());
}

// Tests getcwd() with default settings. Calls getcwd() inside enclave and
// compares the result with the value outside enclave.
TEST_F(SyscallsTest, GetCwd) {
  SyscallsTestOutput test_output;
  ASSERT_THAT(RunSyscallInsideEnclave("getcwd", true, PATH_MAX, &test_output),
              IsOk());
  ASSERT_TRUE(test_output.has_string_syscall_return());
  char buf[PATH_MAX];
  ASSERT_NE(getcwd(buf, sizeof(buf)), nullptr);
  EXPECT_EQ(test_output.string_syscall_return(), buf);
}

// Tests getcwd() with default settings. Calls getcwd() inside enclave with 0
// buffer size and verifies the call fails.
TEST_F(SyscallsTest, GetCwdNoSize) {
  ASSERT_THAT(RunSyscallInsideEnclave("getcwd", true, 0, nullptr), Not(IsOk()));
}

// Tests getcwd() with default settings. Calls getcwd() inside enclave with no
// buffer and compares the result with the value outside the enclave.
TEST_F(SyscallsTest, GetCwdNoBuffer) {
  SyscallsTestOutput test_output;
  ASSERT_THAT(RunSyscallInsideEnclave("getcwd", false, PATH_MAX, &test_output),
              IsOk());
  ASSERT_TRUE(test_output.has_string_syscall_return());
  char buf[PATH_MAX];
  ASSERT_NE(getcwd(buf, sizeof(buf)), nullptr);
  EXPECT_EQ(test_output.string_syscall_return(), buf);
}

// Tests getcwd() with default settings. Calls getcwd() inside enclave with no
// buffer or size and compares the result with the value outside the enclave.
TEST_F(SyscallsTest, GetCwdNoBufferNoSize) {
  SyscallsTestOutput test_output;
  ASSERT_THAT(RunSyscallInsideEnclave("getcwd", false, 0, &test_output),
              IsOk());
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
  ASSERT_THAT(RunSyscallInsideEnclave("getcwd", "", &test_output), IsOk());
  ASSERT_TRUE(test_output.has_string_syscall_return());
  EXPECT_EQ(test_output.string_syscall_return(), kCustomWorkingDirectory);
}

// Tests getcwd() with custom settings. Sets working directory config before
// loading enclave, calls getcwd() inside enclave with insufficient buffer size,
// and verifies the call fails.
TEST_F(CustomConfigSyscallsTest, GetCwdInsufficientSize) {
  ASSERT_THAT(RunSyscallInsideEnclave("getcwd", true,
                                      strlen(kCustomWorkingDirectory), nullptr),
              Not(IsOk()));
}

// Tests getcwd() with custom settings. Sets working directory config before
// loading enclave, calls getcwd() inside enclave with no buffer and
// insufficient buffer size, and verifies the call fails.
TEST_F(CustomConfigSyscallsTest, GetCwdNoBufferInsufficientSize) {
  ASSERT_THAT(RunSyscallInsideEnclave("getcwd", false,
                                      strlen(kCustomWorkingDirectory), nullptr),
              Not(IsOk()));
}

// Tests getegid() by comparing the return value of getegid() inside/outside the
// enclave.
TEST_F(SyscallsTest, GetEgid) {
  SyscallsTestOutput test_output;
  ASSERT_THAT(RunSyscallInsideEnclave("getegid", "", &test_output), IsOk());
  ASSERT_TRUE(test_output.has_int_syscall_return());
  EXPECT_EQ(test_output.int_syscall_return(), getegid());
}

// Tests geteuid() by comparing the return value of geteuid() inside/outside the
// enclave.
TEST_F(SyscallsTest, GetEuid) {
  SyscallsTestOutput test_output;
  ASSERT_THAT(RunSyscallInsideEnclave("geteuid", "", &test_output), IsOk());
  ASSERT_TRUE(test_output.has_int_syscall_return());
  EXPECT_EQ(test_output.int_syscall_return(), geteuid());
}

// Tests gethostname() with default settings. Calls gethostname() inside
// enclave, and compares the result with the value outside enclave.
TEST_F(SyscallsTest, GetHostName) {
  SyscallsTestOutput test_output;
  ASSERT_THAT(RunSyscallInsideEnclave("gethostname", "", &test_output), IsOk());
  ASSERT_TRUE(test_output.has_string_syscall_return());
#ifdef HOST_NAME_MAX
  char buf[HOST_NAME_MAX + 1];
#else
  char buf[256];
#endif
  ASSERT_EQ(gethostname(buf, sizeof(buf)), 0);
  EXPECT_EQ(test_output.string_syscall_return(), buf);
}

// Tests gethostname() with custom settings. Sets host name config before
// loading enclave, Calls gethostname() inside enclave, and compares the result
// with the value set.
TEST_F(CustomConfigSyscallsTest, GetHostName) {
  SyscallsTestOutput test_output;
  ASSERT_THAT(RunSyscallInsideEnclave("gethostname", "", &test_output), IsOk());
  ASSERT_TRUE(test_output.has_string_syscall_return());
  EXPECT_EQ(test_output.string_syscall_return(), kCustomHostName);
}

// Tests getgid() by comparing the return value of getgid() inside/outside the
// enclave.
TEST_F(SyscallsTest, GetGid) {
  SyscallsTestOutput test_output;
  ASSERT_THAT(RunSyscallInsideEnclave("getgid", "", &test_output), IsOk());
  ASSERT_TRUE(test_output.has_int_syscall_return());
  EXPECT_EQ(test_output.int_syscall_return(), getgid());
}

// Tests getpid() by comparing the return value of getpid() inside/outside the
// enclave.
TEST_F(SyscallsTest, GetPid) {
  SyscallsTestOutput test_output;
  ASSERT_THAT(RunSyscallInsideEnclave("getpid", "", &test_output), IsOk());
  ASSERT_TRUE(test_output.has_int_syscall_return());
  EXPECT_EQ(test_output.int_syscall_return(), getpid());
}

// Tests getppid() by comparing the return value of getppid() inside/outside the
// enclave.
TEST_F(SyscallsTest, GetPpid) {
  SyscallsTestOutput test_output;
  ASSERT_THAT(RunSyscallInsideEnclave("getppid", "", &test_output), IsOk());
  ASSERT_TRUE(test_output.has_int_syscall_return());
  EXPECT_EQ(test_output.int_syscall_return(), getppid());
}

// Tests getuid() by comparing the return value of getuid() inside/outside the
// enclave.
TEST_F(SyscallsTest, GetUid) {
  SyscallsTestOutput test_output;
  ASSERT_THAT(RunSyscallInsideEnclave("getuid", "", &test_output), IsOk());
  ASSERT_TRUE(test_output.has_int_syscall_return());
  EXPECT_EQ(test_output.int_syscall_return(), getuid());
}

// Tests link(). Calls link() inside enclave, writes to the old path, and reads
// from the new path to check whether they are the same.
TEST_F(SyscallsTest, Link) {
  EXPECT_THAT(RunSyscallInsideEnclave(
                  "link", absl::GetFlag(FLAGS_test_tmpdir) + "/link", nullptr),
              IsOk());
}

// Tests pread() by write a message to a file, and then read it with an offset
// by pread, compare the results.
TEST_F(SyscallsTest, PRead) {
  EXPECT_THAT(
      RunSyscallInsideEnclave(
          "pread", absl::GetFlag(FLAGS_test_tmpdir) + "/pread", nullptr),
      IsOk());
}

// Tests rmdir(). Calls mkdir() to create a directory, then calls rmdir() inside
// the enclave to remove it. Verifies the directory is deleted outside the
// enclave.
TEST_F(SyscallsTest, Rmdir) {
  const std::string test_directory =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/rmdir");
  EXPECT_EQ(mkdir(test_directory.c_str(), 0644), 0);
  EXPECT_THAT(RunSyscallInsideEnclave("rmdir", test_directory, nullptr),
              IsOk());
  DIR *directory = opendir(test_directory.c_str());
  EXPECT_EQ(directory, nullptr);
}

// Tests sysconf(). This test checks whether sysconf(_SC_NPROCESSORS_CONF)
// inside enclave gives the same result as outside the enclave.
TEST_F(SyscallsTest, SysconfScNprocessorsConf) {
  SyscallsTestOutput test_output;
  ASSERT_THAT(RunSyscallInsideEnclave("sysconf(_SC_NPROCESSORS_CONF)", "",
                                      &test_output),
              IsOk());
  ASSERT_TRUE(test_output.has_int_syscall_return());
  EXPECT_EQ(test_output.int_syscall_return(), sysconf(_SC_NPROCESSORS_CONF));
}

// Tests sysconf(). This test checks whether sysconf(_SC_NPROCESSORS_ONLN)
// inside enclave gives the same result as outside the enclave.
TEST_F(SyscallsTest, SysconfScNprocessorsOnln) {
  SyscallsTestOutput test_output;
  ASSERT_THAT(RunSyscallInsideEnclave("sysconf(_SC_NPROCESSORS_ONLN)", "",
                                      &test_output),
              IsOk());
  ASSERT_TRUE(test_output.has_int_syscall_return());
  EXPECT_EQ(test_output.int_syscall_return(), sysconf(_SC_NPROCESSORS_ONLN));
}

// Tests sysconf(). sysconf(_SC_PAGESIZE) should return 4096, regardless of
// the host configuration.
TEST_F(SyscallsTest, SysconfScPagesize) {
  SyscallsTestOutput test_output;
  ASSERT_THAT(
      RunSyscallInsideEnclave("sysconf(_SC_PAGESIZE)", "", &test_output),
      IsOk());
  ASSERT_TRUE(test_output.has_int_syscall_return());
  EXPECT_EQ(test_output.int_syscall_return(), 4096);
}

// Tests truncate and ftruncate by truncating the file inside an enclave, and
// read from it to ensure it's truncated to the correct size.
TEST_F(SyscallsTest, Truncate) {
  EXPECT_THAT(
      RunSyscallInsideEnclave(
          "truncate", absl::GetFlag(FLAGS_test_tmpdir) + "/truncate", nullptr),
      IsOk());
}

// Tests unlink(). Opens a file, closes it and unlinks it. Then checks whether
// it's still available.
TEST_F(SyscallsTest, Unlink) {
  EXPECT_THAT(
      RunSyscallInsideEnclave(
          "unlink", absl::GetFlag(FLAGS_test_tmpdir) + "/unlink", nullptr),
      IsOk());
}

//////////////////////////////////////
//             utime.h              //
//////////////////////////////////////

// Tests utimes(). Calls utimes() inside enclave to change the access and
// modification time inside the enclave, and calls stat() to verify the times
// are correctly set.
TEST_F(SyscallsTest, Utimes) {
  EXPECT_THAT(
      RunSyscallInsideEnclave(
          "utimes", absl::GetFlag(FLAGS_test_tmpdir) + "/utimes", nullptr),
      IsOk());
}

}  // namespace
}  // namespace asylo
