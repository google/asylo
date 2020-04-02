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

#ifndef ASYLO_PLATFORM_HOST_CALL_TEST_ENCLAVE_TEST_SELECTORS_H_
#define ASYLO_PLATFORM_HOST_CALL_TEST_ENCLAVE_TEST_SELECTORS_H_

#include "asylo/platform/primitives/primitives.h"
#include "asylo/platform/system_call/sysno.h"

// This header file defines the entry points registered by the enclave.

namespace asylo {
namespace host_call {

// Selector (entry handler) for handler that aborts the enclave.
constexpr uint64_t kAbortEnclaveSelector = primitives::kSelectorUser;

// Offset to be used for starting host call entry handler constants relative to
// |kSelectorUser|.
constexpr uint64_t kFirstSelector = primitives::kSelectorUser + 1;

// Offset to be used when starting host libc host call entry handler
// constants relative to |kSelectorUser|.
constexpr uint64_t kHostLibCSelector = primitives::kSelectorUser + 1024;

// Each entry handler constant below corresponds to a host call
// (enc_untrusted_foo()), and its corresponding trusted handler is responsible
// for triggering a host call to test it, and sending the results back to the
// untrusted side for validation.

// Host calls with their own syscall numbers.
constexpr uint64_t kTestAccess =
    kFirstSelector + asylo::system_call::kSYS_access;
constexpr uint64_t kTestChmod = kFirstSelector + asylo::system_call::kSYS_chmod;
constexpr uint64_t kTestClose = kFirstSelector + asylo::system_call::kSYS_close;
constexpr uint64_t kTestFchmod =
    kFirstSelector + asylo::system_call::kSYS_fchmod;
constexpr uint64_t kTestGetPid =
    kFirstSelector + asylo::system_call::kSYS_getpid;
constexpr uint64_t kTestGetPpid =
    kFirstSelector + asylo::system_call::kSYS_getppid;
constexpr uint64_t kTestKill = kFirstSelector + asylo::system_call::kSYS_kill;
constexpr uint64_t kTestLink = kFirstSelector + asylo::system_call::kSYS_link;
constexpr uint64_t kTestLseek = kFirstSelector + asylo::system_call::kSYS_lseek;
constexpr uint64_t kTestMkdir = kFirstSelector + asylo::system_call::kSYS_mkdir;
constexpr uint64_t kTestOpen = kFirstSelector + asylo::system_call::kSYS_open;
constexpr uint64_t kTestUnlink =
    kFirstSelector + asylo::system_call::kSYS_unlink;
constexpr uint64_t kTestUmask = kFirstSelector + asylo::system_call::kSYS_umask;
constexpr uint64_t kTestGetUid =
    kFirstSelector + asylo::system_call::kSYS_getuid;
constexpr uint64_t kTestGetGid =
    kFirstSelector + asylo::system_call::kSYS_getgid;
constexpr uint64_t kTestGetEuid =
    kFirstSelector + asylo::system_call::kSYS_geteuid;
constexpr uint64_t kTestGetEgid =
    kFirstSelector + asylo::system_call::kSYS_getegid;
constexpr uint64_t kTestRename =
    kFirstSelector + asylo::system_call::kSYS_rename;
constexpr uint64_t kTestRead = kFirstSelector + asylo::system_call::kSYS_read;
constexpr uint64_t kTestWrite = kFirstSelector + asylo::system_call::kSYS_write;
constexpr uint64_t kTestSymlink =
    kFirstSelector + asylo::system_call::kSYS_symlink;
constexpr uint64_t kTestReadLink =
    kFirstSelector + asylo::system_call::kSYS_readlink;
constexpr uint64_t kTestTruncate =
    kFirstSelector + asylo::system_call::kSYS_truncate;
constexpr uint64_t kTestFTruncate =
    kFirstSelector + asylo::system_call::kSYS_ftruncate;
constexpr uint64_t kTestRmdir = kFirstSelector + asylo::system_call::kSYS_rmdir;
constexpr uint64_t kTestSocket =
    kFirstSelector + asylo::system_call::kSYS_socket;
constexpr uint64_t kTestListen =
    kFirstSelector + asylo::system_call::kSYS_listen;
constexpr uint64_t kTestShutdown =
    kFirstSelector + asylo::system_call::kSYS_shutdown;
constexpr uint64_t kTestFcntl = kFirstSelector + asylo::system_call::kSYS_fcntl;
constexpr uint64_t kTestChown = kFirstSelector + asylo::system_call::kSYS_chown;
constexpr uint64_t kTestFChown =
    kFirstSelector + asylo::system_call::kSYS_fchown;
constexpr uint64_t kTestSetSockOpt =
    kFirstSelector + asylo::system_call::kSYS_setsockopt;
constexpr uint64_t kTestFlock = kFirstSelector + asylo::system_call::kSYS_flock;
constexpr uint64_t kTestFsync = kFirstSelector + asylo::system_call::kSYS_fsync;
constexpr uint64_t kTestInotifyInit1 =
    kFirstSelector + asylo::system_call::kSYS_inotify_init1;
constexpr uint64_t kTestInotifyAddWatch =
    kFirstSelector + asylo::system_call::kSYS_inotify_add_watch;
constexpr uint64_t kTestInotifyRmWatch =
    kFirstSelector + asylo::system_call::kSYS_inotify_rm_watch;
constexpr uint64_t kTestSchedYield =
    kFirstSelector + asylo::system_call::kSYS_sched_yield;
constexpr uint64_t kTestSchedGetAffinity =
    kFirstSelector + asylo::system_call::kSYS_sched_getaffinity;
constexpr uint64_t kTestFstat = kFirstSelector + asylo::system_call::kSYS_fstat;
constexpr uint64_t kTestLstat = kFirstSelector + asylo::system_call::kSYS_lstat;
constexpr uint64_t kTestStat = kFirstSelector + asylo::system_call::kSYS_stat;
constexpr uint64_t kTestStatFs =
    kFirstSelector + asylo::system_call::kSYS_statfs;
constexpr uint64_t kTestFstatFs =
    kFirstSelector + asylo::system_call::kSYS_fstatfs;
constexpr uint64_t kTestPread64 =
    kFirstSelector + asylo::system_call::kSYS_pread64;
constexpr uint64_t kTestPwrite64 =
    kFirstSelector + asylo::system_call::kSYS_pwrite64;
constexpr uint64_t kTestPipe2 = kFirstSelector + asylo::system_call::kSYS_pipe2;
constexpr uint64_t kTestNanosleep =
    kFirstSelector + asylo::system_call::kSYS_nanosleep;
constexpr uint64_t kTestBind = kFirstSelector + asylo::system_call::kSYS_bind;
constexpr uint64_t kTestConnect =
    kFirstSelector + asylo::system_call::kSYS_connect;
constexpr uint64_t kTestSelect =
    kFirstSelector + asylo::system_call::kSYS_select;
constexpr uint64_t kTestPoll = kFirstSelector + asylo::system_call::kSYS_poll;
constexpr uint64_t kTestUtime = kFirstSelector + asylo::system_call::kSYS_utime;
constexpr uint64_t kTestGetRusage =
    kFirstSelector + asylo::system_call::kSYS_getrusage;
constexpr uint64_t kTestXattr =
    kFirstSelector + asylo::system_call::kSYS_setxattr;
constexpr uint64_t kTestLXattr =
    kFirstSelector + asylo::system_call::kSYS_lsetxattr;
constexpr uint64_t kTestFXattr =
    kFirstSelector + asylo::system_call::kSYS_fsetxattr;

// Host calls implemented via other syscalls or as libc library functions.
constexpr uint64_t kTestIsAtty = kHostLibCSelector;
constexpr uint64_t kTestUSleep = kHostLibCSelector + 1;
constexpr uint64_t kTestSysconf = kHostLibCSelector + 2;
constexpr uint64_t kTestWait = kHostLibCSelector + 3;
constexpr uint64_t kTestSend = kHostLibCSelector + 4;
constexpr uint64_t kTestRealloc = kHostLibCSelector + 5;
constexpr uint64_t kTestSleep = kHostLibCSelector + 6;
constexpr uint64_t kTestSendMsg = kHostLibCSelector + 7;
constexpr uint64_t kTestRecvMsg = kHostLibCSelector + 8;
constexpr uint64_t kTestGetSockname = kHostLibCSelector + 9;
constexpr uint64_t kTestAccept = kHostLibCSelector + 10;
constexpr uint64_t kTestRaise = kHostLibCSelector + 11;
constexpr uint64_t kTestGetSockOpt = kHostLibCSelector + 12;
constexpr uint64_t kTestGetAddrInfo = kHostLibCSelector + 13;
constexpr uint64_t kTestClockGettime = kHostLibCSelector + 14;

}  // namespace host_call
}  // namespace asylo

#endif  // ASYLO_PLATFORM_HOST_CALL_TEST_ENCLAVE_TEST_SELECTORS_H_
