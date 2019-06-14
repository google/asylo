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

#include <cstdint>

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

// Offset to be used when starting non-syscall host call entry handler
// constants relative to |kSelectorUser|.
constexpr uint64_t kNonSyscallFirstSelector = primitives::kSelectorUser + 1024;

// Each entry handler constant below corresponds to an unit test on the
// untrusted side, and its corresponding trusted handler is responsible for
// triggering a host call to test it, and sending the results back to the
// untrusted side for validation.
constexpr uint64_t kTestAccess =
    kFirstSelector + asylo::system_call::kSYS_access;
constexpr uint64_t kTestChmod = kFirstSelector + asylo::system_call::kSYS_chmod;
constexpr uint64_t kTestClose = kFirstSelector + asylo::system_call::kSYS_close;
constexpr uint64_t kTestFchmod =
    kFirstSelector + asylo::system_call::kSYS_fchmod;
constexpr uint64_t kTestGetPid =
    kFirstSelector + asylo::system_call::kSYS_getpid;
constexpr uint64_t kTestKill = kFirstSelector + asylo::system_call::kSYS_kill;
constexpr uint64_t kTestLink = kFirstSelector + asylo::system_call::kSYS_link;
constexpr uint64_t kTestLseek = kFirstSelector + asylo::system_call::kSYS_lseek;
constexpr uint64_t kTestMkdir = kFirstSelector + asylo::system_call::kSYS_mkdir;
constexpr uint64_t kTestOpen = kFirstSelector + asylo::system_call::kSYS_open;
constexpr uint64_t kTestUnlink =
    kFirstSelector + asylo::system_call::kSYS_unlink;
constexpr uint64_t kTestUmask =
    kFirstSelector + asylo::system_call::kSYS_umask;
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
constexpr uint64_t kTestFcntl = kFirstSelector + asylo::system_call::kSYS_fcntl;
constexpr uint64_t kTestChown = kFirstSelector + asylo::system_call::kSYS_chown;
constexpr uint64_t kTestFChown =
    kFirstSelector + asylo::system_call::kSYS_fchown;
constexpr uint64_t kTestSetSockOpt =
    kFirstSelector + asylo::system_call::kSYS_setsockopt;
constexpr uint64_t kTestFlock =
    kFirstSelector + asylo::system_call::kSYS_flock;
constexpr uint64_t kTestInotifyInit1 =
    kFirstSelector + asylo::system_call::kSYS_inotify_init1;
constexpr uint64_t kTestInotifyAddWatch =
    kFirstSelector + asylo::system_call::kSYS_inotify_add_watch;
constexpr uint64_t kTestInotifyRmWatch =
    kFirstSelector + asylo::system_call::kSYS_inotify_rm_watch;

constexpr uint64_t kTestIsAtty = kNonSyscallFirstSelector;

}  // namespace host_call
}  // namespace asylo

#endif  // ASYLO_PLATFORM_HOST_CALL_TEST_ENCLAVE_TEST_SELECTORS_H_
