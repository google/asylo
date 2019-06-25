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

#include "asylo/platform/host_call/test/enclave_test_selectors.h"
#include "asylo/platform/host_call/trusted/host_call_dispatcher.h"
#include "asylo/platform/host_call/trusted/host_calls.h"
#include "asylo/platform/primitives/primitive_status.h"
#include "asylo/platform/primitives/trusted_primitives.h"
#include "asylo/platform/primitives/trusted_runtime.h"
#include "asylo/platform/system_call/system_call.h"
#include "asylo/platform/system_call/type_conversions/types_functions.h"
#include "asylo/util/status_macros.h"

using asylo::primitives::EntryHandler;
using asylo::primitives::PrimitiveStatus;
using asylo::primitives::TrustedPrimitives;

namespace asylo {
namespace host_call {
namespace {

// Message handler that aborts the enclave.
PrimitiveStatus Abort(void *context,
                      primitives::TrustedParameterStack *params) {
  ASYLO_RETURN_IF_STACK_EMPTY(params);
  TrustedPrimitives::BestEffortAbort("Aborting enclave");
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestAccess(void *context,
                           primitives::TrustedParameterStack *params) {
  ASYLO_RETURN_IF_INCORRECT_ARGUMENTS(params, 2);

  int mode = params->Pop<int>();
  const auto path_name = params->Pop();

  params->PushByCopy<int>(enc_untrusted_access(path_name->As<char>(), mode));
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestChmod(void *context,
                          primitives::TrustedParameterStack *params) {
  ASYLO_RETURN_IF_INCORRECT_ARGUMENTS(params, 2);

  mode_t mode = params->Pop<mode_t>();
  const auto path_name = params->Pop();

  params->PushByCopy<int>(enc_untrusted_chmod(path_name->As<char>(), mode));
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestClose(void *context,
                          primitives::TrustedParameterStack *params) {
  ASYLO_RETURN_IF_INCORRECT_ARGUMENTS(params, 1);

  int fd = params->Pop<int>();
  params->PushByCopy<int>(enc_untrusted_close(fd));
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestFchmod(void *context,
                           primitives::TrustedParameterStack *params) {
  ASYLO_RETURN_IF_INCORRECT_ARGUMENTS(params, 2);

  mode_t mode = params->Pop<mode_t>();
  int fd = params->Pop<int>();

  params->PushByCopy<int>(enc_untrusted_fchmod(fd, mode));
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestGetpid(void *context,
                           primitives::TrustedParameterStack *params) {
  ASYLO_RETURN_IF_STACK_EMPTY(params);

  params->PushByCopy<pid_t>(enc_untrusted_getpid());
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestGetPpid(void *context,
                            primitives::TrustedParameterStack *params) {
  ASYLO_RETURN_IF_STACK_EMPTY(params);

  params->PushByCopy<pid_t>(enc_untrusted_getppid());
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestSetSid(void *context,
                           primitives::TrustedParameterStack *params) {
  ASYLO_RETURN_IF_STACK_EMPTY(params);

  params->PushByCopy<pid_t>(enc_untrusted_setsid());
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestKill(void *context,
                         primitives::TrustedParameterStack *params) {
  ASYLO_RETURN_IF_INCORRECT_ARGUMENTS(params, 2);

  int sig = params->Pop<int>();
  pid_t pid = params->Pop<pid_t>();

  params->PushByCopy<int>(enc_untrusted_kill(pid, sig));
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestLink(void *context,
                         primitives::TrustedParameterStack *params) {
  ASYLO_RETURN_IF_INCORRECT_ARGUMENTS(params, 2);

  const auto new_path = params->Pop();
  const auto old_path = params->Pop();

  params->PushByCopy<int>(
      enc_untrusted_link(old_path->As<char>(), new_path->As<char>()));
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestLseek(void *context,
                          primitives::TrustedParameterStack *params) {
  ASYLO_RETURN_IF_INCORRECT_ARGUMENTS(params, 3);

  int whence = params->Pop<int>();
  off_t offset = params->Pop<off_t>();
  int fd = params->Pop<int>();

  params->PushByCopy<off_t>(enc_untrusted_lseek(fd, offset, whence));
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestMkdir(void *context,
                          primitives::TrustedParameterStack *params) {
  ASYLO_RETURN_IF_INCORRECT_ARGUMENTS(params, 2);

  mode_t mode = params->Pop<mode_t>();
  const auto pathname = params->Pop();

  params->PushByCopy<int>(enc_untrusted_mkdir(pathname->As<char>(), mode));
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestOpen(void *context,
                         primitives::TrustedParameterStack *params) {
  // open() can assume 2 or 3 arguments.
  if (params->size() == 3) {
    mode_t mode = params->Pop<mode_t>();
    int flags = params->Pop<int>();
    const auto pathname = params->Pop();
    params->PushByCopy<int>(
        enc_untrusted_open(pathname->As<char>(), flags, mode));
  } else if (params->size() == 2) {
    int flags = params->Pop<int>();
    const auto pathname = params->Pop();
    params->PushByCopy<int>(enc_untrusted_open(pathname->As<char>(), flags));
  } else {
    return {error::GoogleError::INVALID_ARGUMENT,
            "Unexpected number of arguments. open() expects 2 or 3 arguments."};
  }

  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestUnlink(void *context,
                           primitives::TrustedParameterStack *params) {
  ASYLO_RETURN_IF_INCORRECT_ARGUMENTS(params, 1);

  const auto pathname = params->Pop();

  params->PushByCopy<int>(enc_untrusted_unlink(pathname->As<char>()));
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestUmask(void *context,
                          primitives::TrustedParameterStack *params) {
  ASYLO_RETURN_IF_INCORRECT_ARGUMENTS(params, 1);

  mode_t mask = params->Pop<mode_t>();

  params->PushByCopy<mode_t>(enc_untrusted_umask(mask));
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestGetuid(void *context,
                           primitives::TrustedParameterStack *params) {
  ASYLO_RETURN_IF_STACK_EMPTY(params);

  params->PushByCopy<uid_t>(enc_untrusted_getuid());
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestGetgid(void *context,
                           primitives::TrustedParameterStack *params) {
  ASYLO_RETURN_IF_STACK_EMPTY(params);

  params->PushByCopy<gid_t>(enc_untrusted_getgid());
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestGeteuid(void *context,
                            primitives::TrustedParameterStack *params) {
  ASYLO_RETURN_IF_STACK_EMPTY(params);

  params->PushByCopy<uid_t>(enc_untrusted_geteuid());
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestGetegid(void *context,
                            primitives::TrustedParameterStack *params) {
  ASYLO_RETURN_IF_STACK_EMPTY(params);

  params->PushByCopy<gid_t>(enc_untrusted_getegid());
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestRename(void *context,
                           primitives::TrustedParameterStack *params) {
  ASYLO_RETURN_IF_INCORRECT_ARGUMENTS(params, 2);

  const auto newpath = params->Pop();
  const auto oldpath = params->Pop();

  params->PushByCopy<int>(
      enc_untrusted_rename(oldpath->As<char>(), newpath->As<char>()));
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestRead(void *context,
                         primitives::TrustedParameterStack *params) {
  ASYLO_RETURN_IF_INCORRECT_ARGUMENTS(params, 2);
  size_t count = params->Pop<size_t>();
  int fd = params->Pop<int>();
  char read_buf[20];

  params->PushByCopy<ssize_t>(enc_untrusted_read(fd, read_buf, count));
  params->PushByCopy<char>(read_buf, strlen(read_buf) + 1);
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestWrite(void *context,
                          primitives::TrustedParameterStack *params) {
  ASYLO_RETURN_IF_INCORRECT_ARGUMENTS(params, 3);
  size_t count = params->Pop<size_t>();
  const auto write_buf = params->Pop();
  int fd = params->Pop<int>();

  params->PushByCopy<ssize_t>(
      enc_untrusted_write(fd, write_buf->As<char>(), count));
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestSymlink(void *context,
                            primitives::TrustedParameterStack *params) {
  ASYLO_RETURN_IF_INCORRECT_ARGUMENTS(params, 2);
  const auto linkpath = params->Pop();
  const auto target = params->Pop();

  params->PushByCopy<ssize_t>(
      enc_untrusted_symlink(target->As<char>(), linkpath->As<char>()));
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestReadlink(void *context,
                             primitives::TrustedParameterStack *params) {
  ASYLO_RETURN_IF_INCORRECT_ARGUMENTS(params, 1);
  const auto pathname = params->Pop();

  char buf[PATH_MAX];
  ssize_t len =
      enc_untrusted_readlink(pathname->As<char>(), buf, sizeof(buf) - 1);
  params->PushByCopy<ssize_t>(len);

  buf[len] = '\0';
  params->PushByCopy<char>(buf, strlen(buf) + 1);
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestTruncate(void *context,
                             primitives::TrustedParameterStack *params) {
  ASYLO_RETURN_IF_INCORRECT_ARGUMENTS(params, 2);
  off_t length = params->Pop<off_t>();
  const auto path = params->Pop();

  params->PushByCopy<int>(enc_untrusted_truncate(path->As<char>(), length));

  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestFTruncate(void *context,
                              primitives::TrustedParameterStack *params) {
  ASYLO_RETURN_IF_INCORRECT_ARGUMENTS(params, 2);
  auto length = params->Pop<off_t>();
  int fd = params->Pop<int>();

  params->PushByCopy<int>(enc_untrusted_ftruncate(fd, length));

  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestRmdir(void *context,
                          primitives::TrustedParameterStack *params) {
  ASYLO_RETURN_IF_INCORRECT_ARGUMENTS(params, 1);
  const auto path = params->Pop();

  params->PushByCopy<int>(enc_untrusted_rmdir(path->As<char>()));
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestSocket(void *context,
                           primitives::TrustedParameterStack *params) {
  ASYLO_RETURN_IF_INCORRECT_ARGUMENTS(params, 3);

  int protocol = params->Pop<int>();
  int type = params->Pop<int>();
  int domain = params->Pop<int>();
  params->PushByCopy<int>(enc_untrusted_socket(domain, type, protocol));

  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestFcntl(void *context,
                          primitives::TrustedParameterStack *params) {
  ASYLO_RETURN_IF_INCORRECT_ARGUMENTS(params, 3);

  int arg = params->Pop<int>();
  int cmd = params->Pop<int>();
  int fd = params->Pop<int>();
  params->PushByCopy<int>(enc_untrusted_fcntl(fd, cmd, arg));

  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestChown(void *context,
                          primitives::TrustedParameterStack *params) {
  ASYLO_RETURN_IF_INCORRECT_ARGUMENTS(params, 3);

  gid_t group = params->Pop<gid_t>();
  uid_t owner = params->Pop<uid_t>();
  const auto pathname = params->Pop();
  params->PushByCopy<int>(
      enc_untrusted_chown(pathname->As<char>(), owner, group));
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestFChown(void *context,
                           primitives::TrustedParameterStack *params) {
  ASYLO_RETURN_IF_INCORRECT_ARGUMENTS(params, 3);

  auto group = params->Pop<gid_t>();
  auto owner = params->Pop<uid_t>();
  int fd = params->Pop<int>();
  params->PushByCopy<int>(enc_untrusted_fchown(fd, owner, group));
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestSetsockopt(void *context,
                               primitives::TrustedParameterStack *params) {
  ASYLO_RETURN_IF_INCORRECT_ARGUMENTS(params, 4);

  int option = params->Pop<int>();
  int klinux_optname = params->Pop<int>();
  int level = params->Pop<int>();
  int sockfd = params->Pop<int>();

  int optname;
  FromkLinuxOptionName(&level, &klinux_optname, &optname);
  params->PushByCopy<int>(enc_untrusted_setsockopt(
      sockfd, level, optname, (void *)&option, sizeof(option)));

  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestFlock(void *context,
                          primitives::TrustedParameterStack *params) {
  ASYLO_RETURN_IF_INCORRECT_ARGUMENTS(params, 2);

  int operation =
      params->Pop<int>();  // The operation is expected to be
                           // already converted from a kLinux_ operation.
  int fd = params->Pop<int>();
  params->PushByCopy<int>(enc_untrusted_flock(fd, operation));

  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestFsync(void *context,
                          primitives::TrustedParameterStack *params) {
  ASYLO_RETURN_IF_INCORRECT_ARGUMENTS(params, 1);

  int fd = params->Pop<int>();
  params->PushByCopy<int>(enc_untrusted_fsync(fd));

  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestInotifyInit1(void *context,
                                 primitives::TrustedParameterStack *params) {
  ASYLO_RETURN_IF_INCORRECT_ARGUMENTS(params, 1);

  int flags = params->Pop<int>();  // The operation is expected to be already
                                   // converted from a kLinux_ operation.
  params->PushByCopy<int>(enc_untrusted_inotify_init1(flags));
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestInotifyAddWatch(void *context,
                                    primitives::TrustedParameterStack *params) {
  ASYLO_RETURN_IF_INCORRECT_ARGUMENTS(params, 3);

  uint32_t mask =
      params->Pop<uint32_t>();  // The operation is expected to be already
                                // converted from a kLinux_ operation.
  const auto pathname = params->Pop();
  int fd = params->Pop<int>();
  params->PushByCopy<int>(
      enc_untrusted_inotify_add_watch(fd, pathname->As<char>(), mask));

  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestInotifyRmWatch(void *context,
                                   primitives::TrustedParameterStack *params) {
  ASYLO_RETURN_IF_INCORRECT_ARGUMENTS(params, 2);

  int wd = params->Pop<int>();
  int fd = params->Pop<int>();
  params->PushByCopy<int>(enc_untrusted_inotify_rm_watch(fd, wd));
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestSchedYield(void *context,
                               primitives::TrustedParameterStack *params) {
  ASYLO_RETURN_IF_STACK_EMPTY(params);

  params->PushByCopy<int>(enc_untrusted_sched_yield());
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestIsAtty(void *context,
                           primitives::TrustedParameterStack *params) {
  ASYLO_RETURN_IF_INCORRECT_ARGUMENTS(params, 1);

  int fd = params->Pop<int>();
  params->PushByCopy<int>(enc_untrusted_isatty(fd));
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestUSleep(void *context,
                           primitives::TrustedParameterStack *params) {
  ASYLO_RETURN_IF_INCORRECT_ARGUMENTS(params, 1);
  auto usec = params->Pop<unsigned int>();
  params->PushByCopy<int>(enc_untrusted_usleep(usec));
  return PrimitiveStatus::OkStatus();
}

}  // namespace
}  // namespace host_call
}  // namespace asylo

// Implements the required enclave initialization function.
extern "C" PrimitiveStatus asylo_enclave_init() {
  // Register the host call dispatcher.
  enc_set_dispatch_syscall(asylo::host_call::SystemCallDispatcher);

  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kAbortEnclaveSelector,
      EntryHandler{asylo::host_call::Abort}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestAccess,
      EntryHandler{asylo::host_call::TestAccess}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestChmod, EntryHandler{asylo::host_call::TestChmod}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestClose, EntryHandler{asylo::host_call::TestClose}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestFchmod,
      EntryHandler{asylo::host_call::TestFchmod}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestGetPid,
      EntryHandler{asylo::host_call::TestGetpid}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestGetPpid,
      EntryHandler{asylo::host_call::TestGetPpid}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestSetSid,
      EntryHandler{asylo::host_call::TestSetSid}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestKill, EntryHandler{asylo::host_call::TestKill}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestLink, EntryHandler{asylo::host_call::TestLink}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestLseek, EntryHandler{asylo::host_call::TestLseek}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestMkdir, EntryHandler{asylo::host_call::TestMkdir}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestOpen, EntryHandler{asylo::host_call::TestOpen}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestUnlink,
      EntryHandler{asylo::host_call::TestUnlink}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestUmask, EntryHandler{asylo::host_call::TestUmask}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestGetUid,
      EntryHandler{asylo::host_call::TestGetuid}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestGetGid,
      EntryHandler{asylo::host_call::TestGetgid}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestGetEuid,
      EntryHandler{asylo::host_call::TestGeteuid}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestGetEgid,
      EntryHandler{asylo::host_call::TestGetegid}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestRename,
      EntryHandler{asylo::host_call::TestRename}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestRead, EntryHandler{asylo::host_call::TestRead}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestWrite, EntryHandler{asylo::host_call::TestWrite}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestSymlink,
      EntryHandler{asylo::host_call::TestSymlink}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestReadLink,
      EntryHandler{asylo::host_call::TestReadlink}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestTruncate,
      EntryHandler{asylo::host_call::TestTruncate}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestFTruncate,
      EntryHandler{asylo::host_call::TestFTruncate}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestRmdir, EntryHandler{asylo::host_call::TestRmdir}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestSocket,
      EntryHandler{asylo::host_call::TestSocket}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestFcntl, EntryHandler{asylo::host_call::TestFcntl}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestChown, EntryHandler{asylo::host_call::TestChown}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestFChown,
      EntryHandler{asylo::host_call::TestFChown}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestSetSockOpt,
      EntryHandler{asylo::host_call::TestSetsockopt}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestFlock, EntryHandler{asylo::host_call::TestFlock}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestFsync, EntryHandler{asylo::host_call::TestFsync}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestInotifyInit1,
      EntryHandler{asylo::host_call::TestInotifyInit1}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestInotifyAddWatch,
      EntryHandler{asylo::host_call::TestInotifyAddWatch}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestInotifyRmWatch,
      EntryHandler{asylo::host_call::TestInotifyRmWatch}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestSchedYield,
      EntryHandler{asylo::host_call::TestSchedYield}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestIsAtty,
      EntryHandler{asylo::host_call::TestIsAtty}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestUSleep,
      EntryHandler{asylo::host_call::TestUSleep}));
  return PrimitiveStatus::OkStatus();
}

// Implements the required enclave finalization function.
extern "C" PrimitiveStatus asylo_enclave_fini() {
  return PrimitiveStatus::OkStatus();
}
