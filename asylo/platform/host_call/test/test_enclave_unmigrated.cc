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
#include "asylo/platform/host_call/trusted/host_calls_unmigrated.h"
#include "asylo/platform/primitives/primitive_status.h"
#include "asylo/platform/primitives/trusted_primitives.h"
#include "asylo/platform/primitives/trusted_runtime.h"
#include "asylo/platform/primitives/util/message.h"
#include "asylo/platform/system_call/system_call.h"
#include "asylo/platform/system_call/type_conversions/types.h"
#include "asylo/platform/system_call/type_conversions/types_functions.h"
#include "asylo/util/status_macros.h"

using asylo::primitives::EntryHandler;
using asylo::primitives::Extent;
using asylo::primitives::MessageReader;
using asylo::primitives::MessageWriter;
using asylo::primitives::PrimitiveStatus;
using asylo::primitives::TrustedPrimitives;

namespace asylo {
namespace host_call {
namespace {

// Message handler that aborts the enclave.
PrimitiveStatus Abort(void *context, MessageReader *in, MessageWriter *out) {
  ASYLO_RETURN_IF_READER_NOT_EMPTY(*in);
  TrustedPrimitives::BestEffortAbort("Aborting enclave");
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestChmod(void *context, MessageReader *in,
                          MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 2);

  const auto path_name = in->next();
  mode_t mode = in->next<mode_t>();

  out->Push<int>(enc_untrusted_chmod(path_name.As<char>(), mode));
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestClose(void *context, MessageReader *in,
                          MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 1);

  int fd = in->next<int>();
  out->Push<int>(enc_untrusted_close(fd));
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestFchmod(void *context, MessageReader *in,
                           MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 2);

  int fd = in->next<int>();
  mode_t mode = in->next<mode_t>();

  out->Push<int>(enc_untrusted_fchmod(fd, mode));
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestUmask(void *context, MessageReader *in,
                          MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 1);

  mode_t mask = in->next<mode_t>();

  out->Push<mode_t>(enc_untrusted_umask(mask));
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestSocket(void *context, MessageReader *in,
                           MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 3);

  int domain = in->next<int>();
  int type = in->next<int>();
  int protocol = in->next<int>();
  out->Push<int>(enc_untrusted_socket(domain, type, protocol));

  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestListen(void *context, MessageReader *in,
                           MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 2);

  int sockfd = in->next<int>();
  int backlog = in->next<int>();
  out->Push<int>(enc_untrusted_listen(sockfd, backlog));

  return primitives::PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestShutdown(void *context, MessageReader *in,
                             MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 2);

  int sockfd = in->next<int>();
  int how = in->next<int>();
  out->Push<int>(enc_untrusted_shutdown(sockfd, how));

  return primitives::PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestSend(void *context, MessageReader *in, MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 4);

  int sockfd = in->next<int>();
  const auto buf = in->next();
  auto len = in->next<size_t>();
  int flags = in->next<int>();
  out->Push<ssize_t>(enc_untrusted_send(sockfd, buf.As<char>(), len, flags));

  return primitives::PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestFcntl(void *context, MessageReader *in,
                          MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 3);

  int fd = in->next<int>();
  int cmd = in->next<int>();
  int arg = in->next<int>();
  int result = enc_untrusted_fcntl(fd, cmd, arg);
  if (cmd == F_GETFL) {
    int tmp = result;
    TokLinuxFileStatusFlag(&tmp, &result);
  } else if (cmd == F_GETFD) {
    int tmp = result;
    TokLinuxFDFlag(&tmp, &result);
  }

  out->Push<int>(result);

  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestChown(void *context, MessageReader *in,
                          MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 3);

  const auto pathname = in->next();
  uid_t owner = in->next<uid_t>();
  gid_t group = in->next<gid_t>();
  out->Push<int>(enc_untrusted_chown(pathname.As<char>(), owner, group));
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestFChown(void *context, MessageReader *in,
                           MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 3);

  int fd = in->next<int>();
  auto owner = in->next<uid_t>();
  auto group = in->next<gid_t>();
  out->Push<int>(enc_untrusted_fchown(fd, owner, group));
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestSetsockopt(void *context, MessageReader *in,
                               MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 4);

  int sockfd = in->next<int>();
  int level = in->next<int>();
  int klinux_optname = in->next<int>();
  int option = in->next<int>();

  int optname;
  FromkLinuxOptionName(&level, &klinux_optname, &optname);
  out->Push<int>(enc_untrusted_setsockopt(sockfd, level, optname,
                                          (void *)&option, sizeof(option)));

  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestFlock(void *context, MessageReader *in,
                          MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 2);

  int fd = in->next<int>();
  int kLinux_operation = in->next<int>();  // The operation is expected to be
                                           // a kLinux_ operation.
  int operation;
  FromkLinuxFLockOperation(&kLinux_operation, &operation);
  out->Push<int>(enc_untrusted_flock(fd, operation));

  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestFsync(void *context, MessageReader *in,
                          MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 1);

  int fd = in->next<int>();
  out->Push<int>(enc_untrusted_fsync(fd));

  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestInotifyInit1(void *context, MessageReader *in,
                                 MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 1);

  int kLinux_flags = in->next<int>();  // The operation is expected to be
                                       // a kLinux_ operation.
  int flags;
  FromkLinuxInotifyFlag(&kLinux_flags, &flags);
  out->Push<int>(enc_untrusted_inotify_init1(flags));
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestInotifyAddWatch(void *context, MessageReader *in,
                                    MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 3);

  int fd = in->next<int>();
  const auto pathname = in->next();
  int kLinux_mask = in->next<uint32_t>();  // The operation is expected to be
                                           // a kLinux_ operation.
  int mask;
  FromkLinuxInotifyEventMask(&kLinux_mask, &mask);
  out->Push<int>(
      enc_untrusted_inotify_add_watch(fd, pathname.As<char>(), mask));

  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestInotifyRmWatch(void *context, MessageReader *in,
                                   MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 2);

  int fd = in->next<int>();
  int wd = in->next<int>();
  out->Push<int>(enc_untrusted_inotify_rm_watch(fd, wd));
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestSchedYield(void *context, MessageReader *in,
                               MessageWriter *out) {
  ASYLO_RETURN_IF_READER_NOT_EMPTY(*in);

  out->Push<int>(enc_untrusted_sched_yield());
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestIsAtty(void *context, MessageReader *in,
                           MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 1);

  int fd = in->next<int>();
  out->Push<int>(enc_untrusted_isatty(fd));
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestUSleep(void *context, MessageReader *in,
                           MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 1);

  auto usec = in->next<unsigned int>();
  out->Push<int>(enc_untrusted_usleep(usec));
  return PrimitiveStatus::OkStatus();
}

// Push meaningful stat attributes to MessageWriter.
void PushStatAttributes(MessageWriter *out, struct stat *st) {
  int mode = st->st_mode;
  int kLinux_mode;
  TokLinuxFileModeFlag(&mode, &kLinux_mode);

  out->Push<uint64_t>(st->st_atime);
  out->Push<int64_t>(st->st_blksize);
  out->Push<int64_t>(st->st_blocks);
  out->Push<uint64_t>(st->st_mtime);
  out->Push<uint64_t>(st->st_dev);
  out->Push<uint32_t>(st->st_gid);
  out->Push<uint64_t>(st->st_ino);
  out->Push<uint32_t>(kLinux_mode);
  out->Push<uint64_t>(st->st_ctime);
  out->Push<uint64_t>(st->st_nlink);
  out->Push<uint64_t>(st->st_rdev);
  out->Push<int64_t>(st->st_size);
  out->Push<uint32_t>(st->st_uid);
}

PrimitiveStatus TestFstat(void *context, MessageReader *in,
                          MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 1);

  struct stat st;
  int fd = in->next<int>();
  out->Push<int>(enc_untrusted_fstat(fd, &st));
  PushStatAttributes(out, &st);
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestLstat(void *context, MessageReader *in,
                          MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 1);

  struct stat st;
  const auto path_name = in->next();
  out->Push<int>(enc_untrusted_lstat(path_name.As<char>(), &st));
  PushStatAttributes(out, &st);
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestStat(void *context, MessageReader *in, MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 1);

  struct stat st;
  const auto path_name = in->next();
  out->Push<int>(enc_untrusted_stat(path_name.As<char>(), &st));
  PushStatAttributes(out, &st);
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestPread64(void *context, MessageReader *in,
                            MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 3);

  int fd = in->next<int>();
  int len = in->next<int>();
  off_t offset = in->next<off_t>();
  char buf[10];

  out->Push<int>(enc_untrusted_pread64(fd, buf, len, offset));
  out->Push(buf);
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestPwrite64(void *context, MessageReader *in,
                             MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 4);

  int fd = in->next<int>();
  auto buf = in->next();
  int len = in->next<int>();
  off_t offset = in->next<off_t>();

  out->Push<int>(enc_untrusted_pwrite64(fd, buf.As<char>(), len, offset));
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestWait(void *context, MessageReader *in, MessageWriter *out) {
  ASYLO_RETURN_IF_READER_NOT_EMPTY(*in);

  int wstatus = 0;

  out->Push<int>(enc_untrusted_wait(&wstatus));
  out->Push<int>(wstatus);
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestSysconf(void *context, MessageReader *in,
                            MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 1);

  int kLinux_name = in->next<int>();
  int name;
  FromkLinuxSysconfConstant(&kLinux_name, &name);
  out->Push<int64_t>(enc_untrusted_sysconf(name));
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
      asylo::host_call::kTestChmod, EntryHandler{asylo::host_call::TestChmod}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestClose, EntryHandler{asylo::host_call::TestClose}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestFchmod,
      EntryHandler{asylo::host_call::TestFchmod}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestUmask, EntryHandler{asylo::host_call::TestUmask}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestSocket,
      EntryHandler{asylo::host_call::TestSocket}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestListen,
      EntryHandler{asylo::host_call::TestListen}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestShutdown,
      EntryHandler{asylo::host_call::TestShutdown}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestSend, EntryHandler{asylo::host_call::TestSend}));
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
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestFstat, EntryHandler{asylo::host_call::TestFstat}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestLstat, EntryHandler{asylo::host_call::TestLstat}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestStat, EntryHandler{asylo::host_call::TestStat}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestPread64,
      EntryHandler{asylo::host_call::TestPread64}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestPwrite64,
      EntryHandler{asylo::host_call::TestPwrite64}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestWait, EntryHandler{asylo::host_call::TestWait}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestSysconf,
      EntryHandler{asylo::host_call::TestSysconf}));
  return PrimitiveStatus::OkStatus();
}

// Implements the required enclave finalization function.
extern "C" PrimitiveStatus asylo_enclave_fini() {
  return PrimitiveStatus::OkStatus();
}
