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

#include <errno.h>

#include "asylo/platform/host_call/test/enclave_test_selectors.h"
#include "asylo/platform/host_call/trusted/host_call_dispatcher.h"
#include "asylo/platform/host_call/trusted/host_calls.h"
#include "asylo/platform/primitives/primitive_status.h"
#include "asylo/platform/primitives/trusted_primitives.h"
#include "asylo/platform/primitives/trusted_runtime.h"
#include "asylo/platform/primitives/util/message.h"
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

PrimitiveStatus TestAccess(void *context, MessageReader *in,
                           MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 2);

  const auto path_name = in->next();
  int mode = in->next<int>();

  out->Push<int>(enc_untrusted_access(path_name.As<char>(), mode));
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestGetpid(void *context, MessageReader *in,
                           MessageWriter *out) {
  ASYLO_RETURN_IF_READER_NOT_EMPTY(*in);

  out->Push<pid_t>(enc_untrusted_getpid());
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestGetPpid(void *context, MessageReader *in,
                            MessageWriter *out) {
  ASYLO_RETURN_IF_READER_NOT_EMPTY(*in);

  out->Push<pid_t>(enc_untrusted_getppid());
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestSetSid(void *context, MessageReader *in,
                           MessageWriter *out) {
  ASYLO_RETURN_IF_READER_NOT_EMPTY(*in);

  out->Push<pid_t>(enc_untrusted_setsid());
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestGetuid(void *context, MessageReader *in,
                           MessageWriter *out) {
  ASYLO_RETURN_IF_READER_NOT_EMPTY(*in);

  out->Push<uid_t>(enc_untrusted_getuid());
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestGetgid(void *context, MessageReader *in,
                           MessageWriter *out) {
  ASYLO_RETURN_IF_READER_NOT_EMPTY(*in);

  out->Push<gid_t>(enc_untrusted_getgid());
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestGeteuid(void *context, MessageReader *in,
                            MessageWriter *out) {
  ASYLO_RETURN_IF_READER_NOT_EMPTY(*in);

  out->Push<uid_t>(enc_untrusted_geteuid());
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestGetegid(void *context, MessageReader *in,
                            MessageWriter *out) {
  ASYLO_RETURN_IF_READER_NOT_EMPTY(*in);

  out->Push<gid_t>(enc_untrusted_getegid());
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestKill(void *context, MessageReader *in, MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 2);

  pid_t pid = in->next<pid_t>();
  int sig = in->next<int>();

  out->Push<int>(enc_untrusted_kill(pid, sig));
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestLink(void *context, MessageReader *in, MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 2);

  const auto old_path = in->next();
  const auto new_path = in->next();

  out->Push<int>(enc_untrusted_link(old_path.As<char>(), new_path.As<char>()));
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestLseek(void *context, MessageReader *in,
                          MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 3);

  int fd = in->next<int>();
  off_t offset = in->next<off_t>();
  int whence = in->next<int>();

  out->Push<off_t>(enc_untrusted_lseek(fd, offset, whence));
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestMkdir(void *context, MessageReader *in,
                          MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 2);

  const auto pathname = in->next();
  mode_t mode = in->next<mode_t>();

  out->Push<int>(enc_untrusted_mkdir(pathname.As<char>(), mode));
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestOpen(void *context, MessageReader *in, MessageWriter *out) {
  // open() can assume 2 or 3 arguments.
  if (in->size() == 3) {
    const auto pathname = in->next();
    int linux_flags = in->next<int>();
    int linux_mode = in->next<mode_t>();
    int flags;
    FromkLinuxFileStatusFlag(&linux_flags, &flags);
    int mode;
    FromkLinuxFileModeFlag(&linux_mode, &mode);
    out->Push<int>(enc_untrusted_open(pathname.As<char>(), flags, mode));
  } else if (in->size() == 2) {
    const auto pathname = in->next();
    int kLinux_flags = in->next<int>();
    int flags;
    FromkLinuxFileStatusFlag(&kLinux_flags, &flags);
    out->Push<int>(enc_untrusted_open(pathname.As<char>(), flags));
  } else {
    return {error::GoogleError::INVALID_ARGUMENT,
            "Unexpected number of arguments. open() expects 2 or 3 arguments."};
  }

  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestUnlink(void *context, MessageReader *in,
                           MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 1);

  const auto pathname = in->next();

  out->Push<int>(enc_untrusted_unlink(pathname.As<char>()));
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestRename(void *context, MessageReader *in,
                           MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 2);

  const auto oldpath = in->next();
  const auto newpath = in->next();

  out->Push<int>(enc_untrusted_rename(oldpath.As<char>(), newpath.As<char>()));
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestRead(void *context, MessageReader *in, MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 2);
  int fd = in->next<int>();
  size_t count = in->next<size_t>();
  char read_buf[20];

  out->Push<ssize_t>(enc_untrusted_read(fd, read_buf, count));
  out->PushByCopy(Extent{read_buf, strlen(read_buf) + 1});
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestWrite(void *context, MessageReader *in,
                          MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 3);
  int fd = in->next<int>();
  const auto write_buf = in->next();
  size_t count = in->next<size_t>();

  out->Push<ssize_t>(enc_untrusted_write(fd, write_buf.As<char>(), count));
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestSymlink(void *context, MessageReader *in,
                            MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 2);
  const auto target = in->next();
  const auto linkpath = in->next();

  out->Push<ssize_t>(
      enc_untrusted_symlink(target.As<char>(), linkpath.As<char>()));
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestReadlink(void *context, MessageReader *in,
                             MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 1);
  const auto pathname = in->next();

  char buf[PATH_MAX];
  ssize_t len =
      enc_untrusted_readlink(pathname.As<char>(), buf, sizeof(buf) - 1);
  out->Push<ssize_t>(len);

  buf[len] = '\0';
  out->PushByCopy(Extent{buf, strlen(buf) + 1});
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestTruncate(void *context, MessageReader *in,
                             MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 2);
  const auto path = in->next();
  off_t length = in->next<off_t>();

  out->Push<int>(enc_untrusted_truncate(path.As<char>(), length));

  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestFTruncate(void *context, MessageReader *in,
                              MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 2);
  int fd = in->next<int>();
  auto length = in->next<off_t>();

  out->Push<int>(enc_untrusted_ftruncate(fd, length));

  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestRmdir(void *context, MessageReader *in,
                          MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 1);
  const auto path = in->next();

  out->Push<int>(enc_untrusted_rmdir(path.As<char>()));
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestPipe2(void *context, MessageReader *in,
                          MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 1);

  auto msg_to_pipe = in->next();
  int p[2];
  char inbuf[msg_to_pipe.size()];

  out->Push<int>(enc_untrusted_pipe2(p, O_NONBLOCK));
  enc_untrusted_write(p[1], msg_to_pipe.data(), msg_to_pipe.size());
  enc_untrusted_read(p[0], inbuf, msg_to_pipe.size());
  out->Push(std::string(inbuf, msg_to_pipe.size()));
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

PrimitiveStatus TestChmod(void *context, MessageReader *in,
                          MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 2);

  const auto path_name = in->next();
  mode_t mode = in->next<mode_t>();

  out->Push<int>(enc_untrusted_chmod(path_name.As<char>(), mode));
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
  out->Push<int>(enc_untrusted_isatty(fd));  // Push return value.

  int enclave_errno = errno;
  int klinux_errno;
  TokLinuxErrorNumber(&enclave_errno, &klinux_errno);
  out->Push<int>(klinux_errno);
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

PrimitiveStatus TestClose(void *context, MessageReader *in,
                          MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 1);

  int fd = in->next<int>();
  out->Push<int>(enc_untrusted_close(fd));
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestRealloc(void *context, MessageReader *in,
                            MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 2);
  auto ptr1 = in->next<void *>();
  auto size = static_cast<size_t>(in->next<uint64_t>());

  out->Push(reinterpret_cast<uint64_t>(enc_untrusted_realloc(ptr1, size)));
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestSleep(void *context, MessageReader *in,
                          MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 1);

  auto seconds = in->next<uint32_t>();
  out->Push<uint32_t>(enc_untrusted_sleep(seconds));
  return PrimitiveStatus::OkStatus();
}

}  // namespace
}  // namespace host_call
}  // namespace asylo

// Implements the required enclave initialization function.
extern "C" PrimitiveStatus asylo_enclave_init() {
  init_host_calls();

  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kAbortEnclaveSelector,
      EntryHandler{asylo::host_call::Abort}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestAccess,
      EntryHandler{asylo::host_call::TestAccess}));
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
      asylo::host_call::kTestPipe2, EntryHandler{asylo::host_call::TestPipe2}));
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
      asylo::host_call::kTestChmod, EntryHandler{asylo::host_call::TestChmod}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestFchmod,
      EntryHandler{asylo::host_call::TestFchmod}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestUmask, EntryHandler{asylo::host_call::TestUmask}));
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
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestClose, EntryHandler{asylo::host_call::TestClose}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestRealloc,
      EntryHandler{asylo::host_call::TestRealloc}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestSleep, EntryHandler{asylo::host_call::TestSleep}));

  return PrimitiveStatus::OkStatus();
}

// Implements the required enclave finalization function.
extern "C" PrimitiveStatus asylo_enclave_fini() {
  return PrimitiveStatus::OkStatus();
}
