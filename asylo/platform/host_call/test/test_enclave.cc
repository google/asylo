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
#include <netdb.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <vector>

#include "absl/base/macros.h"
#include "absl/status/status.h"
#include "asylo/platform/host_call/test/enclave_test_selectors.h"
#include "asylo/platform/host_call/trusted/host_call_dispatcher.h"
#include "asylo/platform/host_call/trusted/host_calls.h"
#include "asylo/platform/primitives/primitive_status.h"
#include "asylo/platform/primitives/trusted_primitives.h"
#include "asylo/platform/primitives/trusted_runtime.h"
#include "asylo/platform/primitives/util/message.h"
#include "asylo/platform/system_call/type_conversions/generated_types_functions.h"
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
  int klinux_sig = in->next<int>();
  absl::optional<int> sig = FromkLinuxSignalNumber(klinux_sig);
  if (!sig) {
    return {error::GoogleError::INVALID_ARGUMENT,
            "TestKill: Conversion from klinux_sig failed."};
  }

  out->Push<int>(enc_untrusted_kill(pid, *sig));
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
    absl::optional<int> flags = FromkLinuxFileStatusFlag(in->next<int>());
    absl::optional<int> mode = FromkLinuxFileModeFlag(in->next<mode_t>());

    if (!flags) {
      return {error::GoogleError::INVALID_ARGUMENT,
              "TestOpen: Conversion from klinux flags failed."};
    }

    if (!mode) {
      return {error::GoogleError::INVALID_ARGUMENT,
              "TestOpen: Conversion from klinux mode failed."};
    }

    out->Push<int>(enc_untrusted_open(pathname.As<char>(), *flags, *mode));
  } else if (in->size() == 2) {
    const auto pathname = in->next();
    absl::optional<int> flags = FromkLinuxFileStatusFlag(in->next<int>());
    if (!flags) {
      return {error::GoogleError::INVALID_ARGUMENT,
              "TestOpen: Conversion to flags failed."};
    }

    out->Push<int>(enc_untrusted_open(pathname.As<char>(), *flags));
  } else {
    return {primitives::AbslStatusCode::kInvalidArgument,
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

  out->Push<int64_t>(enc_untrusted_read(fd, read_buf, count));
  out->PushString(read_buf);
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestWrite(void *context, MessageReader *in,
                          MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 3);
  int fd = in->next<int>();
  const auto write_buf = in->next();
  size_t count = in->next<size_t>();

  out->Push<int64_t>(enc_untrusted_write(fd, write_buf.As<char>(), count));
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestSymlink(void *context, MessageReader *in,
                            MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 2);
  const auto target = in->next();
  const auto linkpath = in->next();

  out->Push<int64_t>(
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
  out->Push<int64_t>(len);

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
  std::vector<char> inbuf(msg_to_pipe.size());

  out->Push<int>(enc_untrusted_pipe2(p, O_NONBLOCK));
  enc_untrusted_write(p[1], msg_to_pipe.data(), msg_to_pipe.size());
  enc_untrusted_read(p[0], inbuf.data(), msg_to_pipe.size());
  out->PushString(inbuf.data(), msg_to_pipe.size());
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
  out->Push<int64_t>(enc_untrusted_send(sockfd, buf.As<char>(), len, flags));

  return primitives::PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestSendMsg(void *context, MessageReader *in,
                            MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 4);

  int sockfd = in->next<int>();
  const auto msg1 = in->next();
  const auto msg2 = in->next();
  int flags = in->next<int>();

  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));

  constexpr size_t kNumMsgs = 2;
  struct iovec msg_iov[kNumMsgs];
  memset(msg_iov, 0, sizeof(*msg_iov));
  msg_iov[0].iov_base =
      reinterpret_cast<void *>(const_cast<char *>(msg1.As<char>()));
  msg_iov[0].iov_len = msg1.size();
  msg_iov[1].iov_base =
      reinterpret_cast<void *>(const_cast<char *>(msg2.As<char>()));
  msg_iov[1].iov_len = msg2.size();

  msg.msg_iov = msg_iov;
  msg.msg_iovlen = kNumMsgs;

  out->Push<int64_t>(enc_untrusted_sendmsg(sockfd, &msg, flags));

  return primitives::PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestRecvMsg(void *context, MessageReader *in,
                            MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 4);

  int sockfd = in->next<int>();
  int msg1_size = in->next<int>();
  int msg2_size = in->next<int>();
  int flags = in->next<int>();

  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  struct iovec msg_iov[2];
  std::unique_ptr<char[]> msg1_buffer(new char[msg1_size]);
  std::unique_ptr<char[]> msg2_buffer(new char[msg2_size]);
  msg_iov[0].iov_base = msg1_buffer.get();
  msg_iov[0].iov_len = msg1_size;
  msg_iov[1].iov_base = msg2_buffer.get();
  msg_iov[1].iov_len = msg2_size;

  msg.msg_iov = msg_iov;
  msg.msg_iovlen = 2;
  out->Push<int64_t>(enc_untrusted_recvmsg(sockfd, &msg, flags));

  return primitives::PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestFcntl(void *context, MessageReader *in,
                          MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 3);

  int fd = in->next<int>();
  int cmd = in->next<int>();
  int arg = in->next<int>();
  absl::optional<int> result = enc_untrusted_fcntl(fd, cmd, arg);
  if (cmd == F_GETFL) {
    result = TokLinuxFileStatusFlag(*result);
  } else if (cmd == F_GETFD) {
    result = TokLinuxFDFlag(*result);
  }

  if (!result) {
    return {error::GoogleError::INVALID_ARGUMENT,
            "TestGetRusage: Conversion to klinux result failed."};
  }

  out->Push<int>(*result);

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

  absl::optional<int> optname = FromkLinuxOptionName(level, klinux_optname);
  if (!optname) {
    return {error::GoogleError::INVALID_ARGUMENT,
            "TestSetsockopt: Conversion from klinux_optname failed."};
  }
  out->Push<int>(enc_untrusted_setsockopt(sockfd, level, *optname,
                                          (void *)&option, sizeof(option)));

  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestFlock(void *context, MessageReader *in,
                          MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 2);

  int fd = in->next<int>();
  int kLinux_operation = in->next<int>();  // The operation is expected to be
                                           // a kLinux_ operation.
  absl::optional<int> operation = FromkLinuxFLockOperation(kLinux_operation);
  if (!operation) {
    return {error::GoogleError::INVALID_ARGUMENT,
            "TestFlock: Conversion from klinux_operation failed."};
  }
  out->Push<int>(enc_untrusted_flock(fd, *operation));

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
  absl::optional<int> flags = FromkLinuxInotifyFlag(kLinux_flags);
  if (!flags) {
    return {error::GoogleError::INVALID_ARGUMENT,
            "TestInotifyInit1: Conversion from klinux_flags failed."};
  }
  out->Push<int>(enc_untrusted_inotify_init1(*flags));
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestInotifyAddWatch(void *context, MessageReader *in,
                                    MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 3);

  int fd = in->next<int>();
  const auto pathname = in->next();
  int kLinux_mask = in->next<uint32_t>();  // The operation is expected to be
                                           // a kLinux_ operation.
  absl::optional<int> mask = FromkLinuxInotifyEventMask(kLinux_mask);
  if (!mask) {
    return {error::GoogleError::INVALID_ARGUMENT,
            "TestInotifyAddWatch: Conversion from klinux_mask failed."};
  }
  out->Push<int>(
      enc_untrusted_inotify_add_watch(fd, pathname.As<char>(), *mask));

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

PrimitiveStatus TestSchedGetAffinity(void *context, MessageReader *in,
                                     MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 2);

  auto pid = in->next<pid_t>();
  auto cpusetsize = in->next<size_t>();

  cpu_set_t mask;

  out->Push<int>(enc_untrusted_sched_getaffinity(pid, cpusetsize, &mask));

  for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
    if (CPU_ISSET(cpu, &mask)) {
      out->Push<int>(cpu);
    }
  }

  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestIsAtty(void *context, MessageReader *in,
                           MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 1);

  int fd = in->next<int>();
  out->Push<int>(enc_untrusted_isatty(fd));  // Push return value.

  absl::optional<int> klinux_errno = TokLinuxErrorNumber(errno);
  if (!klinux_errno) {
    return {error::GoogleError::INVALID_ARGUMENT,
            "TestIsAtty: Conversion to klinux_errno failed."};
  }
  out->Push<int>(*klinux_errno);
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
PrimitiveStatus PushStatAttributes(MessageWriter *out, struct stat *st) {
  int mode = st->st_mode;
  absl::optional<int> kLinux_mode = TokLinuxFileModeFlag(mode);
  if (!kLinux_mode) {
    return {error::GoogleError::INVALID_ARGUMENT,
            "PushStatAttributes: Conversion to kLinux_mode failed."};
  }

  out->Push<uint64_t>(st->st_atime);
  out->Push<int64_t>(st->st_blksize);
  out->Push<int64_t>(st->st_blocks);
  out->Push<uint64_t>(st->st_mtime);
  out->Push<uint64_t>(st->st_dev);
  out->Push<uint32_t>(st->st_gid);
  out->Push<uint64_t>(st->st_ino);
  out->Push<uint32_t>(*kLinux_mode);
  out->Push<uint64_t>(st->st_ctime);
  out->Push<uint64_t>(st->st_nlink);
  out->Push<uint64_t>(st->st_rdev);
  out->Push<int64_t>(st->st_size);
  out->Push<uint32_t>(st->st_uid);
  return PrimitiveStatus::OkStatus();
}

// Push meaningful stat attributes to MessageWriter.
PrimitiveStatus PushStatFsAttributes(MessageWriter *out, struct statfs *st) {
  absl::optional<int64_t> kLinux_flags = TokLinuxStatFsFlags(st->f_flags);
  if (!kLinux_flags) {
    return {error::GoogleError::INVALID_ARGUMENT,
            "PushStatFsAttributes: Conversion to kLinux_flags failed."};
  }
  out->Push<int64_t>(st->f_type);
  out->Push<int64_t>(st->f_bsize);
  out->Push<uint64_t>(st->f_blocks);
  out->Push<uint64_t>(st->f_bfree);
  out->Push<uint64_t>(st->f_bavail);
  out->Push<uint64_t>(st->f_files);
  out->Push<uint64_t>(st->f_ffree);
  out->Push<int32_t>(st->f_fsid.__val[0]);
  out->Push<int32_t>(st->f_fsid.__val[1]);
  out->Push<int64_t>(st->f_namelen);
  out->Push<int64_t>(st->f_frsize);
  out->Push<int64_t>(*kLinux_flags);
  for (int i = 0; i < ABSL_ARRAYSIZE(st->f_spare); ++i) {
    out->Push<int64_t>(st->f_spare[i]);
  }
  return PrimitiveStatus::OkStatus();
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

PrimitiveStatus TestFstatFs(void *context, MessageReader *in,
                            MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 1);

  struct statfs st;
  int fd = in->next<int>();
  out->Push<int>(enc_untrusted_fstatfs(fd, &st));
  return PushStatFsAttributes(out, &st);
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

PrimitiveStatus TestStatFs(void *context, MessageReader *in,
                           MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 1);

  struct statfs st;
  const auto path_name = in->next();
  out->Push<int>(enc_untrusted_statfs(path_name.As<char>(), &st));
  return PushStatFsAttributes(out, &st);
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

  int enclave_wstatus = 0;
  out->Push<int>(enc_untrusted_wait(&enclave_wstatus));

  if (!WIFEXITED(enclave_wstatus)) {
    return {primitives::AbslStatusCode::kInvalidArgument,
            "TestWait: Expected WIFEXITED to be true, found false."};
  }
  if (WEXITSTATUS(enclave_wstatus) != 0) {
    return {primitives::AbslStatusCode::kInvalidArgument,
            "TestWait: Found non-zero WEXITSTATUS."};
  }

  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestSysconf(void *context, MessageReader *in,
                            MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 1);

  int kLinux_name = in->next<int>();
  absl::optional<int> name = FromkLinuxSysconfConstant(kLinux_name);
  if (!name) {
    return {error::GoogleError::INVALID_ARGUMENT,
            "TestSysconf: Conversion from klinux_name failed."};
  }
  out->Push<int64_t>(enc_untrusted_sysconf(*name));
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

PrimitiveStatus TestNanosleep(void *context, MessageReader *in,
                              MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 1);
  auto klinux_req = in->next<struct kLinux_timespec>();

  struct timespec req, rem;
  FromkLinuxtimespec(&klinux_req, &req);
  out->Push<int>(enc_untrusted_nanosleep(&req, &rem));

  struct kLinux_timespec klinux_rem;
  TokLinuxtimespec(&rem, &klinux_rem);
  out->Push<struct kLinux_timespec>(klinux_rem);
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestClockGettime(void *context, MessageReader *in,
                                 MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 1);
  auto klinux_clk_id = in->next<clockid_t>();
  absl::optional<clockid_t> clk_id = FromkLinuxClockId(klinux_clk_id);
  if (!clk_id) {
    return {error::GoogleError::INVALID_ARGUMENT,
            "TestClockGettime: Conversion from klinux_clk_id failed."};
  }

  struct timespec tp;
  struct kLinux_timespec klinux_tp;
  out->Push<int>(enc_untrusted_clock_gettime(*clk_id, &tp));
  TokLinuxtimespec(&tp, &klinux_tp);
  out->Push<struct kLinux_timespec>(klinux_tp);
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestBind(void *context, MessageReader *in, MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 2);

  int sockfd = in->next<int>();
  struct klinux_sockaddr_un klinux_sock_un =
      in->next<struct klinux_sockaddr_un>();

  struct sockaddr_un sock_un;
  FromkLinuxSockAddrUn(&klinux_sock_un, &sock_un);
  out->Push<int>(enc_untrusted_bind(sockfd, (struct sockaddr *)&sock_un,
                                    sizeof(struct sockaddr_un)));
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestConnect(void *context, MessageReader *in,
                            MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 2);

  int sockfd = in->next<int>();
  struct klinux_sockaddr_un klinux_sock_un =
      in->next<struct klinux_sockaddr_un>();

  sockaddr_un sock_un = {};
  FromkLinuxSockAddrUn(&klinux_sock_un, &sock_un);
  out->Push<int>(enc_untrusted_connect(sockfd, (struct sockaddr *)&sock_un,
                                       sizeof(struct sockaddr_un)));
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestGetSockname(void *context, MessageReader *in,
                                MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 1);
  int sockfd = in->next<int>();

  sockaddr_un sock_un = {};
  socklen_t sock_un_len = sizeof(sock_un);

  out->Push<int>(enc_untrusted_getsockname(
      sockfd, reinterpret_cast<struct sockaddr *>(&sock_un), &sock_un_len));

  klinux_sockaddr_un klinux_sock_un = {};
  SockaddrTokLinuxSockaddrUn(reinterpret_cast<struct sockaddr *>(&sock_un),
                             sizeof(sock_un), &klinux_sock_un);
  out->Push<struct klinux_sockaddr_un>(klinux_sock_un);
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestAccept(void *context, MessageReader *in,
                           MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 1);
  int sockfd = in->next<int>();
  out->Push<int>(enc_untrusted_accept(sockfd, nullptr, nullptr));
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestSelect(void *context, MessageReader *in,
                           MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 2);

  int nfds = in->next<int>();
  auto klinux_rfds = in->next<struct klinux_fd_set>();
  fd_set rfds;
  FromkLinuxFdSet(&klinux_rfds, &rfds);

  struct timeval timeout;
  timeout.tv_sec = 10;
  timeout.tv_usec = 0;

  out->Push<int>(enc_untrusted_select(nfds, &rfds, nullptr, nullptr, &timeout));
  TokLinuxFdSet(&rfds, &klinux_rfds);
  out->Push<struct klinux_fd_set>(klinux_rfds);

  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestFsync(void *context, MessageReader *in,
                          MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 1);

  int fd = in->next<int>();
  out->Push<int>(enc_untrusted_fsync(fd));

  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestRaise(void *context, MessageReader *in,
                          MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 1);

  int klinux_sig = in->next<int>();
  absl::optional<int> sig = FromkLinuxSignalNumber(klinux_sig);
  if (!sig) {
    return {error::GoogleError::INVALID_ARGUMENT,
            "TestRaise: Conversion from klinux_sig failed."};
  }
  out->Push<int>(enc_untrusted_raise(*sig));
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestGetSockOpt(void *context, MessageReader *in,
                               MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 1);

  int socket_fd = in->next<int>();
  int optval_actual = -1;
  socklen_t optlen_actual = sizeof(optlen_actual);
  out->Push<int>(enc_untrusted_getsockopt(socket_fd, SOL_SOCKET, SO_KEEPALIVE,
                                          &optval_actual, &optlen_actual));
  out->Push<int>(optval_actual);
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestGetAddrInfo(void *context, MessageReader *in,
                                MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 1);
  auto node_buffer = in->next();

  struct addrinfo *result;
  out->Push<int>(enc_untrusted_getaddrinfo(node_buffer.As<char>(), nullptr,
                                           nullptr, &result));

  // Convert sockaddrs from addrinfo to linux_sockaddrs and push to |out|.
  for (struct addrinfo *res = result; res != nullptr; res = res->ai_next) {
    socklen_t klinux_sock_len = std::max(
        std::max(sizeof(klinux_sockaddr_un), sizeof(klinux_sockaddr_in)),
        sizeof(klinux_sockaddr_in6));
    auto klinux_sock = absl::make_unique<char[]>(klinux_sock_len);

    if (!TokLinuxSockAddr(
            res->ai_addr, res->ai_addrlen,
            reinterpret_cast<klinux_sockaddr *>(klinux_sock.get()),
            &klinux_sock_len, TrustedPrimitives::BestEffortAbort)) {
      return {primitives::AbslStatusCode::kInvalidArgument,
              "TestGetAddrInfo: Couldn't convert sockaddr to klinux_sockaddr"};
    }

    out->PushByCopy(Extent{klinux_sock.get(), klinux_sock_len});
  }

  enc_freeaddrinfo(result);
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestPoll(void *context, MessageReader *in, MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 3);
  auto klinux_pollfd_buffer = in->next();
  struct klinux_pollfd *klinux_fds = klinux_pollfd_buffer.As<klinux_pollfd>();
  auto nfds = in->next<nfds_t>();
  int timeout = in->next<int>();

  struct pollfd fds[2];
  if (!FromkLinuxPollfd(klinux_fds, &fds[0]) ||
      !FromkLinuxPollfd(klinux_fds + 1, &fds[1])) {
    return {primitives::AbslStatusCode::kInvalidArgument,
            "TestPoll: Couldn't convert klinux_pollfd to native pollfd"};
  }
  out->Push<int>(enc_untrusted_poll(fds, nfds, timeout));

  if (!TokLinuxPollfd(&fds[0], &klinux_fds[0]) ||
      !TokLinuxPollfd(&fds[1], &klinux_fds[1])) {
    return {primitives::AbslStatusCode::kInvalidArgument,
            "TestPoll: Couldn't convert native pollfd to kernel pollfd"};
  }
  out->PushByCopy(Extent{klinux_fds, klinux_pollfd_buffer.size()});
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestUtime(void *context, MessageReader *in,
                          MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 2);
  auto file_buf = in->next();
  auto klinux_times = in->next<struct kLinux_utimbuf>();

  struct utimbuf times {};
  if (!FromkLinuxutimbuf(&klinux_times, &times)) {
    return {primitives::AbslStatusCode::kInvalidArgument,
            "TestUtime: Couldn't convert klinux_utimbuf to native utimbuf"};
  }
  out->Push<int>(enc_untrusted_utime(file_buf.As<char>(), &times));
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestGetRusage(void *context, MessageReader *in,
                              MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 1);
  int klinux_who = in->next<int>();

  absl::optional<int> who = FromkLinuxRusageTarget(klinux_who);
  if (!who) {
    return {error::GoogleError::INVALID_ARGUMENT,
            "TestGetRusage: Conversion from klinux_who failed."};
  }

  struct rusage usage {};
  struct klinux_rusage klinux_usage {};
  out->Push<int>(enc_untrusted_getrusage(*who, &usage));

  if (!TokLinuxRusage(&usage, &klinux_usage)) {
    return {primitives::AbslStatusCode::kInvalidArgument,
            "TestGetRusage: Conversion to klinux_rusage failed."};
  }
  out->Push<struct klinux_rusage>(klinux_usage);
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestXattr(void *context, MessageReader *in,
                          MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 3);
  const auto file_path = in->next();
  const auto xattr_name = in->next();
  const auto xattr_value = in->next();

  out->Push<int>(enc_untrusted_setxattr(
      file_path.As<char>(), xattr_name.As<char>(), xattr_value.As<char>(),
      strlen(xattr_value.As<char>()), 0));
  char name_buf[16];
  out->Push<ssize_t>(enc_untrusted_listxattr(file_path.As<char>(), name_buf,
                                             sizeof(name_buf)));
  char value_buf[16];
  out->Push<ssize_t>(enc_untrusted_getxattr(file_path.As<char>(), name_buf,
                                            value_buf, sizeof(value_buf)));
  out->PushString(name_buf);
  out->PushString(value_buf);
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestLXattr(void *context, MessageReader *in,
                           MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 3);
  const auto file_path = in->next();
  const auto xattr_name = in->next();
  const auto xattr_value = in->next();

  out->Push<int>(enc_untrusted_lsetxattr(
      file_path.As<char>(), xattr_name.As<char>(), xattr_value.As<char>(),
      strlen(xattr_value.As<char>()), 0));
  char name_buf[16];
  out->Push<ssize_t>(enc_untrusted_llistxattr(file_path.As<char>(), name_buf,
                                              sizeof(name_buf)));
  char value_buf[16];
  out->Push<ssize_t>(enc_untrusted_lgetxattr(file_path.As<char>(), name_buf,
                                             value_buf, sizeof(value_buf)));
  out->PushString(name_buf);
  out->PushString(value_buf);
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestFXattr(void *context, MessageReader *in,
                           MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 3);
  int fd = in->next<int>();
  const auto xattr_name = in->next();
  const auto xattr_value = in->next();

  out->Push<int>(enc_untrusted_fsetxattr(fd, xattr_name.As<char>(),
                                         xattr_value.As<char>(),
                                         strlen(xattr_value.As<char>()), 0));
  char name_buf[16];
  out->Push<ssize_t>(enc_untrusted_flistxattr(fd, name_buf, sizeof(name_buf)));
  char value_buf[16];
  out->Push<ssize_t>(
      enc_untrusted_fgetxattr(fd, name_buf, value_buf, sizeof(value_buf)));
  out->PushString(name_buf);
  out->PushString(value_buf);
  return PrimitiveStatus::OkStatus();
}

}  // namespace
}  // namespace host_call
}  // namespace asylo

// Implements the required enclave initialization function.
extern "C" PrimitiveStatus asylo_enclave_init() {
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
      asylo::host_call::kTestSendMsg,
      EntryHandler{asylo::host_call::TestSendMsg}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestRecvMsg,
      EntryHandler{asylo::host_call::TestRecvMsg}));
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
      asylo::host_call::kTestSchedGetAffinity,
      EntryHandler{asylo::host_call::TestSchedGetAffinity}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestIsAtty,
      EntryHandler{asylo::host_call::TestIsAtty}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestUSleep,
      EntryHandler{asylo::host_call::TestUSleep}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestFstat, EntryHandler{asylo::host_call::TestFstat}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestFstatFs,
      EntryHandler{asylo::host_call::TestFstatFs}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestLstat, EntryHandler{asylo::host_call::TestLstat}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestStat, EntryHandler{asylo::host_call::TestStat}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestStatFs,
      EntryHandler{asylo::host_call::TestStatFs}));
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
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestNanosleep,
      EntryHandler{asylo::host_call::TestNanosleep}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestClockGettime,
      EntryHandler{asylo::host_call::TestClockGettime}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestBind, EntryHandler{asylo::host_call::TestBind}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestConnect,
      EntryHandler{asylo::host_call::TestConnect}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestGetSockname,
      EntryHandler{asylo::host_call::TestGetSockname}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestAccept,
      EntryHandler{asylo::host_call::TestAccept}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestSelect,
      EntryHandler{asylo::host_call::TestSelect}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestFsync, EntryHandler{asylo::host_call::TestFsync}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestRaise, EntryHandler{asylo::host_call::TestRaise}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestGetSockOpt,
      EntryHandler{asylo::host_call::TestGetSockOpt}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestGetAddrInfo,
      EntryHandler{asylo::host_call::TestGetAddrInfo}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestPoll, EntryHandler{asylo::host_call::TestPoll}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestUtime, EntryHandler{asylo::host_call::TestUtime}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestGetRusage,
      EntryHandler{asylo::host_call::TestGetRusage}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestXattr, EntryHandler{asylo::host_call::TestXattr}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestLXattr,
      EntryHandler{asylo::host_call::TestLXattr}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestFXattr,
      EntryHandler{asylo::host_call::TestFXattr}));

  return PrimitiveStatus::OkStatus();
}

// Implements the required enclave finalization function.
extern "C" PrimitiveStatus asylo_enclave_fini() {
  return PrimitiveStatus::OkStatus();
}
