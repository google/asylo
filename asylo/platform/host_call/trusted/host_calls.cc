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

#include "asylo/platform/host_call/trusted/host_calls.h"

#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <signal.h>
#include <sys/statfs.h>

#include <algorithm>

#include "asylo/platform/host_call/exit_handler_constants.h"
#include "asylo/platform/host_call/serializer_functions.h"
#include "asylo/platform/primitives/trusted_primitives.h"
#include "asylo/platform/system_call/type_conversions/types_functions.h"

using ::asylo::host_call::NonSystemCallDispatcher;
using ::asylo::primitives::Extent;
using ::asylo::primitives::MessageReader;
using ::asylo::primitives::MessageWriter;
using ::asylo::primitives::TrustedPrimitives;

void CheckStatusAndParamCount(const asylo::primitives::PrimitiveStatus &status,
                              const MessageReader &output, const char *name,
                              int expected_params, bool match_exact_params) {
  if (!status.ok()) {
    std::string message = absl::StrCat("Host call '", name, "' failed.");
    TrustedPrimitives::BestEffortAbort(message.c_str());
  }

  if (!match_exact_params) {
    if (output.size() < expected_params) {
      std::string message = absl::StrCat(
          "Host call '", name, "': Expected at least ", expected_params,
          " parameters on the MessageReader, found ", output.size());
      TrustedPrimitives::BestEffortAbort(message.c_str());
    }
  } else {
    if (output.size() != expected_params) {
      std::string message = absl::StrCat(
          "Host call '", name, "': Expected ", expected_params,
          " parameters on the MessageReader, found ", output.size());
      TrustedPrimitives::BestEffortAbort(message.c_str());
    }
  }
}

namespace {

// A global passwd struct. The address of it is used as the return value of
// getpwuid.
struct passwd global_passwd;

size_t CalculateTotalMessageSize(const struct msghdr *msg) {
  size_t total_message_size = 0;
  for (int i = 0; i < msg->msg_iovlen; ++i) {
    total_message_size += msg->msg_iov[i].iov_len;
  }
  return total_message_size;
}

#define PASSWD_HOLDER_FIELD_LENGTH 1024

// Struct for storing the buffers needed by struct passwd members.
struct passwd_holder {
  char pw_name[PASSWD_HOLDER_FIELD_LENGTH];
  char pw_passwd[PASSWD_HOLDER_FIELD_LENGTH];
  uid_t pw_uid;
  gid_t pw_gid;
  char pw_gecos[PASSWD_HOLDER_FIELD_LENGTH];
  char pw_dir[PASSWD_HOLDER_FIELD_LENGTH];
  char pw_shell[PASSWD_HOLDER_FIELD_LENGTH];
};

bool DeserializePasswd(MessageReader *reader,
                       struct passwd_holder *passwd_buffers) {
  if (!reader || !passwd_buffers) {
    return false;
  }
  if (reader->size() < 7) {
    return false;
  }

  auto pw_name_buf = reader->next();
  auto pw_passwd_buf = reader->next();
  auto pw_uid = reader->next<uid_t>();
  auto pw_gid = reader->next<gid_t>();
  auto pw_gecos_buf = reader->next();
  auto pw_dir_buf = reader->next();
  auto pw_shell_buf = reader->next();

  strncpy(passwd_buffers->pw_name, pw_name_buf.As<char>(),
          std::min(sizeof(passwd_buffers->pw_name), pw_name_buf.size()));
  strncpy(passwd_buffers->pw_passwd, pw_passwd_buf.As<char>(),
          std::min(sizeof(passwd_buffers->pw_passwd), pw_passwd_buf.size()));
  passwd_buffers->pw_uid = pw_uid;
  passwd_buffers->pw_gid = pw_gid;
  strncpy(passwd_buffers->pw_gecos, pw_gecos_buf.As<char>(),
          std::min(sizeof(passwd_buffers->pw_gecos), pw_gecos_buf.size()));
  strncpy(passwd_buffers->pw_dir, pw_dir_buf.As<char>(),
          std::min(sizeof(passwd_buffers->pw_dir), pw_dir_buf.size()));
  strncpy(passwd_buffers->pw_shell, pw_shell_buf.As<char>(),
          std::min(sizeof(passwd_buffers->pw_shell), pw_shell_buf.size()));
  return true;
}

bool PasswdHolderToPasswd(struct passwd_holder *passwd_in,
                          struct passwd *passwd_out) {
  if (!passwd_in || !passwd_out) {
    return false;
  }

  passwd_out->pw_name = passwd_in->pw_name;
  passwd_out->pw_passwd = passwd_in->pw_passwd;
  passwd_out->pw_uid = passwd_in->pw_uid;
  passwd_out->pw_gid = passwd_in->pw_gid;
  passwd_out->pw_gecos = passwd_in->pw_gecos;
  passwd_out->pw_dir = passwd_in->pw_dir;
  passwd_out->pw_shell = passwd_in->pw_shell;
  return true;
}

}  // namespace

extern "C" {

int enc_untrusted_access(const char *path_name, int mode) {
  return EnsureInitializedAndDispatchSyscall(asylo::system_call::kSYS_access,
                                             path_name, mode);
}

pid_t enc_untrusted_getpid() {
  return EnsureInitializedAndDispatchSyscall(asylo::system_call::kSYS_getpid);
}

pid_t enc_untrusted_getppid() {
  return EnsureInitializedAndDispatchSyscall(asylo::system_call::kSYS_getppid);
}

pid_t enc_untrusted_setsid() {
  return EnsureInitializedAndDispatchSyscall(asylo::system_call::kSYS_setsid);
}

uid_t enc_untrusted_getuid() {
  return EnsureInitializedAndDispatchSyscall(asylo::system_call::kSYS_getuid);
}

gid_t enc_untrusted_getgid() {
  return EnsureInitializedAndDispatchSyscall(asylo::system_call::kSYS_getgid);
}

uid_t enc_untrusted_geteuid() {
  return EnsureInitializedAndDispatchSyscall(asylo::system_call::kSYS_geteuid);
}

gid_t enc_untrusted_getegid() {
  return EnsureInitializedAndDispatchSyscall(asylo::system_call::kSYS_getegid);
}

int enc_untrusted_kill(pid_t pid, int sig) {
  int klinux_sig = TokLinuxSignalNumber(sig);
  if (klinux_sig < 0) {
    errno = EINVAL;
    return -1;
  }

  return EnsureInitializedAndDispatchSyscall(asylo::system_call::kSYS_kill, pid,
                                             klinux_sig);
}

int enc_untrusted_link(const char *oldpath, const char *newpath) {
  return EnsureInitializedAndDispatchSyscall(asylo::system_call::kSYS_link,
                                             oldpath, newpath);
}

off_t enc_untrusted_lseek(int fd, off_t offset, int whence) {
  return EnsureInitializedAndDispatchSyscall(asylo::system_call::kSYS_lseek, fd,
                                             offset, whence);
}

int enc_untrusted_mkdir(const char *pathname, mode_t mode) {
  return EnsureInitializedAndDispatchSyscall(asylo::system_call::kSYS_mkdir,
                                             pathname, mode);
}

int enc_untrusted_open(const char *pathname, int flags, ...) {
  int mode = 0;
  if (flags & O_CREAT) {
    va_list ap;
    va_start(ap, flags);
    mode = va_arg(ap, mode_t);
    va_end(ap);
  }

  return EnsureInitializedAndDispatchSyscall(
      asylo::system_call::kSYS_open, pathname, TokLinuxFileStatusFlag(flags),
      TokLinuxFileModeFlag(mode));
}

int enc_untrusted_unlink(const char *pathname) {
  return EnsureInitializedAndDispatchSyscall(asylo::system_call::kSYS_unlink,
                                             pathname);
}

int enc_untrusted_rename(const char *oldpath, const char *newpath) {
  return EnsureInitializedAndDispatchSyscall(asylo::system_call::kSYS_rename,
                                             oldpath, newpath);
}

ssize_t enc_untrusted_read(int fd, void *buf, size_t count) {
  return static_cast<ssize_t>(EnsureInitializedAndDispatchSyscall(
      asylo::system_call::kSYS_read, fd, buf, count));
}

ssize_t enc_untrusted_write(int fd, const void *buf, size_t count) {
  return static_cast<ssize_t>(EnsureInitializedAndDispatchSyscall(
      asylo::system_call::kSYS_write, fd, buf, count));
}

int enc_untrusted_symlink(const char *target, const char *linkpath) {
  return EnsureInitializedAndDispatchSyscall(asylo::system_call::kSYS_symlink,
                                             target, linkpath);
}

ssize_t enc_untrusted_readlink(const char *pathname, char *buf, size_t bufsiz) {
  return static_cast<ssize_t>(EnsureInitializedAndDispatchSyscall(
      asylo::system_call::kSYS_readlink, pathname, buf, bufsiz));
}

int enc_untrusted_truncate(const char *path, off_t length) {
  return EnsureInitializedAndDispatchSyscall(asylo::system_call::kSYS_truncate,
                                             path, length);
}

int enc_untrusted_ftruncate(int fd, off_t length) {
  return EnsureInitializedAndDispatchSyscall(asylo::system_call::kSYS_ftruncate,
                                             fd, length);
}

int enc_untrusted_rmdir(const char *path) {
  return EnsureInitializedAndDispatchSyscall(asylo::system_call::kSYS_rmdir,
                                             path);
}

int enc_untrusted_pipe2(int pipefd[2], int flags) {
  if (flags & ~(O_CLOEXEC | O_DIRECT | O_NONBLOCK)) {
    errno = EINVAL;
    return -1;
  }

  return EnsureInitializedAndDispatchSyscall(
      asylo::system_call::kSYS_pipe2, pipefd, TokLinuxFileStatusFlag(flags));
}

int enc_untrusted_socket(int domain, int type, int protocol) {
  return EnsureInitializedAndDispatchSyscall(
      asylo::system_call::kSYS_socket, TokLinuxAfFamily(domain),
      TokLinuxSocketType(type), protocol);
}

int enc_untrusted_listen(int sockfd, int backlog) {
  return EnsureInitializedAndDispatchSyscall(asylo::system_call::kSYS_listen,
                                             sockfd, backlog);
}

int enc_untrusted_shutdown(int sockfd, int how) {
  return EnsureInitializedAndDispatchSyscall(asylo::system_call::kSYS_shutdown,
                                             sockfd, how);
}

ssize_t enc_untrusted_send(int sockfd, const void *buf, size_t len, int flags) {
  return EnsureInitializedAndDispatchSyscall(asylo::system_call::kSYS_sendto,
                                             sockfd, buf, len, flags,
                                             /*dest_addr=*/nullptr,
                                             /*addrlen=*/0);
}

int enc_untrusted_fcntl(int fd, int cmd, ... /* arg */) {
  // We do not currently support file locks in Asylo, so arg is not expected to
  // be a pointer to struct flock.
  int64_t arg = 0;
  va_list ap;
  va_start(ap, cmd);
  arg = va_arg(ap, int64_t);
  va_end(ap);

  int klinux_cmd = TokLinuxFcntlCommand(cmd);
  if (klinux_cmd == -1) {
    errno = EINVAL;
    return -1;
  }

  int intarg = arg;
  switch (cmd) {
    case F_SETFL: {
      return EnsureInitializedAndDispatchSyscall(
          asylo::system_call::kSYS_fcntl, fd, klinux_cmd,
          TokLinuxFileStatusFlag(intarg));
    }
    case F_SETFD: {
      return EnsureInitializedAndDispatchSyscall(asylo::system_call::kSYS_fcntl,
                                                 fd, klinux_cmd,
                                                 TokLinuxFDFlag(intarg));
    }
    case F_GETFL: {
      int retval = EnsureInitializedAndDispatchSyscall(
          asylo::system_call::kSYS_fcntl, fd, klinux_cmd, arg);
      if (retval != -1) {
        retval = FromkLinuxFileStatusFlag(retval);
      }

      return retval;
    }
    case F_GETFD: {
      int retval = EnsureInitializedAndDispatchSyscall(
          asylo::system_call::kSYS_fcntl, fd, klinux_cmd, arg);
      if (retval != -1) {
        retval = FromkLinuxFDFlag(retval);
      }
      return retval;
    }
    case F_GETPIPE_SZ:
    case F_SETPIPE_SZ: {
      return EnsureInitializedAndDispatchSyscall(asylo::system_call::kSYS_fcntl,
                                                 fd, klinux_cmd, arg);
    }
    // We do not handle the case for F_DUPFD. It is expected to be handled at
    // a higher abstraction, as we need not exit the enclave for duplicating
    // the file descriptor.
    default: {
      errno = EINVAL;
      return -1;
    }
  }
}

int enc_untrusted_chown(const char *pathname, uid_t owner, gid_t group) {
  return EnsureInitializedAndDispatchSyscall(asylo::system_call::kSYS_chown,
                                             pathname, owner, group);
}

int enc_untrusted_fchown(int fd, uid_t owner, gid_t group) {
  return EnsureInitializedAndDispatchSyscall(asylo::system_call::kSYS_fchown,
                                             fd, owner, group);
}

int enc_untrusted_setsockopt(int sockfd, int level, int optname,
                             const void *optval, socklen_t optlen) {
  return EnsureInitializedAndDispatchSyscall(
      asylo::system_call::kSYS_setsockopt, sockfd, level,
      TokLinuxOptionName(level, optname), optval, optlen);
}

int enc_untrusted_flock(int fd, int operation) {
  return EnsureInitializedAndDispatchSyscall(asylo::system_call::kSYS_flock, fd,
                                             TokLinuxFLockOperation(operation));
}

int enc_untrusted_wait(int *wstatus) {
  int klinux_wstatus;
  pid_t ret = EnsureInitializedAndDispatchSyscall(
      asylo::system_call::kSYS_wait4, /*wpid=*/-1, &klinux_wstatus,
      /*options=*/0,
      /*rusage=*/nullptr);
  *wstatus = FromkLinuxToNewlibWstatus(klinux_wstatus);
  return ret;
}

int enc_untrusted_inotify_init1(int flags) {
  return EnsureInitializedAndDispatchSyscall(
      asylo::system_call::kSYS_inotify_init1, TokLinuxInotifyFlag(flags));
}

int enc_untrusted_inotify_add_watch(int fd, const char *pathname,
                                    uint32_t mask) {
  return EnsureInitializedAndDispatchSyscall(
      asylo::system_call::kSYS_inotify_add_watch, fd, pathname,
      TokLinuxInotifyEventMask(mask));
}

int enc_untrusted_inotify_rm_watch(int fd, int wd) {
  return EnsureInitializedAndDispatchSyscall(
      asylo::system_call::kSYS_inotify_rm_watch, fd, wd);
}

mode_t enc_untrusted_umask(mode_t mask) {
  return EnsureInitializedAndDispatchSyscall(asylo::system_call::kSYS_umask,
                                             mask);
}

int enc_untrusted_chmod(const char *path_name, mode_t mode) {
  return EnsureInitializedAndDispatchSyscall(asylo::system_call::kSYS_chmod,
                                             path_name, mode);
}

int enc_untrusted_fchmod(int fd, mode_t mode) {
  return EnsureInitializedAndDispatchSyscall(asylo::system_call::kSYS_fchmod,
                                             fd, mode);
}

int enc_untrusted_sched_yield() {
  return EnsureInitializedAndDispatchSyscall(
      asylo::system_call::kSYS_sched_yield);
}

int enc_untrusted_sched_getaffinity(pid_t pid, size_t cpusetsize,
                                    cpu_set_t *mask) {
  klinux_cpu_set_t klinux_mask{};
  int result = EnsureInitializedAndDispatchSyscall(
      asylo::system_call::kSYS_sched_getaffinity, pid,
      static_cast<uint64_t>(cpusetsize), &klinux_mask);
  // On success, the raw getaffinity syscall returns the size of the cpumask_t
  // data type, To mimic the glibc behavior, we return 0 on success and -1 on
  // failure. See https://linux.die.net/man/2/sched_getaffinity, under "notes".
  if (result < 0) {
    return -1;
  }
  if (!FromkLinuxCpuSet(&klinux_mask, mask)) {
    errno = EFAULT;
    return -1;
  }
  return 0;
}

int enc_untrusted_pread64(int fd, void *buf, size_t count, off_t offset) {
  return EnsureInitializedAndDispatchSyscall(asylo::system_call::kSYS_pread64,
                                             fd, buf, count, offset);
}

int enc_untrusted_pwrite64(int fd, const void *buf, size_t count,
                           off_t offset) {
  return EnsureInitializedAndDispatchSyscall(asylo::system_call::kSYS_pwrite64,
                                             fd, buf, count, offset);
}

int enc_untrusted_isatty(int fd) {
  MessageWriter input;
  input.Push(fd);
  MessageReader output;
  const auto status = NonSystemCallDispatcher(
      ::asylo::host_call::kIsAttyHandler, &input, &output);
  CheckStatusAndParamCount(status, output, "enc_untrusted_isatty", 2);

  int result = output.next<int>();

  // isatty() returns 1 if fd is an open file descriptor referring to a
  // terminal; otherwise 0 is returned, and errno is set to indicate the error.
  if (result == 0) {
    int klinux_errno = output.next<int>();
    errno = FromkLinuxErrorNumber(klinux_errno);
  }
  return result;
}

int enc_untrusted_usleep(useconds_t usec) {
  MessageWriter input;
  input.Push(usec);
  MessageReader output;
  asylo::primitives::PrimitiveStatus status =
      asylo::host_call::NonSystemCallDispatcher(
          asylo::host_call::kUSleepHandler, &input, &output);
  CheckStatusAndParamCount(status, output, "enc_untrusted_usleep", 2);

  int result = output.next<int>();
  int klinux_errno = output.next<int>();

  // usleep() returns 0 on success. On error, -1 is returned, with errno set to
  // indicate the cause of the error.
  if (result == -1) {
    errno = FromkLinuxErrorNumber(klinux_errno);
  }

  return result;
}

int enc_untrusted_fstat(int fd, struct stat *statbuf) {
  struct klinux_stat stat_kernel;
  int result = EnsureInitializedAndDispatchSyscall(
      asylo::system_call::kSYS_fstat, fd, &stat_kernel);

  if (FromkLinuxStat(&stat_kernel, statbuf)) {
    statbuf->st_mode = FromkLinuxFileModeFlag(stat_kernel.klinux_st_mode);
  }
  return result;
}

int enc_untrusted_fstatfs(int fd, struct statfs *statbuf) {
  struct klinux_statfs statfs_kernel;
  int result = EnsureInitializedAndDispatchSyscall(
      asylo::system_call::kSYS_fstatfs, fd, &statfs_kernel);

  if (FromkLinuxStatFs(&statfs_kernel, statbuf)) {
    statbuf->f_flags = FromkLinuxStatFsFlags(statfs_kernel.klinux_f_flags);
  }
  return result;
}

int enc_untrusted_lstat(const char *pathname, struct stat *statbuf) {
  struct klinux_stat stat_kernel;
  int result = EnsureInitializedAndDispatchSyscall(
      asylo::system_call::kSYS_lstat, pathname, &stat_kernel);

  if (FromkLinuxStat(&stat_kernel, statbuf)) {
    statbuf->st_mode = FromkLinuxFileModeFlag(stat_kernel.klinux_st_mode);
  }
  return result;
}

int enc_untrusted_stat(const char *pathname, struct stat *statbuf) {
  struct klinux_stat stat_kernel;
  int result = EnsureInitializedAndDispatchSyscall(
      asylo::system_call::kSYS_stat, pathname, &stat_kernel);
  if (FromkLinuxStat(&stat_kernel, statbuf)) {
    statbuf->st_mode = FromkLinuxFileModeFlag(stat_kernel.klinux_st_mode);
  }
  return result;
}

int enc_untrusted_statfs(const char *pathname, struct statfs *statbuf) {
  struct klinux_statfs statfs_kernel;
  int result = EnsureInitializedAndDispatchSyscall(
      asylo::system_call::kSYS_statfs, pathname, &statfs_kernel);

  if (FromkLinuxStatFs(&statfs_kernel, statbuf)) {
    statbuf->f_flags = FromkLinuxStatFsFlags(statfs_kernel.klinux_f_flags);
  }
  return result;
}

ssize_t enc_untrusted_getxattr(const char *path, const char *name, void *value,
                               size_t size) {
  return EnsureInitializedAndDispatchSyscall(asylo::system_call::kSYS_getxattr,
                                             path, name, value, size);
}

ssize_t enc_untrusted_lgetxattr(const char *path, const char *name, void *value,
                                size_t size) {
  return EnsureInitializedAndDispatchSyscall(asylo::system_call::kSYS_lgetxattr,
                                             path, name, value, size);
}

ssize_t enc_untrusted_fgetxattr(int fd, const char *name, void *value,
                                size_t size) {
  return EnsureInitializedAndDispatchSyscall(asylo::system_call::kSYS_fgetxattr,
                                             fd, name, value, size);
}

int enc_untrusted_setxattr(const char *path, const char *name,
                           const void *value, size_t size, int flags) {
  return EnsureInitializedAndDispatchSyscall(asylo::system_call::kSYS_setxattr,
                                             path, name, value, size, flags);
}

int enc_untrusted_lsetxattr(const char *path, const char *name,
                            const void *value, size_t size, int flags) {
  return EnsureInitializedAndDispatchSyscall(asylo::system_call::kSYS_lsetxattr,
                                             path, name, value, size, flags);
}

int enc_untrusted_fsetxattr(int fd, const char *name, const void *value,
                            size_t size, int flags) {
  return EnsureInitializedAndDispatchSyscall(asylo::system_call::kSYS_fsetxattr,
                                             fd, name, value, size, flags);
}

ssize_t enc_untrusted_listxattr(const char *path, char *list, size_t size) {
  return EnsureInitializedAndDispatchSyscall(asylo::system_call::kSYS_listxattr,
                                             path, list, size);
}

ssize_t enc_untrusted_llistxattr(const char *path, char *list, size_t size) {
  return EnsureInitializedAndDispatchSyscall(
      asylo::system_call::kSYS_llistxattr, path, list, size);
}

ssize_t enc_untrusted_flistxattr(int fd, char *list, size_t size) {
  return EnsureInitializedAndDispatchSyscall(
      asylo::system_call::kSYS_flistxattr, fd, list, size);
}

int64_t enc_untrusted_sysconf(int name) {
  int kLinux_name = TokLinuxSysconfConstant(name);
  if (kLinux_name == -1) {
    errno = EINVAL;
    return -1;
  }

  MessageWriter input;
  input.Push(kLinux_name);
  MessageReader output;
  asylo::primitives::PrimitiveStatus status =
      asylo::host_call::NonSystemCallDispatcher(
          asylo::host_call::kSysconfHandler, &input, &output);
  CheckStatusAndParamCount(status, output, "enc_untrusted_sysconf", 2);

  int64_t result = output.next<int>();
  int klinux_errno = output.next<int>();
  if (result == -1) {
    errno = FromkLinuxErrorNumber(klinux_errno);
  }

  return result;
}

int enc_untrusted_close(int fd) {
  return EnsureInitializedAndDispatchSyscall(asylo::system_call::kSYS_close,
                                             fd);
}

void *enc_untrusted_realloc(void *ptr, size_t size) {
  MessageWriter input;
  input.Push(reinterpret_cast<uint64_t>(ptr));
  input.Push(static_cast<uint64_t>(size));

  MessageReader output;
  asylo::primitives::PrimitiveStatus status =
      asylo::host_call::NonSystemCallDispatcher(
          asylo::host_call::kReallocHandler, &input, &output);
  CheckStatusAndParamCount(status, output, "enc_untrusted_realloc", 2);

  void *result = output.next<void *>();
  int klinux_errno = output.next<int>();

  // realloc only sets the errno (ENOMEM) when output pointer is null and a
  // non-zero |size| is provided.
  if (!result && size != 0) {
    errno = FromkLinuxErrorNumber(klinux_errno);
  }

  if (!::asylo::primitives::TrustedPrimitives::IsOutsideEnclave(result, size)) {
    ::asylo::primitives::TrustedPrimitives::BestEffortAbort(
        "enc_untrusted_realloc: realloc result should be in untrusted "
        "memory");
  }
  return result;
}

uint32_t enc_untrusted_sleep(uint32_t seconds) {
  MessageWriter input;
  input.Push<uint32_t>(seconds);
  MessageReader output;
  asylo::primitives::PrimitiveStatus status =
      asylo::host_call::NonSystemCallDispatcher(asylo::host_call::kSleepHandler,
                                                &input, &output);
  CheckStatusAndParamCount(status, output, "enc_untrusted_sleep", 2);

  // Returns sleep's return value directly since it doesn't set errno.
  return output.next<uint32_t>();
}

int enc_untrusted_nanosleep(const struct timespec *req, struct timespec *rem) {
  struct kLinux_timespec klinux_req;
  if (!TokLinuxtimespec(req, &klinux_req)) {
    errno = EINVAL;
    return -1;
  }
  struct kLinux_timespec klinux_rem;

  int result = EnsureInitializedAndDispatchSyscall(
      asylo::system_call::kSYS_nanosleep, &klinux_req, &klinux_rem);
  FromkLinuxtimespec(&klinux_rem, rem);
  return result;
}

int enc_untrusted_clock_gettime(clockid_t clk_id, struct timespec *tp) {
  clockid_t klinux_clk_id = TokLinuxClockId(clk_id);
  if (klinux_clk_id == -1) {
    errno = EINVAL;
    return -1;
  }

  MessageWriter input;
  input.Push<int64_t>(klinux_clk_id);
  MessageReader output;
  asylo::primitives::PrimitiveStatus status =
      asylo::host_call::NonSystemCallDispatcher(
          asylo::host_call::kClockGettimeHandler, &input, &output);
  CheckStatusAndParamCount(status, output, "enc_untrusted_clock_gettime", 3);

  int result = output.next<int>();
  int klinux_errno = output.next<int>();
  struct kLinux_timespec klinux_tp = output.next<struct kLinux_timespec>();

  // clock_gettime returns -1 on error and sets the errno.
  if (result == -1) {
    errno = FromkLinuxErrorNumber(klinux_errno);
    return -1;
  }

  FromkLinuxtimespec(&klinux_tp, tp);
  return result;
}

int enc_untrusted_clock_getcpuclockid(pid_t pid, clockid_t *clock_id) {
  MessageWriter input;
  input.Push<uint32_t>(pid);
  MessageReader output;
  asylo::primitives::PrimitiveStatus status =
      asylo::host_call::NonSystemCallDispatcher(
          asylo::host_call::kGetCpuClockIdHandler, &input, &output);
  CheckStatusAndParamCount(status, output, "enc_untrusted_getcpuclockid", 2);

  // clock_getcpuclockid returns an errno value directly, without setting errno.
  // The value must still be translated in order to be interpreted.
  int klinux_errno_result = output.next<int32_t>();
  if (klinux_errno_result != 0) {
    return FromkLinuxErrorNumber(klinux_errno_result);
  }

  clockid_t klinux_clk_id = output.next<uint64_t>();
  *clock_id = FromkLinuxClockId(klinux_clk_id);
  return 0;
}

int enc_untrusted_bind(int sockfd, const struct sockaddr *addr,
                       socklen_t addrlen) {
  socklen_t klinux_sock_len =
      std::max(std::max(sizeof(klinux_sockaddr_un), sizeof(klinux_sockaddr_in)),
               sizeof(klinux_sockaddr_in6));
  auto klinux_sock = absl::make_unique<char[]>(klinux_sock_len);

  if (!TokLinuxSockAddr(addr, addrlen,
                        reinterpret_cast<klinux_sockaddr *>(klinux_sock.get()),
                        &klinux_sock_len, TrustedPrimitives::BestEffortAbort)) {
    errno = EINVAL;
    return -1;
  }
  return EnsureInitializedAndDispatchSyscall(asylo::system_call::kSYS_bind,
                                             sockfd, klinux_sock.get(),
                                             klinux_sock_len);
}

int enc_untrusted_connect(int sockfd, const struct sockaddr *addr,
                          socklen_t addrlen) {
  socklen_t klinux_sock_len =
      std::max(std::max(sizeof(klinux_sockaddr_un), sizeof(klinux_sockaddr_in)),
               sizeof(klinux_sockaddr_in6));
  auto klinux_sock = absl::make_unique<char[]>(klinux_sock_len);

  if (!TokLinuxSockAddr(addr, addrlen,
                        reinterpret_cast<klinux_sockaddr *>(klinux_sock.get()),
                        &klinux_sock_len, TrustedPrimitives::BestEffortAbort)) {
    errno = EINVAL;
    return -1;
  }

  return EnsureInitializedAndDispatchSyscall(asylo::system_call::kSYS_connect,
                                             sockfd, klinux_sock.get(),
                                             klinux_sock_len);
}

ssize_t enc_untrusted_sendmsg(int sockfd, const struct msghdr *msg, int flags) {
  size_t total_message_size = CalculateTotalMessageSize(msg);
  std::unique_ptr<char[]> msg_iov_buffer(new char[total_message_size]);
  size_t copied_bytes = 0;
  for (int i = 0; i < msg->msg_iovlen; ++i) {
    memcpy(msg_iov_buffer.get() + copied_bytes, msg->msg_iov[i].iov_base,
           msg->msg_iov[i].iov_len);
    copied_bytes += msg->msg_iov[i].iov_len;
  }

  MessageWriter input;
  input.Push(sockfd);
  input.PushByReference(Extent{msg->msg_name, msg->msg_namelen});
  input.PushByReference(Extent{msg_iov_buffer.get(), total_message_size});
  input.PushByReference(Extent{msg->msg_control, msg->msg_controllen});
  input.Push(msg->msg_flags);
  input.Push(flags);
  MessageReader output;

  const auto status = NonSystemCallDispatcher(
      ::asylo::host_call::kSendMsgHandler, &input, &output);
  CheckStatusAndParamCount(status, output, "enc_untrusted_sendmsg", 2);

  ssize_t result = output.next<ssize_t>();
  int klinux_errno = output.next<int>();
  // sendmsg() returns the number of characters sent. On error, -1 is returned,
  // with errno set to indicate the cause of the error.
  if (result == -1) {
    errno = FromkLinuxErrorNumber(klinux_errno);
  }
  return result;
}

ssize_t enc_untrusted_recvmsg(int sockfd, struct msghdr *msg, int flags) {
  size_t total_buffer_size = CalculateTotalMessageSize(msg);

  MessageWriter input;
  input.Push(sockfd);
  input.Push<uint64_t>(msg->msg_namelen);
  input.Push<uint64_t>(total_buffer_size);
  input.Push<uint64_t>(msg->msg_controllen);
  input.Push(msg->msg_flags);
  input.Push(flags);

  MessageReader output;

  const auto status = NonSystemCallDispatcher(
      ::asylo::host_call::kRecvMsgHandler, &input, &output);
  CheckStatusAndParamCount(status, output, "enc_untrusted_recvmsg", 2,
                           /*match_exact_params=*/false);

  ssize_t result = output.next<ssize_t>();
  int klinux_errno = output.next<int>();

  // recvmsg() returns the number of characters received. On error, -1 is
  // returned, with errno set to indicate the cause of the error.
  if (result == -1) {
    errno = FromkLinuxErrorNumber(klinux_errno);
    return result;
  }

  if (result > total_buffer_size) {
    ::asylo::primitives::TrustedPrimitives::BestEffortAbort(
        "enc_untrusted_recvmsg: result exceeds requested");
  }

  auto msg_name_extent = output.next();
  // The returned |msg_namelen| should not exceed the buffer size.
  if (msg_name_extent.size() <= msg->msg_namelen) {
    msg->msg_namelen = msg_name_extent.size();
  }
  memcpy(msg->msg_name, msg_name_extent.As<char>(), msg->msg_namelen);

  // A single buffer is passed from the untrusted side, copy it into the
  // scattered buffers inside the enclave.
  auto msg_iov_extent = output.next();
  size_t total_bytes = msg_iov_extent.size();
  size_t bytes_copied = 0;
  for (int i = 0; i < msg->msg_iovlen && bytes_copied < total_bytes; ++i) {
    size_t bytes_to_copy =
        std::min(msg->msg_iov[i].iov_len, total_bytes - bytes_copied);
    memcpy(msg->msg_iov[i].iov_base, msg_iov_extent.As<char>() + bytes_copied,
           bytes_to_copy);
    bytes_copied += bytes_to_copy;
  }

  auto msg_control_extent = output.next();
  // The returned |msg_controllen| should not exceed the buffer size.
  if (msg_control_extent.size() <= msg->msg_controllen) {
    msg->msg_controllen = msg_control_extent.size();
  }
  memcpy(msg->msg_control, msg_control_extent.As<char>(), msg->msg_controllen);

  return result;
}

int enc_untrusted_getsockname(int sockfd, struct sockaddr *addr,
                              socklen_t *addrlen) {
  if (!addr || !addrlen) {
    errno = EFAULT;
    return -1;
  }
  // Guard against -1 being passed as addrlen even though it's unsigned.
  if (*addrlen == 0 || *addrlen > INT32_MAX) {
    errno = EINVAL;
    return -1;
  }

  MessageWriter input;
  input.Push<int>(sockfd);
  MessageReader output;
  const auto status = NonSystemCallDispatcher(
      ::asylo::host_call::kGetSocknameHandler, &input, &output);
  CheckStatusAndParamCount(status, output, "enc_untrusted_getsockname", 3);

  int result = output.next<int>();
  int klinux_errno = output.next<int>();

  // getsockname() returns 0 on success. On error, -1 is returned, with errno
  // set to indicate the cause of the error.
  if (result == -1) {
    errno = FromkLinuxErrorNumber(klinux_errno);
    return result;
  }

  auto klinux_sockaddr_buf = output.next();
  const struct klinux_sockaddr *klinux_addr =
      klinux_sockaddr_buf.As<struct klinux_sockaddr>();
  if (!FromkLinuxSockAddr(klinux_addr, klinux_sockaddr_buf.size(), addr,
                          addrlen, TrustedPrimitives::BestEffortAbort)) {
    errno = EFAULT;
    return -1;
  }
  return result;
}

int enc_untrusted_accept(int sockfd, struct sockaddr *addr,
                         socklen_t *addrlen) {
  MessageWriter input;
  input.Push<int>(sockfd);
  MessageReader output;
  const auto status = NonSystemCallDispatcher(
      ::asylo::host_call::kAcceptHandler, &input, &output);
  CheckStatusAndParamCount(status, output, "enc_untrusted_accept", 3);

  int result = output.next<int>();
  int klinux_errno = output.next<int>();

  // accept() returns -1 on failure, with errno set to indicate the cause
  // of the error.
  if (result == -1) {
    errno = FromkLinuxErrorNumber(klinux_errno);
    return result;
  }

  auto klinux_sockaddr_buf = output.next();
  const struct klinux_sockaddr *klinux_addr =
      klinux_sockaddr_buf.As<struct klinux_sockaddr>();
  FromkLinuxSockAddr(klinux_addr, klinux_sockaddr_buf.size(), addr, addrlen,
                     TrustedPrimitives::BestEffortAbort);
  return result;
}

int enc_untrusted_getpeername(int sockfd, struct sockaddr *addr,
                              socklen_t *addrlen) {
  if (!addr || !addrlen) {
    errno = EFAULT;
    return -1;
  }
  // Guard against -1 being passed as addrlen even though it's unsigned.
  if (*addrlen == 0 || *addrlen > INT32_MAX) {
    errno = EINVAL;
    return -1;
  }
  MessageWriter input;
  input.Push<int>(sockfd);
  MessageReader output;
  const auto status = NonSystemCallDispatcher(
      ::asylo::host_call::kGetPeernameHandler, &input, &output);
  CheckStatusAndParamCount(status, output, "enc_untrusted_getpeername", 3);

  int result = output.next<int>();
  int klinux_errno = output.next<int>();

  // getpeername() returns -1 on failure, with errno set to indicate the cause
  // of the error.
  if (result == -1) {
    errno = FromkLinuxErrorNumber(klinux_errno);
    return result;
  }

  auto klinux_sockaddr_buf = output.next();
  const struct klinux_sockaddr *klinux_addr =
      klinux_sockaddr_buf.As<struct klinux_sockaddr>();
  FromkLinuxSockAddr(klinux_addr, klinux_sockaddr_buf.size(), addr, addrlen,
                     TrustedPrimitives::BestEffortAbort);
  return result;
}

ssize_t enc_untrusted_recvfrom(int sockfd, void *buf, size_t len, int flags,
                               struct sockaddr *src_addr, socklen_t *addrlen) {
  int klinux_flags = TokLinuxRecvSendFlag(flags);
  if (klinux_flags == 0 && flags != 0) {
    errno = EINVAL;
    return -1;
  }

  MessageWriter input;
  input.Push<int>(sockfd);
  input.Push<uint64_t>(len);
  input.Push<int>(klinux_flags);
  MessageReader output;
  const auto status = NonSystemCallDispatcher(
      ::asylo::host_call::kRecvFromHandler, &input, &output);
  CheckStatusAndParamCount(status, output, "enc_untrusted_recvfrom", 4);

  int result = output.next<int>();
  int klinux_errno = output.next<int>();
  // recvfrom() returns -1 on failure, with errno set to indicate the cause
  // of the error.
  if (result == -1) {
    errno = FromkLinuxErrorNumber(klinux_errno);
    return result;
  }

  if (result > len) {
    ::asylo::primitives::TrustedPrimitives::BestEffortAbort(
        "enc_untrusted_recvfrom: result exceeds requested");
  }

  auto buffer_received = output.next();
  memcpy(buf, buffer_received.data(), std::min(len, buffer_received.size()));

  // If |src_addr| is not NULL, and the underlying protocol provides the source
  // address, this source address is filled in. When |src_addr| is NULL, nothing
  // is filled in; in this case, |addrlen| is not used, and should also be NULL.
  if (src_addr != nullptr && addrlen != nullptr) {
    auto klinux_sockaddr_buf = output.next();
    const struct klinux_sockaddr *klinux_addr =
        klinux_sockaddr_buf.As<struct klinux_sockaddr>();
    FromkLinuxSockAddr(klinux_addr, klinux_sockaddr_buf.size(), src_addr,
                       addrlen, TrustedPrimitives::BestEffortAbort);
  }

  return result;
}

int enc_untrusted_select(int nfds, fd_set *readfds, fd_set *writefds,
                         fd_set *exceptfds, struct timeval *timeout) {
  struct klinux_fd_set klinux_readfds, klinux_writefds, klinux_exceptfds;
  struct kLinux_timeval klinux_timeout;

  TokLinuxFdSet(readfds, &klinux_readfds);
  TokLinuxFdSet(writefds, &klinux_writefds);
  TokLinuxFdSet(exceptfds, &klinux_exceptfds);
  TokLinuxtimeval(timeout, &klinux_timeout);

  int result = EnsureInitializedAndDispatchSyscall(
      asylo::system_call::kSYS_select, nfds, &klinux_readfds, &klinux_writefds,
      &klinux_exceptfds, &klinux_timeout);

  FromkLinuxFdSet(&klinux_readfds, readfds);
  FromkLinuxFdSet(&klinux_writefds, writefds);
  FromkLinuxFdSet(&klinux_exceptfds, exceptfds);
  return result;
}

int enc_untrusted_gettimeofday(struct timeval *tv, struct timezone *tz) {
  struct kLinux_timeval ktv;
  TokLinuxtimeval(tv, &ktv);

  // We do not convert timezone to a klinux value since this struct is expected
  // to be identical across enclave boundary. Besides, the use of the timezone
  // structure is obsolete; the tz argument should normally be specified as
  // NULL.
  int result = EnsureInitializedAndDispatchSyscall(
      asylo::system_call::kSYS_gettimeofday, &ktv, tz);
  FromkLinuxtimeval(&ktv, tv);
  return result;
}

int enc_untrusted_fsync(int fd) {
  return EnsureInitializedAndDispatchSyscall(asylo::system_call::kSYS_fsync,
                                             fd);
}

int enc_untrusted_raise(int sig) {
  int klinux_sig = TokLinuxSignalNumber(sig);
  if (klinux_sig < 0) {
    errno = EINVAL;
    return -1;
  }

  MessageWriter input;
  input.Push<int>(klinux_sig);
  MessageReader output;
  const auto status = NonSystemCallDispatcher(::asylo::host_call::kRaiseHandler,
                                              &input, &output);
  CheckStatusAndParamCount(status, output, "enc_untrusted_raise", 2);

  int result = output.next<int>();
  int klinux_errno = output.next<int>();
  if (result != 0) {
    errno = FromkLinuxErrorNumber(klinux_errno);
  }
  return result;
}

int enc_untrusted_getsockopt(int sockfd, int level, int optname, void *optval,
                             socklen_t *optlen) {
  if (!optval || !optlen || *optlen == 0) {
    errno = EINVAL;
    return -1;
  }

  MessageWriter input;
  input.Push<int>(sockfd);
  input.Push<int>(level);
  input.Push<int>(TokLinuxOptionName(level, optname));
  input.PushByReference(Extent{reinterpret_cast<char *>(optval), *optlen});
  MessageReader output;
  const auto status = NonSystemCallDispatcher(
      ::asylo::host_call::kGetSockOptHandler, &input, &output);
  CheckStatusAndParamCount(status, output, "enc_untrusted_getsockopt", 3);

  int result = output.next<int>();
  int klinux_errno = output.next<int>();
  Extent opt_received = output.next();

  if (result == -1) {
    errno = FromkLinuxErrorNumber(klinux_errno);
    return -1;
  }

  // The returned |optlen| should not exceed the buffer size.
  if (opt_received.size() <= *optlen) {
    *optlen = opt_received.size();
  }
  memcpy(optval, opt_received.data(), *optlen);
  return result;
}

int enc_untrusted_getitimer(int which, struct itimerval *curr_value) {
  struct klinux_itimerval klinux_curr_value {};
  int result = EnsureInitializedAndDispatchSyscall(
      asylo::system_call::kSYS_getitimer, TokLinuxItimerType(which),
      &klinux_curr_value);

  if (!curr_value || !FromkLinuxItimerval(&klinux_curr_value, curr_value)) {
    errno = EFAULT;
    return -1;
  }
  return result;
}

int enc_untrusted_setitimer(int which, const struct itimerval *new_value,
                            struct itimerval *old_value) {
  struct klinux_itimerval klinux_new_value {};
  struct klinux_itimerval klinux_old_value {};
  if (!TokLinuxItimerval(new_value, &klinux_new_value)) {
    errno = EFAULT;
    return -1;
  }

  int result = EnsureInitializedAndDispatchSyscall(
      asylo::system_call::kSYS_setitimer, TokLinuxItimerType(which),
      &klinux_new_value, &klinux_old_value);

  if (old_value != nullptr &&
      !FromkLinuxItimerval(&klinux_old_value, old_value)) {
    errno = EFAULT;
    return -1;
  }
  return result;
}

clock_t enc_untrusted_times(struct tms *buf) {
  struct kLinux_tms klinux_buf {};
  int64_t result = EnsureInitializedAndDispatchSyscall(
      asylo::system_call::kSYS_times, &klinux_buf);

  if (!FromkLinuxtms(&klinux_buf, buf)) {
    errno = EFAULT;
    return -1;
  }
  return static_cast<clock_t>(result);
}

int enc_untrusted_getaddrinfo(const char *node, const char *service,
                              const struct addrinfo *hints,
                              struct addrinfo **res) {
  MessageWriter input;
  input.PushByReference(Extent{node, (node != nullptr) ? strlen(node) + 1 : 0});
  input.PushByReference(
      Extent{service, (service != nullptr) ? strlen(service) + 1 : 0});
  if (hints != nullptr) {
    input.Push<int>(TokLinuxAddressInfoFlag(hints->ai_flags));
    input.Push<int>(TokLinuxAfFamily(hints->ai_family));
    input.Push<int>(TokLinuxSocketType(hints->ai_socktype));
    input.Push<int>(hints->ai_protocol);
  }

  MessageReader output;
  const auto status = NonSystemCallDispatcher(
      ::asylo::host_call::kGetAddrInfoHandler, &input, &output);
  CheckStatusAndParamCount(status, output, "enc_untrusted_getaddrinfo", 3,
                           /*match_exact_params=*/false);

  int klinux_ret = output.next<int>();
  int klinux_errno = output.next<int>();

  int ret = FromkLinuxAddressInfoError(klinux_ret);
  if (ret != 0) {
    if (ret == EAI_SYSTEM) {
      errno = FromkLinuxErrorNumber(klinux_errno);
    }
    return ret;
  }

  if (!asylo::host_call::DeserializeAddrinfo(
          &output, res, TrustedPrimitives::BestEffortAbort)) {
    TrustedPrimitives::DebugPuts(
        "enc_untrusted_getaddrinfo: Invalid addrinfo in response.");
    return -1;
  }
  return 0;
}

void enc_freeaddrinfo(struct addrinfo *res) {
  struct addrinfo *prev_info = nullptr;
  for (struct addrinfo *info = res; info != nullptr; info = info->ai_next) {
    if (prev_info) free(prev_info);
    if (info->ai_addr) free(info->ai_addr);
    if (info->ai_canonname) free(info->ai_canonname);
    prev_info = info;
  }
  if (prev_info) free(prev_info);
}

int enc_untrusted_poll(struct pollfd *fds, nfds_t nfds, int timeout) {
  auto klinux_fds = absl::make_unique<struct klinux_pollfd[]>(nfds);
  for (int i = 0; i < nfds; ++i) {
    if (!TokLinuxPollfd(&fds[i], &klinux_fds[i])) {
      errno = EFAULT;
      return -1;
    }
  }

  int result = EnsureInitializedAndDispatchSyscall(
      asylo::system_call::kSYS_poll, klinux_fds.get(),
      static_cast<uint64_t>(nfds), timeout);

  if (result < 0) {
    return result;
  }

  for (int i = 0; i < nfds; ++i) {
    if (!FromkLinuxPollfd(&klinux_fds[i], &fds[i])) {
      errno = EFAULT;
      return -1;
    }
  }
  return result;
}

int enc_untrusted_epoll_create(int size) {
  return EnsureInitializedAndDispatchSyscall(
      asylo::system_call::kSYS_epoll_create, size);
}

int enc_untrusted_utimes(const char *filename, const struct timeval times[2]) {
  struct kLinux_timeval klinux_times[2];
  if (!TokLinuxtimeval(&times[0], &klinux_times[0]) ||
      !TokLinuxtimeval(&times[1], &klinux_times[1])) {
    errno = EBADE;
    return -1;
  }
  return EnsureInitializedAndDispatchSyscall(asylo::system_call::kSYS_utimes,
                                             filename, klinux_times);
}

int enc_untrusted_utime(const char *filename, const struct utimbuf *times) {
  struct kLinux_utimbuf klinux_times {};

  // We do not check the return value of the conversion function since utimbuf
  // is allowed to be null.
  TokLinuxutimbuf(times, &klinux_times);
  return EnsureInitializedAndDispatchSyscall(asylo::system_call::kSYS_utime,
                                             filename, &klinux_times);
}

int enc_untrusted_inet_pton(int af, const char *src, void *dst) {
  if (!src || !dst) {
    return 0;
  }

  MessageWriter input;
  input.Push<int>(TokLinuxAfFamily(af));
  input.PushByReference(Extent{
      src, std::min(strlen(src) + 1, static_cast<size_t>(INET6_ADDRSTRLEN))});
  MessageReader output;

  const auto status = NonSystemCallDispatcher(
      ::asylo::host_call::kInetPtonHandler, &input, &output);
  CheckStatusAndParamCount(status, output, "enc_untrusted_inet_pton", 3);

  int result = output.next<int>();
  int klinux_errno = output.next<int>();
  if (result == -1) {
    errno = FromkLinuxErrorNumber(klinux_errno);
    return -1;
  }

  auto klinux_addr_buffer = output.next();
  size_t max_size = 0;
  if (af == AF_INET) {
    if (klinux_addr_buffer.size() != sizeof(klinux_in_addr)) {
      ::asylo::primitives::TrustedPrimitives::BestEffortAbort(
          "enc_untrusted_inet_pton: unexpected output size");
    }
    max_size = sizeof(struct in_addr);
  } else if (af == AF_INET6) {
    if (klinux_addr_buffer.size() != sizeof(klinux_in6_addr)) {
      ::asylo::primitives::TrustedPrimitives::BestEffortAbort(
          "enc_untrusted_inet_pton: unexpected output size");
    }
    max_size = sizeof(struct in6_addr);
  }
  memcpy(dst, klinux_addr_buffer.data(),
         std::min(klinux_addr_buffer.size(), max_size));
  return result;
}

const char *enc_untrusted_inet_ntop(int af, const void *src, char *dst,
                                    socklen_t size) {
  if (!src || !dst) {
    errno = EFAULT;
    return nullptr;
  }
  size_t src_size = 0;
  if (af == AF_INET) {
    src_size = sizeof(struct in_addr);
  } else if (af == AF_INET6) {
    src_size = sizeof(struct in6_addr);
  } else {
    errno = EAFNOSUPPORT;
    return nullptr;
  }

  MessageWriter input;
  input.Push<int>(TokLinuxAfFamily(af));
  input.PushByReference(Extent{reinterpret_cast<const char *>(src), src_size});
  input.Push(size);
  MessageReader output;

  const auto status = NonSystemCallDispatcher(
      ::asylo::host_call::kInetNtopHandler, &input, &output);
  CheckStatusAndParamCount(status, output, "enc_untrusted_inet_ntop", 2);

  auto result = output.next();
  int klinux_errno = output.next<int>();
  if (result.empty()) {
    errno = FromkLinuxErrorNumber(klinux_errno);
    return nullptr;
  }

  memcpy(
      dst, result.data(),
      std::min({static_cast<size_t>(size), static_cast<size_t>(result.size()),
                static_cast<size_t>(INET6_ADDRSTRLEN)}));
  return dst;
}

int enc_untrusted_sigprocmask(int how, const sigset_t *set, sigset_t *oldset) {
  klinux_sigset_t klinux_set;
  if (!TokLinuxSigset(set, &klinux_set)) {
    errno = EINVAL;
    return -1;
  }

  int klinux_how = TokLinuxSigMaskAction(how);
  if (klinux_how == -1) {
    errno = EINVAL;
    return -1;
  }

  MessageWriter input;
  input.Push<int>(klinux_how);
  input.Push<klinux_sigset_t>(klinux_set);
  MessageReader output;
  const auto status = NonSystemCallDispatcher(
      ::asylo::host_call::kSigprocmaskHandler, &input, &output);
  CheckStatusAndParamCount(status, output, "enc_untrusted_sigprocmask", 3);

  int result = output.next<int>();
  int klinux_errno = output.next<int>();
  // sigprocmask() returns -1 on failure, with errno set to indicate the cause
  // of the error.
  if (result == -1) {
    errno = FromkLinuxErrorNumber(klinux_errno);
    return result;
  }

  klinux_sigset_t klinux_oldset = output.next<klinux_sigset_t>();
  if (oldset != nullptr) {
    if (!FromkLinuxSigset(&klinux_oldset, oldset)) {
      errno = EINVAL;
      return -1;
    }
  }
  return result;
}

unsigned int enc_untrusted_if_nametoindex(const char *ifname) {
  MessageWriter input;
  input.PushString(ifname);
  MessageReader output;

  const auto status = NonSystemCallDispatcher(
      ::asylo::host_call::kIfNameToIndexHandler, &input, &output);
  CheckStatusAndParamCount(status, output, "enc_untrusted_nametoindex", 2);

  auto result = output.next<unsigned int>();
  int klinux_errno = output.next<int>();
  if (result == 0) {
    errno = FromkLinuxErrorNumber(klinux_errno);
  }
  return result;
}

char *enc_untrusted_if_indextoname(unsigned int ifindex, char *ifname) {
  if (!ifname) {
    return nullptr;
  }

  MessageWriter input;
  input.Push(ifindex);
  MessageReader output;

  const auto status = NonSystemCallDispatcher(
      ::asylo::host_call::kIfIndexToNameHandler, &input, &output);
  CheckStatusAndParamCount(status, output, "enc_untrusted_indextoname", 2);

  Extent ifname_buffer = output.next();
  memcpy(ifname, ifname_buffer.As<char>(),
         std::min(ifname_buffer.size(), static_cast<size_t>(IF_NAMESIZE)));
  int klinux_errno = output.next<int>();
  if (ifname_buffer.empty()) {
    errno = FromkLinuxErrorNumber(klinux_errno);
  }
  return ifname;
}

int enc_untrusted_epoll_ctl(int epfd, int op, int fd,
                            struct epoll_event *event) {
  struct klinux_epoll_event klinux_event_tmp {};
  if (event != nullptr && !TokLinuxEpollEvent(event, &klinux_event_tmp)) {
    errno = EINVAL;
    return -1;
  }
  int klinux_op = TokLinuxEpollCtlOp(op);
  if (klinux_op == 0) {
    errno = EINVAL;
    return -1;
  }

  struct klinux_epoll_event *klinux_event =
      (event != nullptr) ? &klinux_event_tmp : nullptr;
  return EnsureInitializedAndDispatchSyscall(asylo::system_call::kSYS_epoll_ctl,
                                             epfd, klinux_op, fd, klinux_event);
}

int enc_untrusted_epoll_wait(int epfd, struct epoll_event *events,
                             int maxevents, int timeout) {
  if (maxevents <= 0) {
    errno = EINVAL;
    return -1;
  }
  auto klinux_events =
      absl::make_unique<struct klinux_epoll_event[]>(maxevents);

  int result = EnsureInitializedAndDispatchSyscall(
      asylo::system_call::kSYS_epoll_wait, epfd, klinux_events.get(), maxevents,
      timeout);

  // Only process epoll events if syscall was successful.
  if (result == -1) {
    // errno is already set by the system_call library at this point for a
    // return value of -1.
    return result;
  }
  if (result > maxevents) {
    TrustedPrimitives::BestEffortAbort(
        "enc_untrusted_epoll_wait: result found to be greater than maxevents "
        "supplied.");
  }

  for (int i = 0; i < result; i++) {
    if (!FromkLinuxEpollEvent(&klinux_events.get()[i], &events[i])) {
      errno = EBADE;
      return -1;
    }
  }
  return result;
}

int enc_untrusted_getifaddrs(struct ifaddrs **ifap) {
  MessageWriter input;
  MessageReader output;

  const auto status = NonSystemCallDispatcher(
      ::asylo::host_call::kGetIfAddrsHandler, &input, &output);
  CheckStatusAndParamCount(status, output, "enc_untrusted_getifaddrs", 3,
                           /*match_exact_params=*/false);

  int result = output.next<int>();
  int klinux_errno = output.next<int>();
  if (result != 0) {
    errno = FromkLinuxErrorNumber(klinux_errno);
    return result;
  }

  if (!asylo::host_call::DeserializeIfAddrs(
          &output, ifap, TrustedPrimitives::BestEffortAbort)) {
    TrustedPrimitives::DebugPuts(
        "enc_untrusted_getifaddrs: Invalid ifaddrs in response.");
    return -1;
  }
  return 0;
}

void enc_freeifaddrs(struct ifaddrs *ifa) {
  asylo::host_call::FreeDeserializedIfAddrs(ifa);
}

int enc_untrusted_getrusage(int who, struct rusage *usage) {
  struct klinux_rusage klinux_usage {};
  int result = EnsureInitializedAndDispatchSyscall(
      asylo::system_call::kSYS_getrusage, TokLinuxRusageTarget(who),
      &klinux_usage);

  if (result != -1) {
    if (!FromkLinuxRusage(&klinux_usage, usage)) {
      errno = EINVAL;
      return -1;
    }
  }
  return result;
}

pid_t enc_untrusted_wait3(int *status, int options, struct rusage *rusage) {
  int klinux_status;
  struct klinux_rusage klinux_usage;
  pid_t result = EnsureInitializedAndDispatchSyscall(
      asylo::system_call::kSYS_wait4, /*pid=*/-1, &klinux_status,
      TokLinuxWaitOption(options), &klinux_usage);

  if (status) {
    *status = FromkLinuxToNewlibWstatus(klinux_status);
  }
  if (rusage) {
    if (!FromkLinuxRusage(&klinux_usage, rusage)) {
      errno = EINVAL;
      return -1;
    }
  }
  return result;
}

pid_t enc_untrusted_waitpid(pid_t pid, int *status, int options) {
  int klinux_status;
  pid_t result = EnsureInitializedAndDispatchSyscall(
      asylo::system_call::kSYS_wait4, pid, &klinux_status,
      TokLinuxWaitOption(options), /*rusage=*/nullptr);

  if (status) {
    *status = FromkLinuxToNewlibWstatus(klinux_status);
  }
  return result;
}

int enc_untrusted_uname(struct utsname *buf) {
  struct klinux_utsname klinux_buf {};
  int result = EnsureInitializedAndDispatchSyscall(
      asylo::system_call::kSYS_uname, &klinux_buf);
  if (result != 0) {
    return result;
  }

  if (!FromkLinuxUtsName(&klinux_buf, buf)) {
    TrustedPrimitives::BestEffortAbort(
        "enc_untrusted_uname: Returned an ill-formed utsname.");
  }
  return 0;
}

struct passwd *enc_untrusted_getpwuid(uid_t uid) {
  MessageWriter input;
  MessageReader output;
  input.Push<uid_t>(uid);
  const auto status = NonSystemCallDispatcher(
      ::asylo::host_call::kGetPwUidHandler, &input, &output);
  CheckStatusAndParamCount(status, output, "enc_untrusted_getpwuid", 1,
                           /*match_exact_params=*/false);

  int klinux_errno = output.next<int>();
  if (output.size() == 1) {
    errno = FromkLinuxErrorNumber(klinux_errno);
    return nullptr;
  }

  // Store the struct passwd members in a static passwd_holder, and direct the
  // pointers in global_passwd to those members.
  static struct passwd_holder passwd_buffers;
  if (!DeserializePasswd(&output, &passwd_buffers) ||
      !PasswdHolderToPasswd(&passwd_buffers, &global_passwd)) {
    errno = EFAULT;
    return nullptr;
  }

  return &global_passwd;
}

void enc_untrusted_hex_dump(const void *buf, size_t nbytes) {
  MessageWriter input;
  MessageReader output;
  input.PushByReference(Extent{reinterpret_cast<const char *>(buf), nbytes});
  const auto status = NonSystemCallDispatcher(
      ::asylo::host_call::kHexDumpHandler, &input, &output);
  CheckStatusAndParamCount(status, output, "enc_untrusted_hex_dump", 2);
}

void enc_untrusted_syslog(int priority, const char *message, int len) {
  EnsureInitializedAndDispatchSyscall(asylo::system_call::kSYS_syslog,
                                      TokLinuxSyslogPriority(priority), message,
                                      len);
}

void enc_untrusted_openlog(const char *ident, int option, int facility) {
  MessageWriter input;
  MessageReader output;
  input.PushString(ident);
  input.Push<int>(TokLinuxSyslogOption(option));
  input.Push<int>(TokLinuxSyslogFacility(facility));

  const auto status = NonSystemCallDispatcher(
      ::asylo::host_call::kOpenLogHandler, &input, &output);
  CheckStatusAndParamCount(status, output, "enc_untrusted_openlog", 1);
}

int enc_untrusted_inotify_read(int fd, size_t count, char **serialized_events,
                               size_t *serialized_events_len) {
  MessageWriter input;
  MessageReader output;
  input.Push<int>(fd);
  input.Push<uint64_t>(count);

  const auto status = NonSystemCallDispatcher(
      ::asylo::host_call::kInotifyReadHandler, &input, &output);
  CheckStatusAndParamCount(status, output, "enc_untrusted_inotify_read", 2,
                           /*match_exact_params=*/false);
  int result = output.next<int>();
  int klinux_errno = output.next<int>();
  if (result == -1) {
    errno = FromkLinuxErrorNumber(klinux_errno);
    return -1;
  }

  Extent serialized_buf = output.next();
  *serialized_events_len = serialized_buf.size();

  // The caller to this host call owns memory pointed by |*serialized_events|.
  *serialized_events = reinterpret_cast<char *>(malloc(*serialized_events_len));
  if (!serialized_events) {
    errno = ENOMEM;
    return -1;
  }
  memcpy(*serialized_events, serialized_buf.As<char>(), *serialized_events_len);
  return result;
}

int enc_untrusted_ioctl1(int fd, uint64_t request) {
  return EnsureInitializedAndDispatchSyscall(asylo::system_call::kSYS_ioctl, fd,
                                             request);
}

}  // extern "C"
