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

#include "asylo/platform/host_call/exit_handler_constants.h"
#include "asylo/platform/host_call/trusted/host_call_dispatcher.h"
#include "asylo/platform/primitives/trusted_primitives.h"
#include "asylo/platform/system_call/type_conversions/types_functions.h"

extern "C" {

void init_host_calls() {
  enc_set_dispatch_syscall(asylo::host_call::SystemCallDispatcher);
}

int enc_untrusted_access(const char *path_name, int mode) {
  return enc_untrusted_syscall(asylo::system_call::kSYS_access, path_name,
                               mode);
}

pid_t enc_untrusted_getpid() {
  return enc_untrusted_syscall(asylo::system_call::kSYS_getpid);
}

pid_t enc_untrusted_getppid() {
  return enc_untrusted_syscall(asylo::system_call::kSYS_getppid);
}

pid_t enc_untrusted_setsid() {
  return enc_untrusted_syscall(asylo::system_call::kSYS_setsid);
}

uid_t enc_untrusted_getuid() {
  return enc_untrusted_syscall(asylo::system_call::kSYS_getuid);
}

gid_t enc_untrusted_getgid() {
  return enc_untrusted_syscall(asylo::system_call::kSYS_getgid);
}

uid_t enc_untrusted_geteuid() {
  return enc_untrusted_syscall(asylo::system_call::kSYS_geteuid);
}

gid_t enc_untrusted_getegid() {
  return enc_untrusted_syscall(asylo::system_call::kSYS_getegid);
}

int enc_untrusted_kill(pid_t pid, int sig) {
  return enc_untrusted_syscall(asylo::system_call::kSYS_kill, pid, sig);
}

int enc_untrusted_link(const char *oldpath, const char *newpath) {
  return enc_untrusted_syscall(asylo::system_call::kSYS_link, oldpath, newpath);
}

off_t enc_untrusted_lseek(int fd, off_t offset, int whence) {
  return enc_untrusted_syscall(asylo::system_call::kSYS_lseek, fd, offset,
                               whence);
}

int enc_untrusted_mkdir(const char *pathname, mode_t mode) {
  return enc_untrusted_syscall(asylo::system_call::kSYS_mkdir, pathname, mode);
}

int enc_untrusted_open(const char *pathname, int flags, ...) {
  int mode = 0;
  if (flags & O_CREAT) {
    va_list ap;
    va_start(ap, flags);
    mode = va_arg(ap, mode_t);
    va_end(ap);
    int klinux_mode;
    TokLinuxFileModeFlag(&mode, &klinux_mode);
  }

  int klinux_flags;
  TokLinuxFileStatusFlag(&flags, &klinux_flags);
  return enc_untrusted_syscall(asylo::system_call::kSYS_open, pathname,
                               klinux_flags, mode);
}

int enc_untrusted_unlink(const char *pathname) {
  return enc_untrusted_syscall(asylo::system_call::kSYS_unlink, pathname);
}

int enc_untrusted_rename(const char *oldpath, const char *newpath) {
  return enc_untrusted_syscall(asylo::system_call::kSYS_rename, oldpath,
                               newpath);
}

ssize_t enc_untrusted_read(int fd, void *buf, size_t count) {
  return static_cast<ssize_t>(
      enc_untrusted_syscall(asylo::system_call::kSYS_read, fd, buf, count));
}

ssize_t enc_untrusted_write(int fd, const void *buf, size_t count) {
  return static_cast<ssize_t>(
      enc_untrusted_syscall(asylo::system_call::kSYS_write, fd, buf, count));
}

int enc_untrusted_symlink(const char *target, const char *linkpath) {
  return enc_untrusted_syscall(asylo::system_call::kSYS_symlink, target,
                               linkpath);
}

ssize_t enc_untrusted_readlink(const char *pathname, char *buf, size_t bufsiz) {
  return static_cast<ssize_t>(enc_untrusted_syscall(
      asylo::system_call::kSYS_readlink, pathname, buf, bufsiz));
}

int enc_untrusted_truncate(const char *path, off_t length) {
  return enc_untrusted_syscall(asylo::system_call::kSYS_truncate, path, length);
}

int enc_untrusted_ftruncate(int fd, off_t length) {
  return enc_untrusted_syscall(asylo::system_call::kSYS_ftruncate, fd, length);
}

int enc_untrusted_rmdir(const char *path) {
  return enc_untrusted_syscall(asylo::system_call::kSYS_rmdir, path);
}

int enc_untrusted_pipe2(int pipefd[2], int flags) {
  if (flags & ~(O_CLOEXEC | O_DIRECT | O_NONBLOCK)) {
    errno = EINVAL;
    return -1;
  }

  int kLinux_flags;
  TokLinuxFileStatusFlag(&flags, &kLinux_flags);
  return enc_untrusted_syscall(asylo::system_call::kSYS_pipe2, pipefd,
                               kLinux_flags);
}

int enc_untrusted_socket(int domain, int type, int protocol) {
  int klinux_domain;
  int klinux_type;
  TokLinuxAfFamily(&domain, &klinux_domain);
  TokLinuxSocketType(&type, &klinux_type);
  return enc_untrusted_syscall(asylo::system_call::kSYS_socket, klinux_domain,
                               klinux_type, protocol);
}

int enc_untrusted_listen(int sockfd, int backlog) {
  return enc_untrusted_syscall(asylo::system_call::kSYS_listen, sockfd,
                               backlog);
}

int enc_untrusted_shutdown(int sockfd, int how) {
  return enc_untrusted_syscall(asylo::system_call::kSYS_shutdown, sockfd, how);
}

ssize_t enc_untrusted_send(int sockfd, const void *buf, size_t len, int flags) {
  return enc_untrusted_syscall(asylo::system_call::kSYS_sendto, sockfd, buf,
                               len, flags, /*dest_addr=*/nullptr,
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

  int klinux_cmd;
  TokLinuxFcntlCommand(&cmd, &klinux_cmd);
  if (klinux_cmd == -1) {
    errno = EINVAL;
    return -1;
  }

  int intarg = arg;
  switch (cmd) {
    case F_SETFL: {
      int klinux_arg;
      TokLinuxFileStatusFlag(&intarg, &klinux_arg);
      return enc_untrusted_syscall(asylo::system_call::kSYS_fcntl, fd,
                                   klinux_cmd, klinux_arg);
    }
    case F_SETFD: {
      int klinux_arg;
      TokLinuxFDFlag(&intarg, &klinux_arg);
      return enc_untrusted_syscall(asylo::system_call::kSYS_fcntl, fd,
                                   klinux_cmd, klinux_arg);
    }
    case F_GETFL: {
      int retval = enc_untrusted_syscall(asylo::system_call::kSYS_fcntl, fd,
                                         klinux_cmd, arg);
      if (retval != -1) {
        int result;
        FromkLinuxFileStatusFlag(&retval, &result);
        retval = result;
      }

      return retval;
    }
    case F_GETFD: {
      int retval = enc_untrusted_syscall(asylo::system_call::kSYS_fcntl, fd,
                                         klinux_cmd, arg);
      if (retval != -1) {
        int result;
        FromkLinuxFDFlag(&retval, &result);
        retval = result;
      }
      return retval;
    }
    case F_GETPIPE_SZ:
    case F_SETPIPE_SZ: {
      return enc_untrusted_syscall(asylo::system_call::kSYS_fcntl, fd,
                                   klinux_cmd, arg);
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
  return enc_untrusted_syscall(asylo::system_call::kSYS_chown, pathname, owner,
                               group);
}

int enc_untrusted_fchown(int fd, uid_t owner, gid_t group) {
  return enc_untrusted_syscall(asylo::system_call::kSYS_fchown, fd, owner,
                               group);
}

int enc_untrusted_setsockopt(int sockfd, int level, int optname,
                             const void *optval, socklen_t optlen) {
  int klinux_option_name;
  TokLinuxOptionName(&level, &optname, &klinux_option_name);
  return enc_untrusted_syscall(asylo::system_call::kSYS_setsockopt, sockfd,
                               level, klinux_option_name, optval, optlen);
}

int enc_untrusted_flock(int fd, int operation) {
  int klinux_operation;
  TokLinuxFLockOperation(&operation, &klinux_operation);
  return enc_untrusted_syscall(asylo::system_call::kSYS_flock, fd,
                               klinux_operation);
}

int enc_untrusted_wait(int *wstatus) {
  return enc_untrusted_syscall(asylo::system_call::kSYS_wait4, /*wpid=*/-1,
                               wstatus, /*options=*/0, /*rusage=*/nullptr);
}

int enc_untrusted_inotify_init1(int flags) {
  int klinux_flags;
  TokLinuxInotifyFlag(&flags, &klinux_flags);
  return enc_untrusted_syscall(asylo::system_call::kSYS_inotify_init1,
                               klinux_flags);
}

int enc_untrusted_inotify_add_watch(int fd, const char *pathname,
                                    uint32_t mask) {
  int klinux_mask, input_mask = mask;
  TokLinuxInotifyEventMask(&input_mask, &klinux_mask);
  return enc_untrusted_syscall(asylo::system_call::kSYS_inotify_add_watch, fd,
                               pathname, klinux_mask);
}

int enc_untrusted_inotify_rm_watch(int fd, int wd) {
  return enc_untrusted_syscall(asylo::system_call::kSYS_inotify_rm_watch, fd,
                               wd);
}

mode_t enc_untrusted_umask(mode_t mask) {
  return enc_untrusted_syscall(asylo::system_call::kSYS_umask, mask);
}

int enc_untrusted_chmod(const char *path_name, mode_t mode) {
  return enc_untrusted_syscall(asylo::system_call::kSYS_chmod, path_name, mode);
}

int enc_untrusted_fchmod(int fd, mode_t mode) {
  return enc_untrusted_syscall(asylo::system_call::kSYS_fchmod, fd, mode);
}

int enc_untrusted_sched_yield() {
  return enc_untrusted_syscall(asylo::system_call::kSYS_sched_yield);
}

int enc_untrusted_pread64(int fd, void *buf, size_t count, off_t offset) {
  return enc_untrusted_syscall(asylo::system_call::kSYS_pread64, fd, buf, count,
                               offset);
}

int enc_untrusted_pwrite64(int fd, const void *buf, size_t count,
                           off_t offset) {
  return enc_untrusted_syscall(asylo::system_call::kSYS_pwrite64, fd, buf,
                               count, offset);
}

int enc_untrusted_isatty(int fd) {
  ::asylo::primitives::MessageWriter input;
  input.Push(fd);
  ::asylo::primitives::MessageReader output;
  const auto status = ::asylo::host_call::NonSystemCallDispatcher(
      ::asylo::host_call::kIsAttyHandler, &input, &output);
  if (!status.ok()) {
    abort();
  }

  int result = output.next<int>();

  // isatty() returns 1 if fd is an open file descriptor referring to a
  // terminal; otherwise 0 is returned, and errno is set to indicate the error.
  if (result == 0) {
    int klinux_errno = output.next<int>();
    int enclave_errno;
    FromkLinuxErrorNumber(&klinux_errno, &enclave_errno);
    errno = enclave_errno;
  }
  return result;
}

int enc_untrusted_usleep(useconds_t usec) {
  ::asylo::primitives::MessageWriter input;
  input.Push(usec);
  ::asylo::primitives::MessageReader output;
  asylo::primitives::PrimitiveStatus status =
      asylo::host_call::NonSystemCallDispatcher(
          asylo::host_call::kUSleepHandler, &input, &output);
  if (!status.ok()) {
    abort();
  }

  int result = output.next<int>();

  // usleep() returns 0 on success. On error, -1 is returned, with errno set to
  // indicate the cause of the error.
  if (result == -1) {
    int klinux_errno = output.next<int>();
    int enclave_errno;
    FromkLinuxErrorNumber(&klinux_errno, &enclave_errno);
    errno = enclave_errno;
  }

  return result;
}

int enc_untrusted_fstat(int fd, struct stat *statbuf) {
  struct kernel_stat stat_kernel;
  int result =
      enc_untrusted_syscall(asylo::system_call::kSYS_fstat, fd, &stat_kernel);
  FromKernelStat(&stat_kernel, statbuf);
  int kLinux_mode = stat_kernel.kernel_st_mode;
  int mode;
  FromkLinuxFileModeFlag(&kLinux_mode, &mode);
  statbuf->st_mode = mode;
  return result;
}

int enc_untrusted_lstat(const char *pathname, struct stat *statbuf) {
  struct kernel_stat stat_kernel;
  int result = enc_untrusted_syscall(asylo::system_call::kSYS_lstat, pathname,
                                     &stat_kernel);
  FromKernelStat(&stat_kernel, statbuf);
  int kLinux_mode = stat_kernel.kernel_st_mode;
  int mode;
  FromkLinuxFileModeFlag(&kLinux_mode, &mode);
  statbuf->st_mode = mode;
  return result;
}

int enc_untrusted_stat(const char *pathname, struct stat *statbuf) {
  struct kernel_stat stat_kernel;
  int result = enc_untrusted_syscall(asylo::system_call::kSYS_stat, pathname,
                                     &stat_kernel);
  FromKernelStat(&stat_kernel, statbuf);
  int kLinux_mode = stat_kernel.kernel_st_mode;
  int mode;
  FromkLinuxFileModeFlag(&kLinux_mode, &mode);
  statbuf->st_mode = mode;
  return result;
}

int64_t enc_untrusted_sysconf(int name) {
  int kLinux_name;
  TokLinuxSysconfConstant(&name, &kLinux_name);
  if (kLinux_name == -1) {
    errno = EINVAL;
    return -1;
  }

  ::asylo::primitives::MessageWriter input;
  input.Push(kLinux_name);
  ::asylo::primitives::MessageReader output;
  asylo::primitives::PrimitiveStatus status =
      asylo::host_call::NonSystemCallDispatcher(
          asylo::host_call::kSysconfHandler, &input, &output);
  if (!status.ok()) {
    abort();
  }

  int64_t result = output.next<int>();
  if (result == -1) {
    int klinux_errno = output.next<int>();
    int enclave_errno;
    FromkLinuxErrorNumber(&klinux_errno, &enclave_errno);
    errno = enclave_errno;
  }

  return result;
}

int enc_untrusted_close(int fd) {
  return enc_untrusted_syscall(asylo::system_call::kSYS_close, fd);
}

ssize_t enc_untrusted_read_with_untrusted_ptr(int fd, void *untrusted_buf,
                                              size_t size) {
  ::asylo::primitives::MessageWriter input;
  input.Push<int>(fd);
  input.Push<uint64_t>(reinterpret_cast<uint64_t>(untrusted_buf));
  input.Push<uint64_t>(static_cast<uint64_t>(size));

  ::asylo::primitives::MessageReader output;
  asylo::primitives::PrimitiveStatus status =
      asylo::host_call::NonSystemCallDispatcher(
          asylo::host_call::kReadWithUntrustedPtr, &input, &output);
  if (!status.ok()) {
    abort();
  }

  auto result = output.next<ssize_t>();
  if (result == -1) {
    int klinux_errno = output.next<int>();
    int enclave_errno;
    FromkLinuxErrorNumber(&klinux_errno, &enclave_errno);
    errno = enclave_errno;
  }

  return result;
}

void *enc_untrusted_realloc(void *ptr, size_t size) {
  ::asylo::primitives::MessageWriter input;
  input.Push(reinterpret_cast<uint64_t>(ptr));
  input.Push(static_cast<uint64_t>(size));

  ::asylo::primitives::MessageReader output;
  asylo::primitives::PrimitiveStatus status =
      asylo::host_call::NonSystemCallDispatcher(
          asylo::host_call::kReallocHandler, &input, &output);

  if (!status.ok()) {
    abort();
  }
  void *result = output.next<void *>();

  // realloc only sets the errno (ENOMEM) when output pointer is null and a
  // non-zero |size| is provided.
  if (result == nullptr && size != 0) {
    int klinux_errno = output.next<int>();
    int enclave_errno;
    FromkLinuxErrorNumber(&klinux_errno, &enclave_errno);
    errno = enclave_errno;
  }
  return result;
}

uint32_t enc_untrusted_sleep(uint32_t seconds) {
  ::asylo::primitives::MessageWriter input;
  input.Push<uint32_t>(seconds);
  ::asylo::primitives::MessageReader output;
  asylo::primitives::PrimitiveStatus status =
      asylo::host_call::NonSystemCallDispatcher(asylo::host_call::kSleepHandler,
                                                &input, &output);
  if (!status.ok()) {
    abort();
  }

  // Returns sleep's return value directly since it doesn't set errno.
  return output.next<uint32_t>();
}

}  // extern "C"
