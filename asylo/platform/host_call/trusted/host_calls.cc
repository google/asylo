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

#include "asylo/platform/system_call/type_conversions/types_functions.h"

extern "C" {

int enc_untrusted_access(const char *path_name, int mode) {
  return enc_untrusted_syscall(asylo::system_call::kSYS_access, path_name,
                               mode);
}

int enc_untrusted_close(int fd) {
  return enc_untrusted_syscall(asylo::system_call::kSYS_close, fd);
}

pid_t enc_untrusted_getpid() {
  return enc_untrusted_syscall(asylo::system_call::kSYS_getpid);
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
  uint32_t mode = 0;
  if (flags & O_CREAT) {
    va_list ap;
    va_start(ap, flags);
    mode = va_arg(ap, mode_t);
    va_end(ap);
  }

  int klinux_flags;
  TokLinuxFileStatusFlag(&flags, &klinux_flags);
  return enc_untrusted_syscall(asylo::system_call::kSYS_open, pathname,
                               klinux_flags, mode);
}

int enc_untrusted_unlink(const char *pathname) {
  return enc_untrusted_syscall(asylo::system_call::kSYS_unlink, pathname);
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

int enc_untrusted_rmdir(const char *path) {
  return enc_untrusted_syscall(asylo::system_call::kSYS_rmdir, path);
}

int enc_untrusted_socket(int domain, int type, int protocol) {
  int klinux_domain;
  int klinux_type;
  TokLinuxAfFamily(&domain, &klinux_domain);
  TokLinuxSocketType(&type, &klinux_type);
  return enc_untrusted_syscall(asylo::system_call::kSYS_socket, klinux_domain,
                               klinux_type, protocol);
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

}  // extern "C"
