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

  return enc_untrusted_syscall(asylo::system_call::kSYS_open, pathname,
                               TokLinuxFileStatusFlag(flags), mode);
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
  return enc_untrusted_syscall(asylo::system_call::kSYS_read, fd, buf, count);
}

ssize_t enc_untrusted_write(int fd, const void *buf, size_t count) {
  return enc_untrusted_syscall(asylo::system_call::kSYS_write, fd, buf, count);
}

int enc_untrusted_symlink(const char *target, const char *linkpath) {
  return enc_untrusted_syscall(asylo::system_call::kSYS_symlink, target,
                               linkpath);
}

ssize_t enc_untrusted_readlink(const char *pathname, char *buf, size_t bufsiz) {
  return enc_untrusted_syscall(asylo::system_call::kSYS_readlink, pathname, buf,
                               bufsiz);
}

int enc_untrusted_truncate(const char *path, off_t length) {
  return enc_untrusted_syscall(asylo::system_call::kSYS_truncate, path, length);
}

int enc_untrusted_rmdir(const char *path) {
  return enc_untrusted_syscall(asylo::system_call::kSYS_rmdir, path);
}

int enc_untrusted_socket(int domain, int type, int protocol) {
  return enc_untrusted_syscall(asylo::system_call::kSYS_socket,
                               TokLinuxAfFamily(domain),
                               TokLinuxSocketType(type), protocol);
}

int enc_untrusted_fcntl(int fd, int cmd, ... /* arg */) {
  // We do not currently support file locks in Asylo, so arg is not expected to
  // be a pointer to struct flock.
  int64_t arg = 0;
  va_list ap;
  va_start(ap, cmd);
  arg = va_arg(ap, int64_t);
  va_end(ap);

  int kLinux_cmd = TokLinuxFcntlCommand(cmd);
  if (kLinux_cmd == -1) {
    errno = EINVAL;
    return -1;
  }

  switch (cmd) {
    case F_SETFL: {
      return enc_untrusted_syscall(asylo::system_call::kSYS_fcntl, fd,
                                   kLinux_cmd, TokLinuxFileStatusFlag(arg));
    }
    case F_SETFD: {
      return enc_untrusted_syscall(asylo::system_call::kSYS_fcntl, fd,
                                   kLinux_cmd, TokLinuxFDFlag(arg));
    }
    case F_GETFL: {
      int result = enc_untrusted_syscall(asylo::system_call::kSYS_fcntl, fd,
                                         kLinux_cmd, arg);
      if (result != -1) {
        result = FromkLinuxFileStatusFlag(result);
      }

      return result;
    }
    case F_GETFD: {
      int result = enc_untrusted_syscall(asylo::system_call::kSYS_fcntl, fd,
                                         kLinux_cmd, arg);
      if (result != -1) {
        result = FromkLinuxFDFlag(result);
      }
      return result;
    }
    case F_GETPIPE_SZ:
    case F_SETPIPE_SZ: {
      return enc_untrusted_syscall(asylo::system_call::kSYS_fcntl, fd,
                                   kLinux_cmd, arg);
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

}  // extern "C"
