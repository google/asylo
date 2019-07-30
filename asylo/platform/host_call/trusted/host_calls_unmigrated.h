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

#ifndef ASYLO_PLATFORM_HOST_CALL_TRUSTED_HOST_CALLS_UNMIGRATED_H_
#define ASYLO_PLATFORM_HOST_CALL_TRUSTED_HOST_CALLS_UNMIGRATED_H_

// Defines the C language interface to the untrusted host environment. These
// functions invoke code outside the enclave and secure applications must assume
// an adversarial implementation.

#include <fcntl.h>
#include <sys/socket.h>

#include <cstdarg>
#include <cstddef>
#include <cstdint>

#include "asylo/platform/system_call/sysno.h"
#include "asylo/platform/system_call/system_call.h"

#ifdef __cplusplus
extern "C" {
#endif

// Unless otherwise specified, each of the following calls invokes the
// corresponding function on the host.
int enc_untrusted_close(int fd);
int enc_untrusted_kill(pid_t pid, int sig);
int enc_untrusted_link(const char *oldpath, const char *newpath);
off_t enc_untrusted_lseek(int fd, off_t offset, int whence);
int enc_untrusted_mkdir(const char *pathname, mode_t mode);
int enc_untrusted_open(const char *pathname, int flags, ...);
int enc_untrusted_unlink(const char *pathname);
int enc_untrusted_rename(const char *oldpath, const char *newpath);
ssize_t enc_untrusted_read(int fd, void *buf, size_t count);
ssize_t enc_untrusted_write(int fd, const void *buf, size_t count);
int enc_untrusted_symlink(const char *target, const char *linkpath);
ssize_t enc_untrusted_readlink(const char *pathname, char *buf, size_t bufsiz);
int enc_untrusted_truncate(const char *path, off_t length);
int enc_untrusted_ftruncate(int fd, off_t length);
int enc_untrusted_rmdir(const char *path);
int enc_untrusted_socket(int domain, int type, int protocol);
int enc_untrusted_listen(int sockfd, int backlog);
int enc_untrusted_shutdown(int sockfd, int how);
ssize_t enc_untrusted_send(int sockfd, const void *buf, size_t len, int flags);
int enc_untrusted_fcntl(int fd, int cmd, ... /* arg */);
int enc_untrusted_chown(const char *pathname, uid_t owner, gid_t group);
int enc_untrusted_fchown(int fd, uid_t owner, gid_t group);
int enc_untrusted_setsockopt(int sockfd, int level, int optname,
                             const void *optval, socklen_t optlen);
int enc_untrusted_flock(int fd, int operation);
int enc_untrusted_fsync(int fd);
int enc_untrusted_inotify_init1(int flags);
int enc_untrusted_inotify_add_watch(int fd, const char *pathname,
                                    uint32_t mask);
int enc_untrusted_inotify_rm_watch(int fd, int wd);
mode_t enc_untrusted_umask(mode_t mask);
int enc_untrusted_chmod(const char *path, mode_t mode);
int enc_untrusted_fchmod(int fd, mode_t mode);
int enc_untrusted_sched_yield();
int enc_untrusted_fstat(int fd, struct stat *statbuf);
int enc_untrusted_lstat(const char *pathname, struct stat *statbuf);
int enc_untrusted_stat(const char *pathname, struct stat *statbuf);
int enc_untrusted_pread64(int fd, void *buf, size_t count, off_t offset);
int enc_untrusted_pwrite64(int fd, const void *buf, size_t count, off_t offset);
int enc_untrusted_pipe2(int pipefd[2], int flags);

// Non-syscall hostcalls (libc library based hostcalls) are defined below.
int enc_untrusted_isatty(int fd);
int enc_untrusted_usleep(useconds_t usec);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // ASYLO_PLATFORM_HOST_CALL_TRUSTED_HOST_CALLS_UNMIGRATED_H_
