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

#ifndef ASYLO_PLATFORM_HOST_CALL_TRUSTED_HOST_CALLS_H_
#define ASYLO_PLATFORM_HOST_CALL_TRUSTED_HOST_CALLS_H_

// Defines the C language interface to the untrusted host environment. These
// functions invoke code outside the enclave and secure applications must assume
// an adversarial implementation.

#include <fcntl.h>
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
int enc_untrusted_access(const char *path_name, int mode);
int enc_untrusted_close(int fd);
pid_t enc_untrusted_getpid();
int enc_untrusted_kill(pid_t pid, int sig);
int enc_untrusted_link(const char *oldpath, const char *newpath);
off_t enc_untrusted_lseek(int fd, off_t offset, int whence);
int enc_untrusted_mkdir(const char *pathname, mode_t mode);
int enc_untrusted_open(const char *pathname, int flags, ...);
int enc_untrusted_unlink(const char *pathname);
uid_t enc_untrusted_getuid();
gid_t enc_untrusted_getgid();
uid_t enc_untrusted_geteuid();
gid_t enc_untrusted_getegid();
int enc_untrusted_rename(const char *oldpath, const char *newpath);
ssize_t enc_untrusted_read(int fd, void *buf, size_t count);
ssize_t enc_untrusted_write(int fd, const void *buf, size_t count);
int enc_untrusted_symlink(const char *target, const char *linkpath);
ssize_t enc_untrusted_readlink(const char *pathname, char *buf, size_t bufsiz);
int enc_untrusted_truncate(const char *path, off_t length);
int enc_untrusted_rmdir(const char *path);
int enc_untrusted_socket(int domain, int type, int protocol);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // ASYLO_PLATFORM_HOST_CALL_TRUSTED_HOST_CALLS_H_
