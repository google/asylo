/*
 *
 * Copyright 2017 Asylo authors
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

// Implementation of POSIX I/O functions. Each of these wraps a call to the
// IOManager, which in turn will delegate the actual operation to the
// appropriate I/O subsystem.

#include <enclave/enclave_syscalls.h>

#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>

#include "asylo/platform/posix/io/io_manager.h"

using asylo::io::IOManager;

extern "C" {

int enclave_close(int fd) { return IOManager::GetInstance().Close(fd); }

int enclave_open(const char *path_name, int flags, int mode) {
  return IOManager::GetInstance().Open(path_name, flags, mode);
}

int enclave_read(int fd, char *buf, int count) {
  return IOManager::GetInstance().Read(fd, static_cast<char *>(buf), count);
}

int enclave_write(int fd, const char *buf, int count) {
  return IOManager::GetInstance().Write(fd, buf, count);
}

int enclave_fcntl(int fd, int cmd, int64_t arg) {
  return IOManager::GetInstance().FCntl(fd, cmd, arg);
}

int enclave_lseek(int fd, int ptr, int dir) {
  return IOManager::GetInstance().LSeek(fd, ptr, dir);
}

int enclave_link(const char *existing, const char *new_link) {
  return IOManager::GetInstance().Link(existing, new_link);
}

int enclave_mkdir(const char *pathname, mode_t mode) {
  return IOManager::GetInstance().Mkdir(pathname, mode);
}

int enclave_stat(const char *file, struct stat *st) {
  return IOManager::GetInstance().Stat(file, st);
}

}  // extern "C"
