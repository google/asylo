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

#include <limits.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdlib>
#include <cstring>

#include "asylo/platform/core/trusted_global_state.h"
#include "asylo/platform/host_call/trusted/host_calls.h"
#include "asylo/platform/posix/io/io_manager.h"
#include "asylo/platform/primitives/trusted_primitives.h"
#include "asylo/platform/primitives/trusted_runtime.h"
#include "asylo/util/posix_errors.h"
#include "asylo/util/statusor.h"

using asylo::io::IOManager;

// Simulated page size, used by the POSIX wrappers.
constexpr size_t kPageSize = 4096;

namespace {

pid_t ForkEnclave() {
  asylo::StatusOr<const asylo::EnclaveConfig *> config_result =
      asylo::GetEnclaveConfig();

  if (!config_result.ok()) {
    errno = EFAULT;
    return -1;
  }

  const asylo::EnclaveConfig *config = config_result.value();
  if (!config->has_enable_fork()) {
    errno = EFAULT;
    return -1;
  }
  if (!config->enable_fork()) {
    errno = ENOSYS;
    return -1;
  }

  return asylo::enc_fork(asylo::GetEnclaveName().c_str());
}

}  // namespace

extern "C" {

int access(const char *path_name, int mode) {
  return IOManager::GetInstance().Access(path_name, mode);
}

int chown(const char *path, uid_t owner, gid_t group) {
  return IOManager::GetInstance().Chown(path, owner, group);
}

int fchown(int fd, uid_t owner, gid_t group) {
  return IOManager::GetInstance().FChOwn(fd, owner, group);
}

ssize_t readlink(const char *path_name, char *buf, size_t bufsize) {
  return IOManager::GetInstance().ReadLink(path_name, buf, bufsize);
}

int symlink(const char *path1, const char *path2) {
  return IOManager::GetInstance().SymLink(path1, path2);
}

int pipe(int pipefd[2]) { return IOManager::GetInstance().Pipe(pipefd, 0); }

int pipe2(int pipefd[2], int flags) {
  return IOManager::GetInstance().Pipe(pipefd, flags);
}

int gethostname(char *name, size_t len) {
  asylo::StatusOr<const asylo::EnclaveConfig *> config_result =
      asylo::GetEnclaveConfig();

  if (!config_result.ok()) {
    errno = EFAULT;
    return -1;
  }

  const asylo::EnclaveConfig *config = config_result.value();
  if (!config->has_host_name()) {
    errno = EFAULT;
    return -1;
  }
  std::string host_name = config->host_name();
  int size = host_name.size();
#ifdef HOST_NAME_MAX
  // The host name size is limited to HOST_NAME_MAX (without the trailing zero).
  if (size >= HOST_NAME_MAX) {
    size = HOST_NAME_MAX;
  }
#endif
  // Truncate |host_name| if longer than size of the buffer.
  if (size >= len) {
    size = len - 1;
  }

  memcpy(name, host_name.c_str(), size);
  name[size] = '\0';
  return 0;
}

// Only _SC_NPROCESSORS_ONLN, _SC_NPROCESSORS_CONF, and _SC_PAGESIZE are
// supported for now. _SC_NPROCESSORS_CONF and _SC_NOPROCESSORS_ONLN retrieve
// the return value from the host because processor resources are under control
// of the host. _SC_PAGESIZE is hard-coded because a malicious value returned by
// a host could result in undesired behavior. For any other arguments, -1 is
// returned.
long sysconf(int name) {
  switch (name) {
    case _SC_NPROCESSORS_CONF:
    case _SC_NPROCESSORS_ONLN:
      return enc_untrusted_sysconf(name);
    case _SC_PAGESIZE:
      // Hard-code a reasonable guess for the page size, without having to
      // make an untrusted call.
      return kPageSize;
    default:
      errno = ENOSYS;
      return -1;
  }
}

int getpagesize() { return kPageSize; }

uint32_t sleep(uint32_t seconds) { return enc_untrusted_sleep(seconds); }

int usleep(useconds_t usec) { return enc_untrusted_usleep(usec); }

// For dup() and dup2() we do not exit enclave to call dup() or dup() on host.
// Instead, we create a new reference to the same host file descriptor in
// IOManager. Therefore the FD_CLOEXEC flag of the new file descriptor will be
// the same as the old one, as opposed to what dup() and dup2() behaves normally
// (FD_CLOEXEC may be different).
int dup(int oldfd) { return IOManager::GetInstance().Dup(oldfd); }

// See the comment for dup().
int dup2(int oldfd, int newfd) {
  return IOManager::GetInstance().Dup2(oldfd, newfd);
}

int fsync(int fd) { return IOManager::GetInstance().FSync(fd); }

int fdatasync(int fd) { return IOManager::GetInstance().FDataSync(fd); }

char *getcwd(char *buf, size_t bufsize) {
  asylo::StatusOr<const asylo::EnclaveConfig *> config_result =
      asylo::GetEnclaveConfig();

  // It is possible for global constructors to call getcwd prior to us
  // initializing the enclave.  In this case, return a placeholder value.
  if (!config_result.ok()) {
    const char *dir = "./";
    memcpy(buf, dir, 3);
    return buf;
  }

  std::string current_working_directory =
      IOManager::GetInstance().GetCurrentWorkingDirectory();
  int size = current_working_directory.size();

  if (current_working_directory.empty()) {
    errno = ENOENT;
    return nullptr;
  }

  // Verify the buffer size.
  if (!buf && !bufsize) bufsize = size + 1;
  if (bufsize <= size) {
    errno = ERANGE;
    return nullptr;
  }

  // If |buf| is null, allocate one.
  if (!buf) {
    buf = reinterpret_cast<char *>(malloc(bufsize));
    if (!buf) {
      errno = ENOMEM;
      return nullptr;
    }
  }

  // Copy into provided buffer.
  current_working_directory.copy(buf, size);
  buf[size] = '\0';

  return buf;
}

int chdir(const char *path) {
  asylo::Status status =
      IOManager::GetInstance().SetCurrentWorkingDirectory(path);
  if (!status.ok()) {
    errno = GetErrno(status);
    return -1;
  }

  return 0;
}

int rmdir(const char *pathname) {
  return IOManager::GetInstance().RmDir(pathname);
}

uid_t getuid() { return enc_untrusted_getuid(); }

uid_t geteuid() { return enc_untrusted_geteuid(); }

gid_t getgid() { return enc_untrusted_getgid(); }

gid_t getegid() { return enc_untrusted_getegid(); }

pid_t getppid() { return enc_untrusted_getppid(); }

pid_t setsid() { return enc_untrusted_setsid(); }

int truncate(const char *path, off_t length) {
  return IOManager::GetInstance().Truncate(path, length);
}

int ftruncate(int fd, off_t length) {
  return IOManager::GetInstance().FTruncate(fd, length);
}

pid_t vfork() {
  pid_t ret = ForkEnclave();
  if (ret < 0) {
    return ret;
  }
  // Suspend the parent and waits till the child finishes.
  if (ret != 0) {
    int status;
    if (wait(&status) == -1) {
      // Errno is set by wait() call.
      return -1;
    }
  }
  return ret;
}

ssize_t pread(int fd, void *buf, size_t count, off_t offset) {
  return IOManager::GetInstance().PRead(fd, buf, count, offset);
}

// The functions below are prefixed with |enclave_|, as they are plumbed in from
// newlib.
int enclave_getpid() {
  int pid = enc_untrusted_getpid();
  if (pid == 0) {
    ::asylo::primitives::TrustedPrimitives::BestEffortAbort(
        "FATAL ERROR: Host returned 0 from getpid()");
  }
  return pid;
}

int enclave_fstat(int fd, struct stat *st) {
  return IOManager::GetInstance().FStat(fd, st);
}

int enclave_isatty(int fd) { return IOManager::GetInstance().Isatty(fd); }

int enclave_unlink(const char *pathname) {
  return IOManager::GetInstance().Unlink(pathname);
}

void enclave_exit(int rc) {
  while (true) {
    enc_exit(rc);
  }
}

pid_t enclave_fork() { return ForkEnclave(); }

}  // extern "C"
