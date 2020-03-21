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

#include "asylo/platform/posix/io/random_devices.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>  // Only included for the transitional define.
#if __has_include(<linux/random.h>)
#include <linux/random.h>
#endif
#include <string.h>
#include <sys/sysmacros.h>

#include "absl/memory/memory.h"
#include "asylo/platform/host_call/trusted/host_calls.h"
#include "asylo/platform/primitives/random_bytes.h"
#include "asylo/platform/primitives/trusted_runtime.h"

namespace asylo {
namespace {

int GetStat(struct stat *stat_buffer, bool is_urandom) {
  // Set the values of |stat_buffer| according to the values used in Linux
  // random files (Documentation/admin-guide/devices.txt).
  static constexpr unsigned int major_dev = 0;
  static constexpr unsigned int minor_dev = 0;
  static constexpr unsigned int major_rdev = 1;
  const unsigned int minor_rdev = is_urandom ? 9 : 8;

  static constexpr unsigned int mode =
      S_IFCHR | S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;
  static constexpr unsigned int blksize = 4096;

  stat_buffer->st_dev = makedev(major_dev, minor_dev);
  stat_buffer->st_ino = -1;
  stat_buffer->st_mode = mode;
  stat_buffer->st_nlink = 0;
  stat_buffer->st_uid = 0;
  stat_buffer->st_gid = 0;
  stat_buffer->st_rdev = makedev(major_rdev, minor_rdev);
  stat_buffer->st_size = 0;
  stat_buffer->st_blksize = blksize;
  stat_buffer->st_blocks = 0;

  return 0;
}

}  // namespace

ssize_t RandomIOContext::Read(void *buf, size_t count) {
  if (fd_ >= 0) {
    // If RDRAND isn't supported, then fall back on the host's randomness.
    return enc_untrusted_read(fd_, buf, count);
  }
  // Delegate to architecture-specific implementation to generate random numbers
  return enc_hardware_random(reinterpret_cast<uint8_t *>(buf), count);
}

ssize_t RandomIOContext::Write(const void *buf, size_t count) {
  // Read-only
  errno = EBADF;
  return -1;
}

int RandomIOContext::Close() {
  if (fd_ >= 0) {
    return enc_untrusted_close(fd_);
  }
  return 0;
}

int RandomIOContext::LSeek(off_t offset, int whence) {
  // Nothing to do.
  return 0;
}

int RandomIOContext::FSync() {
  // Nothing to do.
  return 0;
}

int RandomIOContext::FStat(struct stat *stat_buffer) {
  return GetStat(stat_buffer, IsURandom());
}

int RandomIOContext::Isatty() {
  // Returns 0 as our random devices are not terminals.
  return 0;
}

int RandomIOContext::Ioctl(int request, void *argp) {
  switch (request) {
    #ifdef RNDGETENTCNT
      case RNDGETENTCNT: {
      int result = enc_hardware_random_entropy();
      if (result) {
        return result;
      }
      return enc_untrusted_syscall(asylo::system_call::kSYS_ioctl, request,
                                   argp);
    }
    #endif
    #ifdef RNDINENCLAVE
    // Nonstandard request to random device fd for cwd_test.
    case RNDINENCLAVE: {
      return 0;
    }
    #endif
  default:
    errno = EINVAL;
    return -1;
  }
}

std::unique_ptr<io::IOManager::IOContext> RandomPathHandler::Open(
    const char *path, int flags, mode_t mode) {
  bool is_random = strcmp(path, kRandomPath) == 0;
  bool is_urandom = strcmp(path, kURandomPath) == 0;
  if (is_random || is_urandom) {
    int fd = -1;
    if (!rdrand_supported()) {
        fd = enc_untrusted_open(path, flags, mode);
        if (fd < 0) {
          return nullptr;
        }
    }
    errno = 0;
    return ::absl::make_unique<RandomIOContext>(is_urandom, fd);
  }

  errno = ENOENT;
  return nullptr;
}

int RandomPathHandler::Chown(const char *path, uid_t owner, gid_t group) {
  errno = ENOSYS;
  return -1;
}

int RandomPathHandler::Link(const char *existing, const char *new_link) {
  errno = ENOSYS;
  return -1;
}

int RandomPathHandler::Unlink(const char *pathname) {
  errno = EPERM;
  return -1;
}

ssize_t RandomPathHandler::ReadLink(const char *path_name, char *buf,
                                    size_t bufsize) {
  errno = ENOSYS;
  return -1;
}

int RandomPathHandler::SymLink(const char *path1, const char *path2) {
  errno = ENOSYS;
  return -1;
}

int RandomPathHandler::Stat(const char *pathname, struct stat *stat_buffer) {
  bool is_random = strcmp(pathname, kRandomPath) == 0;
  bool is_urandom = strcmp(pathname, kURandomPath) == 0;
  if (is_random || is_urandom) {
    return GetStat(stat_buffer, is_urandom);
  }
  errno = ENOENT;
  return -1;
}

int RandomPathHandler::LStat(const char *pathname, struct stat *stat_buffer) {
  return Stat(pathname, stat_buffer);
}

}  // namespace asylo
