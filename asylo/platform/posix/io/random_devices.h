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

#ifndef ASYLO_PLATFORM_POSIX_IO_RANDOM_DEVICES_H_
#define ASYLO_PLATFORM_POSIX_IO_RANDOM_DEVICES_H_

#include <sys/stat.h>
#include "asylo/platform/posix/io/io_manager.h"

namespace asylo {

// IOContext implementation that returns random data on reads.
class RandomIOContext : public io::IOManager::IOContext {
 public:
  RandomIOContext(bool is_urandom, int fd) : is_urandom_(is_urandom), fd_(fd) {}
  const bool &IsURandom() const { return is_urandom_; }

 protected:
  ssize_t Read(void *buf, size_t count) override;
  ssize_t Write(const void *buf, size_t count) override;
  int Close() override;
  int LSeek(off_t offset, int whence) override;
  int FSync() override;
  int FStat(struct stat *stat_buffer) override;
  int Isatty() override;
  int Ioctl(int request, void *argp) override;

 private:
  bool is_urandom_;
  int fd_;
};

// VirtualPathHandler implementation that represents random devices.
class RandomPathHandler : public io::IOManager::VirtualPathHandler {
 public:
  static constexpr const char *const kRandomPath = "/dev/random";
  static constexpr const char *const kURandomPath = "/dev/urandom";

 protected:
  std::unique_ptr<io::IOManager::IOContext> Open(const char *path, int flags,
                                                 mode_t mode) override;

  int Chown(const char *path, uid_t owner, gid_t group) override;

  int Link(const char *existing, const char *new_link) override;

  ssize_t ReadLink(const char *path_name, char *buf, size_t bufsize) override;

  int SymLink(const char *path1, const char *path2) override;

  int Stat(const char *pathname, struct stat *stat_buffer) override;

  int LStat(const char *pathname, struct stat *stat_buffer) override;

  int Unlink(const char *pathname) override;
};

}  // namespace asylo

#endif  // ASYLO_PLATFORM_POSIX_IO_RANDOM_DEVICES_H_
