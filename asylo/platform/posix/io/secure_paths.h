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

#ifndef ASYLO_PLATFORM_POSIX_IO_SECURE_PATHS_H_
#define ASYLO_PLATFORM_POSIX_IO_SECURE_PATHS_H_

#include "asylo/platform/posix/io/io_manager.h"

namespace asylo {
namespace io {

// IOContext implementation wrapping a stream managed by the secure I/O layer.
class IOContextSecure : public IOManager::IOContext {
 public:
  // Factory method to create an instance of the class.
  static std::unique_ptr<IOManager::IOContext> Create(const char *path,
                                                      int flags, mode_t mode) {
    int host_fd = platform::storage::secure_open(path, flags, mode);
    if (host_fd == -1) {
      return nullptr;
    }
    return std::unique_ptr<IOManager::IOContext>(new IOContextSecure(host_fd));
  }

 protected:
  ssize_t Read(void *buf, size_t count) override;
  ssize_t Write(const void *buf, size_t count) override;
  int Close() override;
  int LSeek(off_t offset, int whence) override;
  int FSync() override;
  int FStat(struct stat *st) override;
  int Isatty() override;
  int Ioctl(int request, void *argp) override;

 private:
  explicit IOContextSecure(int host_fd) : host_fd_(host_fd) {}

  // Host-provided file descriptor of the backing store.
  int host_fd_;
};

}  // namespace io
}  // namespace asylo

#endif  // ASYLO_PLATFORM_POSIX_IO_SECURE_PATHS_H_
