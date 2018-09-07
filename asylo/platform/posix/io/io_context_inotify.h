/*
 *
 * Copyright 2018 Asylo authors
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

#ifndef ASYLO_PLATFORM_POSIX_IO_IO_CONTEXT_INOTIFY_H_
#define ASYLO_PLATFORM_POSIX_IO_IO_CONTEXT_INOTIFY_H_

#include <sys/inotify.h>

#include <queue>
#include "asylo/platform/posix/io/io_manager.h"

namespace asylo {
namespace io {
// IOContext implementation wrapping an epoll file descriptor
class IOContextInotify : public IOManager::IOContext {
 public:
  explicit IOContextInotify(int host_fd) : host_fd_(host_fd) {}
  // It's important to note that adding dup'd file descriptors here won't work
  // the same as it would in POSIX.
  int GetHostFileDescriptor() override;
  int InotifyAddWatch(const char *pathname, uint32_t mask) override;
  int InotifyRmWatch(int wd) override;
  ssize_t Read(void *buf, size_t count) override;
  ssize_t Write(const void *buf, size_t count) override;
  int Close() override;

 private:
  size_t TransferFromQueueToBuffer(char *buf_ptr, size_t count);
  // Host file descriptor implementing this stream.
  int host_fd_;
  std::queue<struct inotify_event *> event_queue_;
};

}  // namespace io
}  // namespace asylo

#endif  // ASYLO_PLATFORM_POSIX_IO_IO_CONTEXT_INOTIFY_H_
