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

#ifndef ASYLO_PLATFORM_POSIX_IO_IO_CONTEXT_EPOLL_H_
#define ASYLO_PLATFORM_POSIX_IO_IO_CONTEXT_EPOLL_H_

#include <unordered_map>

#include "asylo/platform/posix/io/io_manager.h"

namespace asylo {
namespace io {
// IOContext implementation wrapping an epoll file descriptor
class IOContextEpoll : public IOManager::IOContext {
 public:
  explicit IOContextEpoll(int host_fd) : host_fd_(host_fd) {}
  // It's important to note that adding dup'd file descriptors here won't work
  // the same as it would in POSIX.
  int EpollCtl(int op, int hostfd, struct epoll_event *event) override;
  int EpollWait(struct epoll_event *events, int maxevents,
                int timeout) override;
  int GetHostFileDescriptor() override;
  ssize_t Read(void *buf, size_t count);
  ssize_t Write(const void *buf, size_t count);
  int Close();

 private:
  // Host file descriptor implementing this stream.
  int host_fd_;
  std::unordered_map<uint64_t, uint64_t> key_to_data;
  // Manages a mapping from the host file descriptor to a random key to enable
  // updates to the above map durring deletions/modifications.
  std::unordered_map<int, uint64_t> fd_to_key;
};

}  // namespace io
}  // namespace asylo

#endif  // ASYLO_PLATFORM_POSIX_IO_IO_CONTEXT_EPOLL_H_
