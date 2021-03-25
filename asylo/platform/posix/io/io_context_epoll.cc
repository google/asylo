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
#include "asylo/platform/posix/io/io_context_epoll.h"

#include <errno.h>
#include <openssl/rand.h>
#include <stdint.h>

#include "absl/memory/memory.h"
#include "asylo/platform/host_call/trusted/host_calls.h"

namespace asylo {
namespace io {

int IOContextEpoll::EpollCtl(int op, int hostfd, struct epoll_event *event) {
  struct epoll_event event_copy = {};
  if (event) {
    event_copy.events = event->events;
  }
  if (op == EPOLL_CTL_ADD) {
    uint64_t key = 0;
    do {
      if (RAND_bytes(reinterpret_cast<uint8_t *>(&key),
                     sizeof(uint64_t)) != 1) {
        errno = EBADE;
        return -1;
      }
    } while (key_to_data.find(key) != key_to_data.end());
    key_to_data[key] = event->data.u64;
    fd_to_key[hostfd] = key;
    event_copy.data.u64 = key;
  } else if (op == EPOLL_CTL_MOD) {
    if (fd_to_key.find(hostfd) == fd_to_key.end()) {
      errno = ENOENT;
      return -1;
    }
    uint64_t key = fd_to_key[hostfd];
    key_to_data[key] = event->data.u64;
    event_copy.data.u64 = key;
  } else if (op == EPOLL_CTL_DEL) {
    if (fd_to_key.find(hostfd) == fd_to_key.end()) {
      errno = ENOENT;
      return -1;
    }
    uint64_t key = fd_to_key[hostfd];
    event_copy.data.u64 = key;
    fd_to_key.erase(hostfd);
    key_to_data.erase(key);
  } else {
    return -1;
  }
  return enc_untrusted_epoll_ctl(host_fd_, op, hostfd, &event_copy);
}

int IOContextEpoll::EpollWait(struct epoll_event *events, int maxevents,
                              int timeout) {
  int ret = enc_untrusted_epoll_wait(host_fd_, events, maxevents, timeout);
  if (ret == -1) {
    // errno is set in enc_untrusted_epoll_wait.
    return -1;
  }
  // Convert the random bits in the data field back to the original data using
  // the key_to_data map.
  for (int i = 0; i < ret; ++i) {
    uint64_t key = events[i].data.u64;
    if (key_to_data.find(key) == key_to_data.end()) {
      errno = EBADE;
      return -1;
    }
    events[i].data.u64 = key_to_data[key];
  }
  return ret;
}

int IOContextEpoll::GetHostFileDescriptor() { return host_fd_; }

// Read and Write should never be called on an epoll fd.
ssize_t IOContextEpoll::Read(void *buf, size_t count) {
  errno = EBADF;
  return -1;
}

ssize_t IOContextEpoll::Write(const void *buf, size_t count) {
  errno = EBADF;
  return -1;
}

int IOContextEpoll::Close() { return enc_untrusted_close(host_fd_); }

}  // namespace io
}  // namespace asylo
