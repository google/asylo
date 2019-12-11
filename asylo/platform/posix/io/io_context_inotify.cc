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
#include "asylo/platform/posix/io/io_context_inotify.h"

#include <sys/inotify.h>

#include "asylo/platform/common/memory.h"
#include "asylo/platform/host_call/serializer_functions.h"
#include "asylo/platform/host_call/trusted/host_calls.h"

namespace asylo {
namespace io {

int IOContextInotify::GetHostFileDescriptor() { return host_fd_; }

int IOContextInotify::InotifyAddWatch(const char *pathname, uint32_t mask) {
  return enc_untrusted_inotify_add_watch(host_fd_, pathname, mask);
}

int IOContextInotify::InotifyRmWatch(int wd) {
  return enc_untrusted_inotify_rm_watch(host_fd_, wd);
}

size_t IOContextInotify::TransferFromQueueToBuffer(char *buf_ptr,
                                                   size_t count) {
  size_t num_bytes_written = 0;
  while (!event_queue_.empty()) {
    struct inotify_event *front_event = event_queue_.front();
    size_t front_event_len = sizeof(struct inotify_event) + front_event->len;
    if (count < front_event_len) {
      return num_bytes_written;
    }
    memcpy(buf_ptr, front_event, front_event_len);
    buf_ptr += front_event_len;
    num_bytes_written += front_event_len;
    count -= front_event_len;
    asylo::MallocUniquePtr<struct inotify_event> ev_ptr(front_event);
    event_queue_.pop();
  }
  return num_bytes_written;
}

ssize_t IOContextInotify::Read(void *buf, size_t count) {
  // Remove events from queue, if there are any.
  char *buf_ptr = static_cast<char *>(buf);
  size_t num_bytes_written = TransferFromQueueToBuffer(buf_ptr, count);
  buf_ptr += num_bytes_written;
  count -= num_bytes_written;
  // Check if the buffer was too small.
  if (!event_queue_.empty() && (num_bytes_written == 0)) {
    errno = EINVAL;
    return -1;
  } else if (!event_queue_.empty() || count == 0) {
    // No need to read events from the host if the queue is not empty.
    return num_bytes_written;
  }
  // Read serialized events from the host, adjusting for space left in buffer.
  char *serialized_events = nullptr;
  size_t serialized_events_len = 0;
  if (enc_untrusted_inotify_read(host_fd_, count, &serialized_events,
                                 &serialized_events_len) < 0) {
    // errno is set by enc_untrusted_inotify_read.
    return -1;
  }
  asylo::MallocUniquePtr<char> serialized_events_ptr(serialized_events);
  // Extract events back into the queue.
  if (!asylo::host_call::DeserializeInotifyEvents(
          serialized_events, serialized_events_len, &event_queue_)) {
    errno = EBADE;
    return -1;
  }
  // Transfer events from the queue into the buffer again (as much as possible).
  num_bytes_written += TransferFromQueueToBuffer(buf_ptr, count);
  if (!event_queue_.empty() && (num_bytes_written == 0)) {
    errno = EINVAL;
    return -1;
  }
  return num_bytes_written;
}

ssize_t IOContextInotify::Write(const void *buf, size_t count) {
  errno = EBADF;
  return -1;
}

int IOContextInotify::Close() { return enc_untrusted_close(host_fd_); }

}  // namespace io
}  // namespace asylo
