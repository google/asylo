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
#include "asylo/platform/posix/io/io_context_eventfd.h"

constexpr uint64_t kMaxCounter = 0xfffffffffffffffe;
constexpr ssize_t kCounterBufSize = sizeof(uint64_t);

namespace asylo {
namespace io {

ssize_t IOContextEventFd::Read(void *buf, size_t count) {
  if (count < kCounterBufSize) {
    errno = EINVAL;
    return -1;
  }
  absl::MutexLock counter_mutex_lock(&counter_mutex_);
  if (nonblock_ && (counter_ == 0)) {
    errno = EAGAIN;
    return -1;
  } else {
    auto ready = [this]() { return counter_ > 0; };
    counter_mutex_.Await(absl::Condition(&ready));
  }
  if (semaphore_) {
    *reinterpret_cast<uint64_t *>(buf) = 1;
    --counter_;
  } else {
    *reinterpret_cast<uint64_t *>(buf) = counter_;
    counter_ = 0;
  }
  return kCounterBufSize;
}

ssize_t IOContextEventFd::Write(const void *buf, size_t count) {
  if (count < kCounterBufSize) {
    errno = EINVAL;
    return -1;
  }
  uint64_t add = *reinterpret_cast<const uint64_t *>(buf);
  if (add > kMaxCounter) {
    errno = EINVAL;
    return -1;
  }
  absl::MutexLock counter_mutex_lock(&counter_mutex_);
  if (nonblock_ && (counter_ + add > kMaxCounter)) {
    errno = EAGAIN;
    return -1;
  } else {
    auto ready = [this, add]() { return (counter_ + add) <= kMaxCounter; };
    counter_mutex_.Await(absl::Condition(&ready));
  }
  counter_ += add;
  return kCounterBufSize;
}

int IOContextEventFd::Close() {
  return 0;
}

}  // namespace io
}  // namespace asylo
