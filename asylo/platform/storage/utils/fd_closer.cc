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

#include "asylo/platform/storage/utils/fd_closer.h"

#include <unistd.h>

namespace asylo {
namespace platform {
namespace storage {

FdCloser::FdCloser() : fd_(-1), close_function_(&close) {}

FdCloser::FdCloser(int fd) : fd_(fd), close_function_(&close) {}

FdCloser::FdCloser(int fd, CloseFunction close_function)
    : fd_(fd), close_function_(close_function) {}

int FdCloser::get() const { return fd_; }

FdCloser::~FdCloser() { reset(-1); }

int FdCloser::release() {
  int fd = fd_;
  fd_ = -1;
  return fd;
}

bool FdCloser::reset(int new_fd) {
  bool result = true;
  if (fd_ >= 0)
    result =
        close_function_ ? (close_function_(fd_) != -1) : (close(fd_) != -1);
  fd_ = new_fd;
  return result;
}

bool FdCloser::reset() { return reset(-1); }

}  // namespace storage
}  // namespace platform
}  // namespace asylo
