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

#ifndef ASYLO_PLATFORM_STORAGE_UTILS_FD_CLOSER_H_
#define ASYLO_PLATFORM_STORAGE_UTILS_FD_CLOSER_H_

namespace asylo {
namespace platform {
namespace storage {

typedef int (*CloseFunction)(int);

// Simple wrapper class that automatically calls Close() on a file
// when the wrapper goes out of scope.  (Like scoped_ptr for files.)
class FdCloser {
 public:
  FdCloser();
  explicit FdCloser(int fd);
  FdCloser(int fd, CloseFunction close_function);
  int get() const;
  ~FdCloser();
  int release();

  // Resets the FdCloser to new fd, closing the previous fd, if any. Returns
  // false if closing fails, but resets fd regardless of failure to close.
  bool reset(int new_fd);

  // Equivalent to "reset(-1)"
  bool reset();

 private:
  int fd_;
  const CloseFunction close_function_;
  FdCloser(const FdCloser &) = delete;
  FdCloser &operator=(const FdCloser &) = delete;
};

}  // namespace storage
}  // namespace platform
}  // namespace asylo

#endif  // ASYLO_PLATFORM_STORAGE_UTILS_FD_CLOSER_H_
