/*
 *
 * Copyright 2019 Asylo authors
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

#ifndef ASYLO_UTIL_FD_UTILS_H_
#define ASYLO_UTIL_FD_UTILS_H_

#include <string>
#include <utility>

#include "absl/strings/string_view.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

namespace asylo {

// Pipe represents a POSIX pipe.
//
// Pipe supports getting its read and write file descriptors via the read_fd()
// and write_fd() getters. It also supports closing each end of the pipe
// manually, but both ends are automatically closed when the desctructor is
// called.
//
// It is an error to close either end of the Pipe except by using the provided
// methods.
class Pipe {
 public:
  // Creates an empty pipe. All reads and writes to this pipe will return an
  // error.
  Pipe();

  Pipe(const Pipe &other) = delete;
  Pipe &operator=(const Pipe &other) = delete;

  Pipe(Pipe &&other);
  Pipe &operator=(Pipe &&other);

  ~Pipe();

  // Creates a new Pipe. If |flags| is given, then the provided flags are used
  // to create the Pipe. |flags| must be a bitwise-or of the values O_CLOEXEC,
  // O_DIRECT, and O_NONBLOCK.
  static StatusOr<Pipe> CreatePipe(int flags = 0);

  inline int read_fd() const { return read_fd_; }
  inline int write_fd() const { return write_fd_; }

  // Closes the write end of the pipe if it is not already closed. This
  // operation is thread-safe.
  Status CloseWriteFd();

  // Closes the read end of the pipe if it is not already closed. This
  // operation is thread-safe.
  Status CloseReadFd();

 private:
  // Creates a pipe with the given read and write file descriptors.
  Pipe(int read_fd, int write_fd);

  int read_fd_;
  int write_fd_;
  std::atomic<bool> read_closed_;
  std::atomic<bool> write_closed_;
};

// Reads from |fd| until EOF is reached. Returns the accumulated contents.
StatusOr<std::string> ReadAll(int fd);

// Reads from |fd| (which must be non-blocking) until reading would block or EOF
// is reached. Returns the accumulated contents.
StatusOr<std::string> ReadAllNoBlock(int fd);

// Writes |data| to |fd|.
Status WriteAll(int fd, absl::string_view data);

// Writes as much of |data| as possible to |fd| until writing would block.
// Returns the number of bytes written.
StatusOr<size_t> WriteAllNoBlock(int fd, absl::string_view data);

// Returns the file access mode and file status flags on |fd|.
StatusOr<int> GetFdFlags(int fd);

// Sets |fd|'s file status flags to |flags|. Only O_APPEND, O_ASYNC, O_DIRECT,
// O_NOATIME, and O_NONBLOCK may be set.
Status SetFdFlags(int fd, int flags);

// Sets |flags| on |fd|, keeping |fd|'s existing value for options not set in
// |flags|. If |fd| already has one or more of |flags|, AddFdFlags() does not
// change the value of those flags.
Status AddFdFlags(int fd, int flags);

// Unsets |flags| on |fd|, keeping |fd|'s existing value for options not set in
// |flags|. If |fd| does not have one or more of |flags|, RemoveFdFlags() does
// not change the value of those flags.
Status RemoveFdFlags(int fd, int flags);

// Waits for one of |target_events| to occur on |fd|. |target_events| should be
// a bitwise-or of poll() events. Returns the bitwise-or of the events that did
// occur by the time one of |target_events| occurs.
//
// Events in |ok_events| may also occur while waiting without counting as an
// error.
//
// Returns an error if an internal call to poll() fails or if a poll() succeeds
// but returns events outside of target_events | ok_events.
StatusOr<short> WaitForEvents(int fd, short target_events, short ok_events);

}  // namespace asylo

#endif  // ASYLO_UTIL_FD_UTILS_H_
