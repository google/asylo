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

#ifndef ASYLO_TEST_UTIL_PIPE_H_
#define ASYLO_TEST_UTIL_PIPE_H_

#include <atomic>
#include <string>

#include "asylo/util/statusor.h"

namespace asylo {

// Pipe represents a POSIX pipe.
//
// Pipe supports getting its read and write file descriptors via the read_fd()
// and write_fd() getter. It also supports reading the entire contents of the
// pipe via ReadUntilEof().
class Pipe {
 public:
  Pipe();

  Pipe(const Pipe &other) = delete;
  Pipe &operator=(const Pipe &other) = delete;

  Pipe(Pipe &&other) = delete;
  Pipe &operator=(Pipe &&other) = delete;

  ~Pipe();

  int read_fd() const { return pipe_fds_[0]; }
  int write_fd() const { return pipe_fds_[1]; }

  // Reads from the read end of a pipe until EOF is reached. Returns the
  // accumulated contents.
  StatusOr<std::string> ReadUntilEof();

 private:
  // Closes the write end of the pipe if it is not already closed.
  void CloseWriteFd();

  // Closes the read end of the pipe if it is not already closed.
  void CloseReadFd();

  int pipe_fds_[2];
  std::atomic_bool write_closed_;
  std::atomic_bool read_closed_;
};

}  // namespace asylo

#endif  // ASYLO_TEST_UTIL_PIPE_H_
