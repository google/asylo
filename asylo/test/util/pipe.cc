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

#include "asylo/test/util/pipe.h"

#include <unistd.h>
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <sstream>

#include "absl/strings/str_cat.h"
#include "asylo/util/logging.h"
#include "asylo/util/posix_error_space.h"

namespace asylo {

Pipe::Pipe() : write_closed_(false), read_closed_(false) {
  CHECK_EQ(pipe(pipe_fds_), 0) << strerror(errno);
}

Pipe::~Pipe() {
  CloseWriteFd();
  CloseReadFd();
}

StatusOr<std::string> Pipe::ReadUntilEof() {
  constexpr size_t kReadBufSize = 256;

  CloseWriteFd();

  std::stringstream fd_contents;
  char read_buf[kReadBufSize];
  ssize_t read_result;
  do {
    read_result = read(read_fd(), read_buf, kReadBufSize);
    if (read_result == -1) {
      return Status(
          static_cast<error::PosixError>(errno),
          absl::StrCat("Failed to read from pipe with read fd ", read_fd()));
    }
    fd_contents.write(read_buf, read_result);
  } while (read_result != 0);

  return std::string(fd_contents.str());
}

void Pipe::CloseWriteFd() {
  if (!write_closed_.exchange(true)) {
    CHECK_EQ(close(write_fd()), 0) << strerror(errno);
  }
}

void Pipe::CloseReadFd() {
  if (!read_closed_.exchange(true)) {
    CHECK_EQ(close(read_fd()), 0) << strerror(errno);
  }
}

}  // namespace asylo
