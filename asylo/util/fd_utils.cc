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

// For pipe2() and POLLRDHUP.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif  // _GNU_SOURCE

// For POLL(RD|WR)(NORM|BAND).
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE
#endif  // _XOPEN_SOURCE

#include "asylo/util/fd_utils.h"

#include <fcntl.h>
#include <poll.h>
#include <unistd.h>

#include <cstddef>
#include <sstream>

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/time/time.h"
#include "asylo/util/logging.h"
#include "asylo/util/posix_errors.h"
#include "asylo/util/status_macros.h"

namespace asylo {
namespace {

// Reads from |fd| until either EOF is reached or, if |return_on_eagain| is
// true, read() fails with EAGAIN or EWOULDBLOCK. If |return_on_eagain| is
// false, retries the read() if read() fails with EAGAIN or EWOULDBLOCK.
StatusOr<std::string> ReadInternal(int fd, bool return_on_eagain) {
  constexpr size_t kReadBufSize = 256;

  std::stringstream fd_contents;
  char read_buf[kReadBufSize];
  ssize_t read_result;
  do {
    read_result = read(fd, read_buf, kReadBufSize);
    if (read_result == -1) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        if (return_on_eagain) {
          break;
        } else {
          ASYLO_RETURN_IF_ERROR(
              WaitForEvents(fd, POLLIN | POLLHUP | POLLRDHUP, 0).status());
          continue;
        }
      }

      return LastPosixError(absl::StrCat("Failed to read from fd ", fd));
    }
    fd_contents.write(read_buf, read_result);
  } while (read_result != 0);

  return fd_contents.str();
}

// Writes |data| to |fd|. If |return_on_eagain| is true, stops and returns a
// view of the unwritten data if write() fails with EAGAIN or EWOULDBLOCK. If
// |return_on_eagain| is false, retries the write() if write() fails with EAGAIN
// or EWOULDBLOCK.
//
// Returns the number of bytes written.
StatusOr<size_t> WriteInternal(int fd, absl::string_view data,
                               bool return_on_eagain) {
  size_t bytes_written = 0;
  ssize_t write_result;
  while (bytes_written < data.size()) {
    write_result = write(fd, &data[bytes_written], data.size() - bytes_written);
    if (write_result == -1) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        if (return_on_eagain) {
          break;
        } else {
          ASYLO_RETURN_IF_ERROR(WaitForEvents(fd, POLLIN, 0).status());
          continue;
        }
      }

      return LastPosixError(absl::StrCat("Failed to write to fd ", fd));
    }

    bytes_written += write_result;
  }

  return bytes_written;
}

}  // namespace

Pipe::Pipe()
    : read_fd_(-1), write_fd_(-1), read_closed_(true), write_closed_(true) {}

Pipe::Pipe(Pipe &&other)
    : read_fd_(other.read_fd_),
      write_fd_(other.write_fd_),
      read_closed_(other.read_closed_.exchange(true)),
      write_closed_(other.write_closed_.exchange(true)) {}

Pipe &Pipe::operator=(Pipe &&other) {
  CloseReadFd();
  CloseWriteFd();

  read_fd_ = other.read_fd_;
  write_fd_ = other.write_fd_;
  read_closed_.store(other.read_closed_.exchange(true));
  write_closed_.store(other.write_closed_.exchange(true));

  return *this;
}

Pipe::~Pipe() {
  Status status = CloseReadFd();
  LOG_IF(ERROR, !status.ok()) << status;

  status = CloseWriteFd();
  LOG_IF(ERROR, !status.ok()) << status;
}

StatusOr<Pipe> Pipe::CreatePipe(int flags) {
  int pipe_fds[2];

  if (pipe2(pipe_fds, flags) == -1) {
    return LastPosixError("Failed to create a pipe");
  }

  return Pipe(pipe_fds[0], pipe_fds[1]);
}

Status Pipe::CloseReadFd() {
  if (!read_closed_.exchange(true) && close(read_fd_) == -1) {
    return LastPosixError(
        absl::StrCat("Failed to close pipe read fd ", read_fd_));
  }

  return absl::OkStatus();
}

Status Pipe::CloseWriteFd() {
  if (!write_closed_.exchange(true) && close(write_fd_) == -1) {
    return LastPosixError(
        absl::StrCat("Failed to close pipe write fd ", write_fd_));
  }

  return absl::OkStatus();
}

Pipe::Pipe(int read_fd, int write_fd)
    : read_fd_(read_fd),
      write_fd_(write_fd),
      read_closed_(false),
      write_closed_(false) {}

StatusOr<std::string> ReadAll(int fd) { return ReadInternal(fd, false); }

StatusOr<std::string> ReadAllNoBlock(int fd) {
  int flags;
  ASYLO_ASSIGN_OR_RETURN(flags, GetFdFlags(fd));
  if (!(flags & O_NONBLOCK)) {
    return absl::InvalidArgumentError(
        absl::StrCat("Cannot read from fd ", fd, " without blocking because ",
                     fd, " is a blocking file descriptor"));
  }
  return ReadInternal(fd, true);
}

Status WriteAll(int fd, absl::string_view data) {
  return WriteInternal(fd, data, false).status();
}

StatusOr<size_t> WriteAllNoBlock(int fd, absl::string_view data) {
  int flags;
  ASYLO_ASSIGN_OR_RETURN(flags, GetFdFlags(fd));
  if (~flags & O_NONBLOCK) {
    return absl::InvalidArgumentError(
        absl::StrCat("Cannot write to fd ", fd, " without blocking because ",
                     fd, " is a blocking file descriptor"));
  }
  return WriteInternal(fd, data, true);
}

StatusOr<int> GetFdFlags(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags == -1) {
    return LastPosixError(
        absl::StrCat("Failed to read file status flags on fd ", fd));
  }
  return flags;
}

Status SetFdFlags(int fd, int flags) {
  if (fcntl(fd, F_SETFL, flags) == -1) {
    return LastPosixError(
        absl::StrCat("Failed to set file status flags on fd ", fd));
  }
  return absl::OkStatus();
}

Status AddFdFlags(int fd, int flags) {
  int current_flags;
  ASYLO_ASSIGN_OR_RETURN(current_flags, GetFdFlags(fd));
  return SetFdFlags(fd, current_flags | flags);
}

Status RemoveFdFlags(int fd, int flags) {
  int current_flags;
  ASYLO_ASSIGN_OR_RETURN(current_flags, GetFdFlags(fd));
  return SetFdFlags(fd, current_flags & ~flags);
}

StatusOr<short> WaitForEvents(int fd, short target_events, short ok_events) {
  constexpr absl::Duration kPollTimeout = absl::Seconds(1);

  ok_events &= ~target_events;
  struct pollfd wait_for_events = {
      .fd = fd, .events = target_events, .revents = 0};

  int poll_result;
  do {
    poll_result =
        poll(&wait_for_events, 1, kPollTimeout / absl::Milliseconds(1));

    if (poll_result == -1) {
      return LastPosixError(absl::StrCat("Failed to poll fd ", fd));
    }
    if (poll_result == 1 &&
        (wait_for_events.revents & ~(target_events | ok_events))) {
      return absl::UnknownError(absl::StrCat(
          "poll() did not return the expected events, instead gave:",
          (wait_for_events.revents & POLLIN ? " POLLIN" : ""),
          (wait_for_events.revents & POLLPRI ? " POLLPRI" : ""),
          (wait_for_events.revents & POLLOUT ? " POLLOUT" : ""),
          (wait_for_events.revents & POLLRDHUP ? " POLLRDHUP" : ""),
          (wait_for_events.revents & POLLERR ? " POLLERR" : ""),
          (wait_for_events.revents & POLLHUP ? " POLLHUP" : ""),
          (wait_for_events.revents & POLLNVAL ? " POLLNVAL" : ""),
          (wait_for_events.revents & POLLRDNORM ? " POLLRDNORM" : ""),
          (wait_for_events.revents & POLLRDBAND ? " POLLRDBAND" : ""),
          (wait_for_events.revents & POLLWRNORM ? " POLLWRNORM" : ""),
          (wait_for_events.revents & POLLWRBAND ? " POLLWRBAND" : "")));
    }
  } while (poll_result == 0 ||
           ((wait_for_events.revents | ok_events) == ok_events));

  return wait_for_events.revents;
}

}  // namespace asylo
