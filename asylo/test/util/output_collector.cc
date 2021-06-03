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

#include "asylo/test/util/output_collector.h"

#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>

#include "asylo/util/logging.h"
#include "asylo/util/fd_utils.h"
#include "asylo/util/status_macros.h"

namespace asylo {

OutputCollector::OutputCollector(internal::FromStdoutTag)
    : OutputCollector(STDOUT_FILENO) {}

OutputCollector::OutputCollector(internal::FromStderrTag)
    : OutputCollector(STDERR_FILENO) {}

OutputCollector::OutputCollector(int fd)
    : is_active_(true), target_fd_(fd), fd_copy_(dup(fd)) {
  CHECK_NE(fd_copy_, -1) << strerror(errno);
  int pipe_fds[2];
  CHECK_NE(pipe(pipe_fds), -1) << strerror(errno);

  // Ensure that the new file represented by target_fd_ has the same flags as
  // the original one.
  auto get_flags_result = GetFdFlags(target_fd_);
  ASYLO_CHECK_OK(get_flags_result.status());
  ASYLO_CHECK_OK(SetFdFlags(pipe_fds[1], get_flags_result.value()));

  CHECK_NE(dup2(pipe_fds[1], target_fd_), -1) << strerror(errno);
  CHECK_NE(close(pipe_fds[1]), -1) << strerror(errno);
  read_fd_ = pipe_fds[0];

  // Make read_fd_ non-blocking so that CollectOutputSoFar() can doesn't block
  // waiting for fd_copy_ to close.
  ASYLO_CHECK_OK(AddFdFlags(read_fd_, O_NONBLOCK));
}

OutputCollector::~OutputCollector() {
  Restore();
  CHECK_NE(close(read_fd_), -1) << strerror(errno);
}

StatusOr<std::string> OutputCollector::CollectOutputSoFar() const {
  std::string collected_writes;
  ASYLO_ASSIGN_OR_RETURN(collected_writes, ReadAllNoBlock(read_fd_));
  ASYLO_RETURN_IF_ERROR(WriteAll(fd_copy_, collected_writes));
  return collected_writes;
}

StatusOr<std::string> OutputCollector::CollectAllOutputAndRestore() {
  Restore();

  // Make read_fd_ blocking for the final read().
  ASYLO_RETURN_IF_ERROR(RemoveFdFlags(read_fd_, O_NONBLOCK));

  std::string collected_writes;
  ASYLO_ASSIGN_OR_RETURN(collected_writes, ReadAll(read_fd_));
  ASYLO_RETURN_IF_ERROR(WriteAll(target_fd_, collected_writes));
  return collected_writes;
}

void OutputCollector::Restore() {
  if (is_active_) {
    is_active_ = false;
    CHECK_NE(dup2(fd_copy_, target_fd_), -1) << strerror(errno);
    CHECK_NE(close(fd_copy_), -1) << strerror(errno);
  }
}

}  // namespace asylo
