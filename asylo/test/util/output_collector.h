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

#ifndef ASYLO_TEST_UTIL_OUTPUT_COLLECTOR_H_
#define ASYLO_TEST_UTIL_OUTPUT_COLLECTOR_H_

#include <string>

#include "asylo/util/statusor.h"

namespace asylo {
namespace internal {

struct FromStdoutTag {};
struct FromStderrTag {};

}  // namespace internal

// A tag used to construct an OutputCollector to collect writes to stdout.
constexpr internal::FromStdoutTag kCollectStdout;

// A tag used to construct an OutputCollector to collect writes to stderr.
constexpr internal::FromStderrTag kCollectStderr;

// Collects all output to either stdout or stderr.
class OutputCollector {
 public:
  // Creates an OutputCollector to collect output to stdout.
  explicit OutputCollector(internal::FromStdoutTag);

  // Creates an OutputCollector to collect output to stderr.
  explicit OutputCollector(internal::FromStderrTag);

  OutputCollector(const OutputCollector &other) = delete;
  OutputCollector &operator=(const OutputCollector &other) = delete;

  ~OutputCollector();

  // Returns the accumulation of all output so far to the given target.
  //
  // Due to buffering, CollectOutputSoFar() may miss very recent output.
  StatusOr<std::string> CollectOutputSoFar() const;

  // Returns the accumulation of all output to the given target and stops
  // collecting output.
  //
  // After CollectAllOutputAndRestore() has been called, all calls to
  // CollectOutputSoFar() and CollectAllOutputAndRestore() will fail.
  //
  // Due to buffering, CollectAllOutputAndRestore() may not collect all of the
  // most recent output to the target.
  StatusOr<std::string> CollectAllOutputAndRestore();

 private:
  // Creates a OutputCollector to collect output to |fd|.
  //
  // Note that |fd| is closed in the process of constructing the
  // OutputCollector. This may have unintended consequences if, e.g. another
  // thread has select()ed on |fd|. However, code that only needs to write() to
  // |fd| (and that does not do so while the OutputCollector is being
  // constructed) should work normally.
  explicit OutputCollector(int fd);

  // Restores target_fd_ to its original state and stops capturing writes.
  void Restore();

  bool is_active_;

  // The file descriptor to collect writes to.
  int target_fd_;

  // The read end of a pipe to use for capturing output.
  int read_fd_;

  // A copy of the file handle that was originally at target_fd_. The destructor
  // restores target_fd_ to refer to this handle.
  int fd_copy_;
};

}  // namespace asylo

#endif  // ASYLO_TEST_UTIL_OUTPUT_COLLECTOR_H_
