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

#include "asylo/test/util/test_util.h"

#include <pthread.h>
#include <stdio.h>

#include "asylo/util/logging.h"
#include "asylo/util/status.h"
#include <openssl/mem.h>

namespace asylo {

// Do an expensive operation to act as a busy-wait between reading and writing
// for tests of locks, condition variables, etc. OPENSSL_cleanse is a good
// candidate because it performs a loop that is not performance-optimized in any
// way (for security reasons).
void BusyWork() {
  constexpr int kBufferSize = 4096;

  uint8_t buf[kBufferSize];
  OPENSSL_cleanse(buf, kBufferSize);
}

// Creates |numThreads| threads with the given |start_routine| and |arg|. Each
// thread that is started is placed in the |threads| vector.
Status LaunchThreads(const int numThreads, void *(*start_routine)(void *),
                     void *arg, std::vector<pthread_t> *threads) {
  for (int i = 0; i < numThreads; ++i) {
    pthread_t new_thread;
    int ret = pthread_create(&new_thread, nullptr, start_routine, arg);
    if (ret != 0) {
      return Status(error::GoogleError::INTERNAL,
                    absl::StrCat("Failed to create thread: ", ret));
    }
    threads->emplace_back(new_thread);
  }

  return Status::OkStatus();
}

// Joins all threads in the |threads| vector.
Status JoinThreads(const std::vector<pthread_t> &threads) {
  for (int i = 0; i < threads.size(); ++i) {
    int ret = pthread_join(threads[i], nullptr);
    if (ret != 0) {
      return Status(error::GoogleError::INTERNAL,
                    absl::StrCat("Failed to join thread: ", ret));
    }
  }

  return Status::OkStatus();
}

// Check if |value| (called |debug_name|) is in the range from |min_allowed|
// to |max_allowed|. Returns OkStatus() if so; error status otherwise.
Status CheckInRange(const int value, absl::string_view debug_name,
                    const int min_allowed, const int max_allowed) {
  if (value < min_allowed || value > max_allowed) {
    return Status(
        error::GoogleError::FAILED_PRECONDITION,
        absl::StrCat("illegal value of ", debug_name, ": currently ", value,
                     "; must be in range ", min_allowed, "-", max_allowed));
  }
  return Status::OkStatus();
}

}  // namespace asylo
