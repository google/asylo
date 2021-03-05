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

#ifndef ASYLO_TEST_UTIL_PTHREAD_TEST_UTIL_H_
#define ASYLO_TEST_UTIL_PTHREAD_TEST_UTIL_H_

#include <pthread.h>
#include <vector>

#include "absl/strings/string_view.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

namespace asylo {

// Does an expensive operation to act as a busy-wait in critical sections.
void BusyWork();

// Creates |numThreads| threads with the given |start_routine| and |arg|. Each
// thread that is started is placed in the |threads| vector.
Status LaunchThreads(const int numThreads, void *(*start_routine)(void *),
                     void *arg, std::vector<pthread_t> *threads);

// Joins all threads in the |threads| vector.
Status JoinThreads(const std::vector<pthread_t> &threads);

// Heartbeat encapsulates a stoppable thread that periodically logs a
// heartbeat message.
class Heartbeat {
 public:
  explicit Heartbeat(int periodms);

  Status Create();
  void Stop();

  static void* run(void* arg);

 private:
  pthread_t thread_;
  int periodms_;
  bool canceled_;
};

// Creates a thread that logs a heartbeat message on the given millisecond
// period.
StatusOr<std::unique_ptr<Heartbeat>> LaunchHeartbeat(int periodms);

// Check if |value| (called |debug_name|) is in the range from |min_allowed|
// to |max_allowed|. Returns OkStatus() if so; error status otherwise.
Status CheckInRange(const int value, absl::string_view debug_name,
                    const int min_allowed, const int max_allowed);

}  // namespace asylo

#endif  // ASYLO_TEST_UTIL_PTHREAD_TEST_UTIL_H_
