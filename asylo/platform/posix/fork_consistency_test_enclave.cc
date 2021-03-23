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

#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <bitset>
#include <memory>
#include <thread>
#include <vector>

#include "absl/status/status.h"
#include "absl/synchronization/mutex.h"
#include "asylo/util/logging.h"
#include "asylo/platform/primitives/trusted_primitives.h"
#include "asylo/platform/primitives/trusted_runtime.h"
#include "asylo/test/util/enclave_test_application.h"
#include "asylo/util/posix_errors.h"
#include "asylo/util/status.h"

namespace asylo {

static constexpr int kNumBuffers = 32;
static constexpr int kBufferSize = 1024;
static std::atomic<int> read_to_fork(false);
static std::atomic<bool> fork_finished(false);
std::vector<std::vector<int>> buffers(kNumBuffers);
absl::Mutex mutex;

void UpdateCounter() {
  uint64_t counter = 0;
  // Keep updating counter to a random space in a random buffer, until fork
  // finishes.
  while (!fork_finished) {
    // Notify the main thread to call fork after this thread has run for 10
    // interations to make sure fork() happens while the counter thread is busy
    // working.
    if (counter > 10) {
      read_to_fork = true;
    }
    bool updated = false;
    struct timespec ts;
    // Use nanosecond as seed to ensure a random result.
    clock_gettime(CLOCK_MONOTONIC, &ts);
    unsigned int seed = ts.tv_nsec;

    // Fail the test if we have used up all the buffers.
    if (counter >= kNumBuffers * kBufferSize) {
      LOG(FATAL) << "All buffers are filled up";
    }

    while (!updated) {
      absl::MutexLock lock(&mutex);
      int random_buffer_index = rand_r(&seed) % kNumBuffers;
      int random_buffer_position = rand_r(&seed) % kBufferSize;

      if (buffers[random_buffer_index][random_buffer_position] == 0) {
        buffers[random_buffer_index][random_buffer_position] = ++counter;
        updated = true;
      }
    }
    ts.tv_sec = 0;
    ts.tv_nsec = 1000000;
    nanosleep(&ts, /*rem=*/nullptr);
  }
}

class ForkTest : public EnclaveTestCase {
 public:
  ForkTest() = default;
  Status Run(const EnclaveInput &input, EnclaveOutput *output) {
    // Allocate buffers to be randomly filled up by other threads.
    for (int i = 0; i < kNumBuffers; ++i) {
      buffers[i].resize(kBufferSize, 0);
    }

    // Create another thread which keeps writing to the buffers.
    std::thread counter_thread(UpdateCounter);

    // Waits till the thread has entered the enclave. Checks every 100 ms and
    // timeout at 5 seconds.
    constexpr uint64_t kTimeout = 5000000000;
    constexpr uint64_t kStep = 100000000;
    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = kStep;
    for (int i = 0; i < kTimeout / kStep && !read_to_fork; i++) {
      nanosleep(&ts, /*rem=*/nullptr);
    }

    if (!read_to_fork) {
      return absl::InternalError(
          "Timeout waiting for counter thread to enter the enclave.");
    }

    pid_t pid = fork();
    if (pid < 0) {
      abort();
    }
    if (pid == 0) {
      // Child enclave.
      // Verifies that the value in the buffers are consistent.
      // First put all written bytes into a bitset.
      std::bitset<kNumBuffers * kBufferSize> values;
      int max_value = 0;
      for (int i = 0; i < kNumBuffers; ++i) {
        for (int j = 0; j < kBufferSize; ++j) {
          if (buffers[i][j] > 0) {
            if (values[buffers[i][j]]) {
              return absl::InternalError(
                  "The same counter exists in more than one buffer address");
            }
            values.set(buffers[i][j]);
            max_value = std::max(max_value, buffers[i][j]);
          }
        }
      }

      // Now confirm all values below the maximum does exist (the memory is
      // consistent). Abort if not.
      if (values.count() != max_value) {
        LOG(FATAL) << "The values in the buffers are inconsistent";
      }
      _exit(0);
    } else {
      // Parent enclave.
      // Wait for all other threads to join.
      fork_finished = true;
      counter_thread.join();
      // Wait for the child enclave exits, and checks whether it exited
      // normally.
      int status;
      if (wait(&status) == -1) {
        return LastPosixError("Error waiting for child");
      }
      if (!WIFEXITED(status)) {
        return absl::InternalError("child enclave aborted");
      }
    }
    return absl::OkStatus();
  }
};

TrustedApplication *BuildTrustedApplication() { return new ForkTest; }

}  // namespace asylo
