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

#include <atomic>
#include <random>
#include <thread>
#include <vector>

#include "absl/status/status.h"
#include "asylo/util/logging.h"
#include "asylo/platform/primitives/trusted_primitives.h"
#include "asylo/platform/primitives/trusted_runtime.h"
#include "asylo/test/util/enclave_test_application.h"
#include "asylo/util/posix_errors.h"
#include "asylo/util/status.h"

namespace asylo {

static constexpr int kNumThreads = 8;
static constexpr uint64_t kNanoSecondsPerSecond = 1000000000;
static constexpr uint64_t kAllocateLimit = 1024;
static std::atomic<int> entry_count(0);
static std::atomic<bool> fork_finished(false);

void RandomlyAllocateAndSleep() {
  entry_count++;
  // Keep allocating/freeing memory while exiting/reentering the enclave and
  // wait for random time, until fork finishes.
  while (!fork_finished) {
    struct timespec ts;
    // Use nanosecond as seed to ensure a random result.
    clock_gettime(CLOCK_MONOTONIC, &ts);
    unsigned int seed = ts.tv_nsec;

    void *randomly_allocated_memory = malloc(rand_r(&seed) % kAllocateLimit);
    ts.tv_sec = 0;
    ts.tv_nsec = rand_r(&seed) % kNanoSecondsPerSecond;
    // Exit the enclave and sleep on the host.
    nanosleep(&ts, /*rem=*/nullptr);
    free(randomly_allocated_memory);
  }
}

class ForkTest : public EnclaveTestCase {
 public:
  ForkTest() = default;
  Status Run(const EnclaveInput &input, EnclaveOutput *output) {
    // Create random variables on heap.
    char *test_heap = new char[10];
    for (int i = 0; i < 10; ++i) {
      test_heap[i] = '0' + i;
    }

    // Create a random variable on stack.
    char **test_stack = &test_heap;

    // Creates kNumThreads threads that run the given |RandomlyAllocateAndExit|,
    // which keeps randomly allocating/exiting until fork is done.
    std::vector<std::thread> threads;
    for (int i = 0; i < kNumThreads; ++i) {
      threads.emplace_back(RandomlyAllocateAndSleep);
    }

    // Waits till all threads have entered the enclave. Checks every 10 ms and
    // timeout at 5 seconds.
    constexpr uint64_t kTimeout = 5000000000;
    constexpr uint64_t kStep = 10000000;
    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = kStep;
    for (int i = 0; i < kTimeout / kStep && entry_count != kNumThreads; i++) {
      nanosleep(&ts, /*rem=*/nullptr);
    }

    if (entry_count != kNumThreads) {
      return absl::InternalError(
          "Timeout waiting for other threads to enter the enclave.");
    }

    pid_t pid = fork();
    if (pid < 0) {
      abort();
    }
    if (pid == 0) {
      // Child enclave.
      // Verifies that variables on stack and heap are copied correctly. Abort
      // if not.
      for (int i = 0; i < 10; ++i) {
        if (test_heap[i] != '0' + i) {
          LOG(ERROR) << "Variable on heap in the child enclave does not match "
                        "expectation";
          abort();
        }
      }
      if (test_stack != &test_heap) {
        LOG(ERROR) << "Variable on stack in the child enclave does not match "
                      "expectation";
        abort();
      }
      _exit(0);
    } else {
      // Parent enclave.
      // Wait for all other threads to join.
      fork_finished = true;
      for (int i = 0; i < kNumThreads; ++i) {
        threads[i].join();
      }
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
