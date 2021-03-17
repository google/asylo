/*
 *
 * Copyright 2017 Asylo authors
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

#include <xmmintrin.h>

#include <cstdio>
#include <memory>
#include <thread>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/synchronization/mutex.h"
#include "asylo/test/util/enclave_test_application.h"
#include "asylo/util/status.h"

namespace asylo {
namespace {

static volatile int cc11_wait_count = 0;
static absl::Mutex cc11_mutex;

// Must be greater than or equal to the TCS number, since the main thread also
// consumes a TCS.
constexpr int stop_on_count = 3;

void cc11_increment_count_and_wait() {
  {
    absl::MutexLock lock(&cc11_mutex);
    ++cc11_wait_count;
  }
  while (cc11_wait_count < stop_on_count) {
    _mm_pause();
  }
}

class ExhaustTcsEnclave : public TrustedApplication {
 public:
  Status Run(const EnclaveInput &, EnclaveOutput *) override {
    std::vector<std::unique_ptr<std::thread>> threads;
    for (int i = 0; i < stop_on_count; ++i) {
      threads.push_back(
          absl::make_unique<std::thread>(cc11_increment_count_and_wait));
    }

    for (auto &thread : threads) {
      thread->join();
    }
    return absl::OkStatus();
  }
};

}  // namespace

TrustedApplication *BuildTrustedApplication() {
  return new asylo::ExhaustTcsEnclave;
}

}  // namespace asylo
