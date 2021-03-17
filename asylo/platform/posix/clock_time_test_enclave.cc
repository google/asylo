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
#include <sys/time.h>
#include <time.h>

#include "absl/status/status.h"
#include "asylo/platform/posix/clock_time_test.pb.h"
#include "asylo/trusted_application.h"
#include "asylo/util/status.h"

namespace asylo {
namespace {

class ClockTimeTestEnclave : public TrustedApplication {
 public:
  ClockTimeTestEnclave() = default;

 private:
  Status Run(const EnclaveInput &input, EnclaveOutput *output) override {
    ClockTimeTestOutput *time_test_output =
        output->MutableExtension(clock_time_test_output);

    struct timespec ts;
    uint64_t clk_id = CLOCK_REALTIME;
    uint64_t kNs = 1000000000ULL;

    if (clock_gettime(clk_id, &ts) < 0)
      return absl::FailedPreconditionError("clock_gettime failed");
    time_test_output->set_clock_gettime(ts.tv_sec * kNs + ts.tv_nsec);

    return absl::OkStatus();
  }
};

}  // namespace

TrustedApplication *BuildTrustedApplication() {
  return new ClockTimeTestEnclave;
}

}  // namespace asylo
