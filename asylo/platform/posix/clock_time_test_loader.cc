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

#include <cstdint>

#include "absl/time/clock.h"
#include "asylo/platform/posix/clock_time_test.pb.h"
#include "asylo/test/util/enclave_test.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace {

class ClockTimeTest : public EnclaveTest {};

// Host time should be close to enclave time.
TEST_F(ClockTimeTest, ClockGettime) {
  EnclaveInput enclave_input;
  EnclaveOutput enclave_output;
  Status test_status = client_->EnterAndRun(enclave_input, &enclave_output);
  ASYLO_CHECK_OK(test_status);
  uint64_t host_time = absl::GetCurrentTimeNanos();
  uint64_t clock_gettime =
      enclave_output.GetExtension(clock_time_test_output).clock_gettime();
  EXPECT_LT(0, clock_gettime);
  // Time is presumably at least one nanosecond past the epoch.
  const int64_t ns_sec = 1000 * 1000 * 1000;
  EXPECT_LT(1 * ns_sec, clock_gettime);
  // The host clock function should be close to the enc clock function.
  // If this is flaky, the 5 sec is arbitary.
  int64_t delta = host_time - clock_gettime;
  if (delta < 0) delta = -delta;
  EXPECT_LT(delta, 5 * ns_sec);
}

}  // namespace
}  // namespace asylo
