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

#include <time.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/time/time.h"
#include "asylo/platform/common/time_util.h"
#include "asylo/platform/core/enclave_manager.h"
#include "asylo/platform/core/shared_resource_manager.h"

namespace asylo {
namespace {

int64_t MonotonicClock() {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return TimeSpecToNanoseconds(&ts);
}

// Check that the error of the shared clock variable stays within reasonable
// bounds.
TEST(EnclaveClockTest, ErrorBounds) {
  EnclaveManager::Configure(EnclaveManagerOptions());
  auto enclave_manager = EnclaveManager::Instance();
  auto *resources = enclave_manager.ValueOrDie()->shared_resources();
  auto *clock = resources->AcquireResource<std::atomic<int64_t>>(
      SharedName(kAddressName, "clock_monotonic"));
  ASSERT_NE(clock, nullptr);
  for (int i = 0; i < 1000; i++) {
    int64_t error = std::abs(*clock - MonotonicClock());
    EXPECT_LT(error, absl::ToInt64Nanoseconds(absl::Milliseconds(100)));
    absl::SleepFor(absl::Milliseconds(1));
  }
}

}  // namespace
}  // namespace asylo
