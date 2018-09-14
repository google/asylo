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

#include <sys/time.h>
#include <time.h>
#include <atomic>
#include <cstring>

#include "asylo/platform/arch/include/trusted/enclave_interface.h"
#include "asylo/platform/arch/include/trusted/host_calls.h"
#include "asylo/platform/arch/include/trusted/time.h"
#include "asylo/platform/common/time_util.h"
#include "asylo/platform/core/shared_name.h"
#include "include/sgx_trts.h"

using asylo::NanosecondsToTimeSpec;
using asylo::NanosecondsToTimeVal;
using asylo::SharedName;
using asylo::TimeSpecToNanoseconds;

namespace {

// Ensure the library provides support for atomic operations on a int64_t.
static_assert(sizeof(std::atomic<int64_t>) == sizeof(int64_t),
              "lockfree int64_t is unavailable.");

// Fetches the address of a clock resource, aborting if the address was not
// found or the returned pointer refers to enclave memory.
std::atomic<int64_t> *GetClockAddressOrDie(const char *name) {
  void *addr = enc_untrusted_acquire_shared_resource(kAddressName, name);
  if (!addr || !enc_is_outside_enclave(addr, sizeof(std::atomic<int64_t>))) {
    abort();
  }
  return static_cast<std::atomic<int64_t> *>(addr);
}

// Returns the value of a monotonic clock as a number of nanoseconds.
inline int64_t MonotonicClock() {
  static std::atomic<int64_t> *clock_monotonic =
      GetClockAddressOrDie("clock_monotonic");
  thread_local static int64_t last_tick = *clock_monotonic;
  if (*clock_monotonic < last_tick) abort();
  last_tick = *clock_monotonic;
  return *clock_monotonic;
}

// Returns the value of a monotonic clock as a number of nanoseconds.
inline int64_t RealtimeClock() {
  static std::atomic<int64_t> *clock_realtime =
      GetClockAddressOrDie("clock_realtime");
  return *clock_realtime;
}

// Busy wait with asm("pause").
static int busy_sleep(const struct timespec *requested) {
  int64_t deadline = MonotonicClock() + TimeSpecToNanoseconds(requested);
  while (MonotonicClock() < deadline) {
    __builtin_ia32_pause();
  }
  return 0;
}

}  // namespace

extern "C" {

// Custom in-enclave nanosleep that will leave the enclave for the standard
// nanosleep if the requested sleep time is longer than we expect an enclave
// round-trip to take. Otherwise, busy wait.
int nanosleep(const struct timespec *requested, struct timespec *remainder) {
  // If we want to sleep more than 3ms, then exit the enclave to sleep.
  constexpr int64_t kExitThreshold = INT64_C(3000000);
  int64_t delay = TimeSpecToNanoseconds(requested);
  if (delay > kExitThreshold) {
    return enc_untrusted_nanosleep(requested, remainder);
  }
  // Otherwise, wait on the shared clock.
  if (remainder) {
    NanosecondsToTimeSpec(remainder, 0);
  }
  return busy_sleep(requested);
}

int enclave_gettimeofday(struct timeval *__restrict time, void *timezone) {
  NanosecondsToTimeVal(time, RealtimeClock());
  // The timezone parameter is deprecated by POSIX. Fail if non-null.
  if (timezone) {
    return -1;
  }
  return 0;
}


int enclave_times(struct tms *buf) { return enc_untrusted_times(buf); }

int clock_gettime(clockid_t clock_id, struct timespec *time) {
  switch (clock_id) {
    case CLOCK_MONOTONIC:
      NanosecondsToTimeSpec(time, MonotonicClock());
      return 0;
    case CLOCK_REALTIME:
      NanosecondsToTimeSpec(time, RealtimeClock());
      return 0;
    default:
      return -1;
  }
}

int setitimer(int which, const struct itimerval *new_value,
              struct itimerval *old_value) {
  return enc_untrusted_setitimer(which, new_value, old_value);
}

}  // extern "C"
