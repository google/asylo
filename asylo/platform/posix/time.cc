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

#include "asylo/platform/common/time_util.h"
#include "asylo/platform/host_call/trusted/host_calls.h"

using asylo::NanosecondsToTimeSpec;
using asylo::NanosecondsToTimeVal;
using asylo::TimeSpecToNanoseconds;

namespace {

// Ensure the library provides support for atomic operations on a int64_t.
static_assert(sizeof(std::atomic<int64_t>) == sizeof(int64_t),
              "lockfree int64_t is unavailable.");

}  // namespace

extern "C" {

// Custom in-enclave nanosleep that will leave the enclave for the standard
// nanosleep.
int nanosleep(const struct timespec *requested, struct timespec *remainder) {
  return enc_untrusted_nanosleep(requested, remainder);
}

int enclave_gettimeofday(struct timeval *__restrict time, void *timezone) {
  // The timezone parameter is deprecated by POSIX. Fail if non-null.
  if (timezone) {
    return -1;
  }

  struct timeval tval {};
  int result = enc_untrusted_gettimeofday(&tval, nullptr);
  time->tv_sec = tval.tv_sec;
  time->tv_usec = tval.tv_usec;
  return result;
}

int enclave_times(struct tms *buf) { return enc_untrusted_times(buf); }

int clock_gettime(clockid_t clock_id, struct timespec *time) {
  int result = enc_untrusted_clock_gettime(clock_id, time);
  if (clock_id == CLOCK_MONOTONIC) {
    int64_t clock_monotonic = TimeSpecToNanoseconds(time);
    thread_local static int64_t last_tick = clock_monotonic;
    // CLOCK_MONOTONIC should never go backwards.
    if (clock_monotonic < last_tick) abort();
    last_tick = clock_monotonic;
  }
  return result;
}


int clock_getcpuclockid(pid_t pid, clockid_t *clock_id) {
  return enc_untrusted_clock_getcpuclockid(pid, clock_id);
}

int getitimer(int which, struct itimerval *curr_value) {
  return enc_untrusted_getitimer(which, curr_value);
}

int setitimer(int which, const struct itimerval *new_value,
              struct itimerval *old_value) {
  return enc_untrusted_setitimer(which, new_value, old_value);
}

}  // extern "C"
