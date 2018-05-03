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

#include "asylo/platform/common/time_util.h"

namespace asylo {

namespace {

constexpr int64_t kMicrosecondsPerSecond = INT64_C(1000000);
constexpr int64_t kNanosecondsPerMicrosecond = INT64_C(1000);
constexpr int64_t kNanosecondsPerSecond = INT64_C(1000000000);
constexpr int64_t kFirstRepresentableSecond = INT64_MIN / kNanosecondsPerSecond;
constexpr int64_t kLastRepresentableSecond = INT64_MAX / kNanosecondsPerSecond;

}  // namespace

bool IsRepresentableAsNanoseconds(const struct timespec *ts) {
  return ts->tv_sec > kFirstRepresentableSecond &&
         ts->tv_sec < kLastRepresentableSecond;
}

bool IsRepresentableAsNanoseconds(const struct timeval *tv) {
  return tv->tv_sec > kFirstRepresentableSecond &&
         tv->tv_sec < kLastRepresentableSecond;
}

bool TimeSpecSubtract(struct timespec *result, const struct timespec &lhs,
                      const struct timespec &rhs) {
  // Perform the carry for the later subtraction by updating rhs.
  int64_t rsec = rhs.tv_sec, rnsec = rhs.tv_nsec;
  if (lhs.tv_nsec < rnsec) {
    int sec = (rnsec - lhs.tv_nsec) / kNanosecondsPerSecond + 1;
    rnsec -= kNanosecondsPerSecond * sec;
    rsec += sec;
  }

  int64_t delta_nsec = lhs.tv_nsec - rnsec;
  if (delta_nsec > kNanosecondsPerSecond) {
    int64_t sec = delta_nsec / kNanosecondsPerSecond;
    rnsec += kNanosecondsPerSecond * sec;
    rsec -= sec;
  }

  // Compute the time remaining to wait. tv_nsec is certainly positive.
  result->tv_sec = lhs.tv_sec - rsec;
  result->tv_nsec = lhs.tv_nsec - rnsec;
  return lhs.tv_sec < rsec;
}

int64_t TimeSpecToNanoseconds(const timespec *ts) {
  return ts->tv_sec * kNanosecondsPerSecond + ts->tv_nsec;
}

int64_t TimeValToNanoseconds(const timeval *tv) {
  return tv->tv_sec * kNanosecondsPerSecond +
         tv->tv_usec * kNanosecondsPerMicrosecond;
}

timespec *NanosecondsToTimeSpec(timespec *ts, int64_t nanosecs) {
  ts->tv_sec = nanosecs / kNanosecondsPerSecond;
  ts->tv_nsec = nanosecs % kNanosecondsPerSecond;
  return ts;
}

timeval *NanosecondsToTimeVal(timeval *tv, int64_t nanosecs) {
  tv->tv_sec = nanosecs / kNanosecondsPerSecond;
  tv->tv_usec = nanosecs / kNanosecondsPerMicrosecond % kMicrosecondsPerSecond;
  return tv;
}

}  // namespace asylo
