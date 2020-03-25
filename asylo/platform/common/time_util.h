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

#ifndef ASYLO_PLATFORM_COMMON_TIME_UTIL_H_
#define ASYLO_PLATFORM_COMMON_TIME_UTIL_H_

#include <cstdint>
#include <ctime>

namespace asylo {

constexpr int64_t kMicrosecondsPerSecond = INT64_C(1000000);
constexpr int64_t kNanosecondsPerMicrosecond = INT64_C(1000);
constexpr int64_t kNanosecondsPerSecond = INT64_C(1000000000);
constexpr int64_t kFirstRepresentableSecond = INT64_MIN / kNanosecondsPerSecond;
constexpr int64_t kLastRepresentableSecond = INT64_MAX / kNanosecondsPerSecond;

// Returns true if |ts| is representable by a signed 64-bit offset from the
// epoch. (+/- ~290 years)
bool IsRepresentableAsNanoseconds(const struct timespec *ts);

// Returns true if |tv| is representable by a signed 64-bit offset from the
// epoch. (+/- ~290 years)
bool IsRepresentableAsNanoseconds(const struct timeval *tv);

// Computes the difference |lhs| - |rhs| and puts the result in |result|.
// Returns true if |lhs| < |rhs|, false otherwise.
bool TimeSpecSubtract(const struct timespec &lhs, const struct timespec &rhs,
                      struct timespec *result);

// Converts a timespec to a number of nanoseconds since the epoch.
int64_t TimeSpecToNanoseconds(const timespec *ts);

// Converts a timeval to a number of nanoseconds since the epoch.
int64_t TimeValToNanoseconds(const timeval *tv);

// Converts a timespec to a number of microseconds since the epoch.
int64_t TimeSpecToMicroseconds(const timespec *ts);

// Converts a timeval to a number of microseconds since the epoch.
int64_t TimeValToMicroseconds(const timeval *tv);

// Converts a time in nanoseconds since the epoch to a timespec value.
struct timespec *NanosecondsToTimeSpec(struct timespec *ts, int64_t nanosecs);

// Converts a time in nanoseconds since the epoch to a timeval value.
struct timeval *NanosecondsToTimeVal(struct timeval *tv, int64_t nanosecs);

// Converts a time in microseconds since the epoch to a timespec value.
struct timespec *MicrosecondsToTimeSpec(struct timespec *ts, int64_t microsecs);

// Converts a time in microseconds since the epoch to a timeval value.
struct timeval *MicrosecondsToTimeVal(struct timeval *tv, int64_t microsecs);

// Returns the time difference between two timevals in microseconds.
int64_t TimeValDiffInMicroseconds(const timeval *end, const timeval *start);

// Returns the time difference between two timespecs in nanoseconds.
int64_t TimeSpecDiffInNanoseconds(const timespec *end, const timespec *start);

}  // namespace asylo

#endif  // ASYLO_PLATFORM_COMMON_TIME_UTIL_H_
