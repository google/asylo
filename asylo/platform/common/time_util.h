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

// Returns true if |ts| is representable by a signed 64-bit offset from the
// epoch. (+/- ~290 years)
bool IsRepresentableAsNanoseconds(const struct timespec *ts);

// Returns true if |tv| is representable by a signed 64-bit offset from the
// epoch. (+/- ~290 years)
bool IsRepresentableAsNanoseconds(const struct timeval *tv);

// Computes the difference between two timespecs and sets |result|. True if
// |lhs| < |rhs|, otherwise false.
bool TimeSpecSubtract(struct timespec *result, const struct timespec &lhs,
                      const struct timespec &rhs);

// Converts a timespec to a number of nanoseconds since the epoch.
int64_t TimeSpecToNanoseconds(const timespec *ts);

// Converts a timeval to a number of nanoseconds since the epoch.
int64_t TimeValToNanoseconds(const timeval *tv);

// Converts a time in nanoseconds since the epoch to a timespec value.
struct timespec *NanosecondsToTimeSpec(struct timespec *ts, int64_t nanosecs);

// Converts a time in nanoseconds since the epoch to a timeval value.
struct timeval *NanosecondsToTimeVal(struct timeval *tv, int64_t nanosecs);

}  // namespace asylo

#endif  // ASYLO_PLATFORM_COMMON_TIME_UTIL_H_
