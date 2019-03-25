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

#include_next <time.h>

#ifndef ASYLO_PLATFORM_POSIX_INCLUDE_TIME_H_
#define ASYLO_PLATFORM_POSIX_INCLUDE_TIME_H_

#ifdef __cplusplus
extern "C" {
#endif

// Pause the calling thread execution for requested amount of time.
// The POSIX spec for remainder is not supported.
int nanosleep(const struct timespec *requested, struct timespec *remainder);

// Spec from ctime
int clock_gettime(clockid_t clock_id, struct timespec *time);

#ifdef __cplusplus
}
#endif

#endif  // ASYLO_PLATFORM_POSIX_INCLUDE_TIME_H_
