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

#include_next <errno.h>

#ifndef ASYLO_PLATFORM_POSIX_INCLUDE_ERRNO_H_
#define ASYLO_PLATFORM_POSIX_INCLUDE_ERRNO_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Evaluate EXPRESSION, and repeat as long as it returns -1 with `errno'
   set to EINTR.  */

#ifndef TEMP_FAILURE_RETRY
#define TEMP_FAILURE_RETRY(expression)           \
  (__extension__({                               \
    uint32_t __result;                           \
    do {                                         \
      __result = (uint32_t)(expression);         \
    } while (__result == -1L && errno == EINTR); \
    __result;                                    \
    }))
#endif  // TEMP_FAILURE_RETRY

#ifdef __cplusplus
}
#endif

#endif  // ASYLO_PLATFORM_POSIX_INCLUDE_ERRNO_H_
