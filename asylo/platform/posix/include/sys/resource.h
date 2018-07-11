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

#ifndef ASYLO_PLATFORM_POSIX_INCLUDE_SYS_RESOURCE_H_
#define ASYLO_PLATFORM_POSIX_INCLUDE_SYS_RESOURCE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include_next <sys/resource.h>

#define RLIMIT_NOFILE 0 /* maximum file descriptor number */

typedef uint64_t rlim_t;

struct rlimit {
  rlim_t rlim_cur; /* current soft limit */
  rlim_t rlim_max; /* maximum value for rlim_cur */
};

int getrlimit(int resource, struct rlimit *rlim);
int setrlimit(int resource, const struct rlimit *rlim);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // ASYLO_PLATFORM_POSIX_INCLUDE_SYS_RESOURCE_H_
