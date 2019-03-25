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

#include_next <sys/resource.h>

#ifndef ASYLO_PLATFORM_POSIX_INCLUDE_SYS_RESOURCE_H_
#define ASYLO_PLATFORM_POSIX_INCLUDE_SYS_RESOURCE_H_

#ifdef __cplusplus
extern "C" {
#endif

#define RLIMIT_CPU 0    /* Per-process CPU limit, in seconds.  */
#define RLIMIT_FSIZE 1  /* Largest file that can be created, in bytes.  */
#define RLIMIT_DATA 2   /* Maximum size of data segment, in bytes.  */
#define RLIMIT_STACK 3  /* Maximum size of stack segment, in bytes.  */
#define RLIMIT_CORE 4   /* Largest core file that can be created, in bytes.  */
#define RLIMIT_RSS 5    /* Largest resident set size, in bytes. */
#define RLIMIT_NPROC 6  /* Number of processes.  */
#define RLIMIT_NOFILE 7 /* Number of open files.  */
#define RLIMIT_OFILE RLIMIT_NOFILE /* BSD name for the above. */
#define RLIMIT_MEMLOCK 8           /* Locked-in-memory address space.  */
#define RLIMIT_AS 9                /* Address space limit.  */

typedef uint64_t rlim_t;

struct rlimit {
  rlim_t rlim_cur; /* current soft limit */
  rlim_t rlim_max; /* maximum value for rlim_cur */
};

int getrlimit(int resource, struct rlimit *rlim);
int setrlimit(int resource, const struct rlimit *rlim);

#define RLIM_INFINITY 0xffffffffffffffffuLL

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // ASYLO_PLATFORM_POSIX_INCLUDE_SYS_RESOURCE_H_
