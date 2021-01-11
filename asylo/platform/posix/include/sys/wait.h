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

#include_next <sys/wait.h>

#ifndef ASYLO_PLATFORM_POSIX_INCLUDE_SYS_WAIT_H_
#define ASYLO_PLATFORM_POSIX_INCLUDE_SYS_WAIT_H_

#include <sys/resource.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WNOHANG 1

pid_t wait3(int *wstatus, int options, struct rusage *rusage);
pid_t wait4(pid_t pid, int *wstatus, int options, struct rusage *rusage);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // ASYLO_PLATFORM_POSIX_INCLUDE_SYS_WAIT_H_
