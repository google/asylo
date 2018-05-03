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

#ifndef ASYLO_PLATFORM_POSIX_INCLUDE_FCNTL_H_
#define ASYLO_PLATFORM_POSIX_INCLUDE_FCNTL_H_

// This header file is a redirect file that replaces newlib's redirect file
// <fcntl.h>, in order to complement redirection to <sys/fcntl.h> with
// enclave-specific extensions to POSIX definitions.
#include <sys/fcntl.h>

#define O_SECURE 0x80000000
#undef O_NONBLOCK
#define O_NONBLOCK 04000

#endif  // ASYLO_PLATFORM_POSIX_INCLUDE_FCNTL_H_
