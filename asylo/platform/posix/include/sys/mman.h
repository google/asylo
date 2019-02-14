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

#ifndef ASYLO_PLATFORM_POSIX_INCLUDE_SYS_MMAN_H_
#define ASYLO_PLATFORM_POSIX_INCLUDE_SYS_MMAN_H_

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PROT_READ  0x04
#define PROT_WRITE 0x02
#define PROT_EXEC  0x01

#define MAP_FAILED ((void *)-1)

#define MAP_SHARED     0x00001
#define MAP_PRIVATE    0x00002
#define MAP_FIXED      0x00010 /* Interpret addr exactly.  */
#define MAP_ANONYMOUS  0x00020 /* Don't use a file.  */
#define MAP_ANON MAP_ANONYMOUS
#define MAP_GROWSDOWN  0x00100 /* Stack-like segment.  */
#define MAP_DENYWRITE  0x00800 /* ETXTBSY */
#define MAP_EXECUTABLE 0x01000 /* Mark it as an executable.  */
#define MAP_LOCKED     0x02000 /* Lock the mapping.  */
#define MAP_NORESERVE  0x04000 /* Don't check for reservations.  */
#define MAP_POPULATE   0x08000 /* Populate (prefault) pagetables.  */
#define MAP_NONBLOCK   0x10000 /* Do not block on IO.  */
#define MAP_STACK      0x20000 /* Allocation is for a stack.  */
#define MAP_HUGETLB    0x40000 /* Create huge page mapping.  */

void *mmap(void *addr, size_t length, int prot, int flags, int fd,
           off_t offset);

int munmap(void *addr, size_t length);

// Unimplemented.
int mlock(const void *addr, size_t len);
int mlock2(const void *addr, size_t len, int flags);
int munlock(const void *addr, size_t len);
int mlockall(int flags);
int munlockall(void);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // ASYLO_PLATFORM_POSIX_INCLUDE_SYS_MMAN_H_
