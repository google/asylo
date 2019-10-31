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

#include <assert.h>
#include <errno.h>
#include <malloc.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

// Hard-code a reasonable guess for the page size, without having to
// make an untrusted call.
static const size_t kPageSize = 4096;

#ifndef ASYLO_MMAN_MOVE_TRANSITION
void *mmap(void *addr, size_t length, int prot, int flags, int fd,
           off_t offset) {
  if (addr || prot != (PROT_READ | PROT_WRITE) ||
      flags != (MAP_ANON | MAP_PRIVATE) || fd != -1 || offset != 0) {
    errno = ENOSYS;
    return MAP_FAILED;
  }
  void *ptr = memalign(kPageSize, length);
  memset(ptr, 0, length);
  return ptr;
}

int munmap(void *addr, size_t length) {
  free(addr);
  return 0;
}
#endif

// Only _SC_PAGESIZE is supported for now.
long sysconf(int name) {
  switch (name) {
    case _SC_PAGESIZE:
      return kPageSize;
    default:
      errno = ENOSYS;
      return -1;
  }
}
