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

#include <errno.h>
#include <string.h>
#include <unistd.h>

// Hard-code a reasonable guess for the page size, without having to
// make an untrusted call.
static const size_t kPageSize = 4096;

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
