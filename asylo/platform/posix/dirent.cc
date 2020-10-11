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

#include <dirent.h>

#include <cstdint>
#include <cstdlib>

extern "C" {

int getdents (int fd, void *dirp, unsigned int count) {
  abort();
}

int __attribute__((weak)) closedir(DIR *) { abort(); }

DIR * __attribute__((weak)) opendir(const char *) { abort(); }

struct dirent * __attribute__((weak)) readdir(DIR *) {
  abort();
}

int __attribute__((weak)) readdir_r(DIR *, struct dirent *, struct dirent **) {
  abort();
}

void __attribute__((weak)) rewinddir(DIR *) { abort(); }

void __attribute__((weak)) seekdir(DIR *, int64_t) { abort(); }

int64_t __attribute__((weak)) telldir(DIR *) { abort(); }

}  // extern "C"
