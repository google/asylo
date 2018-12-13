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

#include <grp.h>

#include <stdlib.h>
#include <sys/types.h>

extern "C" {

int getgrgid_r(gid_t gid, struct group *grp, char *buf, size_t buflen,
               struct group **result) {
  abort();
}

int getgrnam_r(const char *name, struct group *grp, char *buf, size_t buflen,
               struct group **result) {
  abort();
}

}  // extern "C"
