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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif  // _GNU_SOURCE

#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>

#include "asylo/util/logging.h"

// A simple application that prints each of its command-line arguments on its
// own line in order and exits with a value equal to the number of command-line
// arguments it was given.
//
// If running inside an enclave, the application also prints out each
// environment variable in its EnclaveConfig in the form NAME="VALUE".
int main(int argc, char *argv[]) {
  for (int i = 0; i < argc; ++i) {
    printf("%s\n", argv[i]);
  }

#ifdef __ASYLO__
  for (char **variable = environ; *variable != nullptr; ++variable) {
    const char *equals_sign = CHECK_NOTNULL(strchr(*variable, '='));
    const char *name_start = *variable;
    int name_length = equals_sign - *variable;
    const char *value_start = equals_sign + 1;
    std::string name(name_start, name_length);
    printf("%s=\"%s\"\n", name.c_str(), value_start);
  }
#endif  // __ASYLO__

  CHECK_EQ(fflush(stdout), 0) << strerror(errno);

  return argc;
}
