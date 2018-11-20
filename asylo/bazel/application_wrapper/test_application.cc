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

#include <cerrno>
#include <cstdio>
#include <cstring>

#include "asylo/util/logging.h"

// A simple application that prints each of its command-line arguments on its
// own line in order and exits with a value equal to the number of command-line
// arguments it was given.
int main(int argc, char *argv[]) {
  for (int i = 0; i < argc; ++i) {
    printf("%s\n", argv[i]);
  }
  CHECK_EQ(fflush(stdout), 0) << strerror(errno);

  return argc;
}
