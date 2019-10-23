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

#include <sys/time.h>
#include <utime.h>

#include "asylo/platform/posix/io/io_manager.h"

extern "C" {

int utime(const char *filename, const struct utimbuf *times) {
  return asylo::io::IOManager::GetInstance().Utime(filename, times);
}

int utimes(const char *filename, const struct timeval times[2]) {
  return asylo::io::IOManager::GetInstance().Utimes(filename, times);
}

}  // extern "C"
