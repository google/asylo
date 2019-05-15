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

#include <sys/stat.h>
#include <sys/types.h>

#include "asylo/platform/posix/io/io_manager.h"

using asylo::io::IOManager;

extern "C" {

int lstat(const char *pathname, struct stat *stat_buffer) {
  return IOManager::GetInstance().LStat(pathname, stat_buffer);
}

mode_t umask(mode_t mask) { return IOManager::GetInstance().Umask(mask); }

int chmod(const char *pathname, mode_t mode) {
  return IOManager::GetInstance().ChMod(pathname, mode);
}

int fchmod(int fd, mode_t mode) {
  return IOManager::GetInstance().FChMod(fd, mode);
}

int mkdir(const char *pathname, mode_t mode) {
  return IOManager::GetInstance().Mkdir(pathname, mode);
}

}  // extern "C"
