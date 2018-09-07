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

#include <sys/inotify.h>
#include <cstdlib>
#include "asylo/platform/posix/io/io_manager.h"

using asylo::io::IOManager;

extern "C" {

int inotify_init1(int flags) {
  bool non_block = flags & IN_NONBLOCK;
  return IOManager::GetInstance().InotifyInit(non_block);
}

int inotify_init() { return inotify_init1(0); }

int inotify_add_watch(int fd, const char *pathname, uint32_t mask) {
  return IOManager::GetInstance().InotifyAddWatch(fd, pathname, mask);
}

int inotify_rm_watch(int fd, int wd) {
  return IOManager::GetInstance().InotifyRmWatch(fd, wd);
}

}  // extern "C"
