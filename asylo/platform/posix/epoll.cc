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

#include <sys/epoll.h>
#include <cstdlib>
#include "asylo/platform/posix/io/io_manager.h"

using asylo::io::IOManager;

extern "C" {

int epoll_create(int size) {
  return IOManager::GetInstance().EpollCreate(size);
}

// Currently, we delegate to epoll_create since we don't yet support fork() and
// the only flag available (EPOLL_CLOEXEC) is relevant to multiple processes.
// Specifying the parameter 1 makes epoll_create1 behave like regular
// epoll_create.
int epoll_create1(int /* flags */) { return epoll_create(1); }

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) {
  return IOManager::GetInstance().EpollCtl(epfd, op, fd, event);
}

int epoll_wait(int epfd, struct epoll_event *events, int maxevents,
               int timeout) {
  if (maxevents <= 0) {
      errno = EINVAL;
      return -1;
  }
  return IOManager::GetInstance().EpollWait(epfd, events, maxevents, timeout);
}

}  // extern "C"
