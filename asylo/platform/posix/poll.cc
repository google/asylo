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

#include <poll.h>

#include <sys/select.h>
#include <cstdlib>

#include "asylo/platform/arch/include/trusted/host_calls.h"
#include "asylo/platform/posix/io/io_manager.h"

using asylo::io::IOManager;

#ifdef __cplusplus
extern "C" {
#endif

int poll(struct pollfd *fds, nfds_t nfds, int timeout) {
  return IOManager::GetInstance().Poll(fds, nfds, timeout);
}

int select(int __n, fd_set *__readfds, fd_set *__writefds, fd_set *__exceptfds,
           struct timeval *__timeout) {
  abort();
}

#ifdef __cplusplus
}  // extern "C"
#endif
