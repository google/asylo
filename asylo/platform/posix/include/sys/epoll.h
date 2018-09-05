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

#ifndef ASYLO_PLATFORM_POSIX_INCLUDE_SYS_EPOLL_H_
#define ASYLO_PLATFORM_POSIX_INCLUDE_SYS_EPOLL_H_
#ifdef __cplusplus
extern "C" {
#endif

#include <signal.h>
#include <stdint.h>

// Epoll event flags.
#define EPOLLIN 0x001
#define EPOLLPRI 0x002
#define EPOLLOUT 0x004
#define EPOLLMSG 0x008
#define EPOLLERR 0x010
#define EPOLLHUP 0x020
#define EPOLLRDHUP 0x040
#define EPOLLWAKEUP 0x080
#define EPOLLONESHOT 0x100
#define EPOLLET 0x200

// Flag for epoll_create.
#define EPOLL_CLOEXEC 0x01

// Operation flags for epoll_ctl.
#define EPOLL_CTL_ADD 1
#define EPOLL_CTL_DEL 2
#define EPOLL_CTL_MOD 3

typedef union epoll_data {
  void *ptr;
  int fd;
  uint32_t u32;
  uint64_t u64;
} epoll_data_t;

struct epoll_event {
  uint32_t events;
  epoll_data_t data;
};

int epoll_create(int size);
int epoll_create1(int flags);
int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
int epoll_wait(int epfd, struct epoll_event *events, int maxevents,
               int timeout);

#ifdef __cplusplus
}  // extern "C"
#endif
#endif  // ASYLO_PLATFORM_POSIX_INCLUDE_SYS_EPOLL_H_
