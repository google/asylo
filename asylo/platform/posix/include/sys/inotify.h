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

#ifndef ASYLO_PLATFORM_POSIX_INCLUDE_SYS_INOTIFY_H_
#define ASYLO_PLATFORM_POSIX_INCLUDE_SYS_INOTIFY_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Flags for inotify_init1(2).
#define IN_NONBLOCK 0x01
#define IN_CLOEXEC 0x02

// Bitmask flags for inotify events.
#define IN_ACCESS 0x001
#define IN_ATTRIB 0x002
#define IN_CLOSE_WRITE 0x004
#define IN_CLOSE_NOWRITE 0x008
#define IN_CREATE 0x010
#define IN_DELETE 0x020
#define IN_DELETE_SELF 0x040
#define IN_MODIFY 0x080
#define IN_MOVE_SELF 0x100
#define IN_MOVED_FROM 0x200
#define IN_MOVED_TO 0x400
#define IN_OPEN 0x800

// Combination flags
#define IN_ALL_EVENTS                                                      \
  (IN_ACCESS | IN_ATTRIB | IN_CLOSE_WRITE | IN_CLOSE_NOWRITE | IN_CREATE | \
   IN_DELETE | IN_DELETE_SELF | IN_MODIFY | IN_MOVE_SELF | IN_MOVED_FROM | \
   IN_MOVED_TO | IN_OPEN)
#define IN_MOVE (IN_MOVED_FROM | IN_MOVED_TO)
#define IN_CLOSE (IN_CLOSE_WRITE | IN_CLOSE_NOWRITE)

// Further flags for inotify_add_watch(2).
#define IN_DONT_FOLLOW 0x01000
#define IN_EXCL_UNLINK 0x02000
#define IN_MASK_ADD 0x04000
#define IN_ONESHOT 0x08000
#define IN_ONLYDIR 0x10000

// Additional flags that may be set in the buffer modified by read(2).
#define IN_IGNORED 0x020000
#define IN_ISDIR 0x040000
#define IN_Q_OVERFLOW 0x080000
#define IN_UNMOUNT 0x100000

// API functions for interacting with an inotify object.
int inotify_init(void);
int inotify_init1(int flags);
int inotify_add_watch(int fd, const char *pathname, uint32_t mask);
int inotify_rm_watch(int fd, int wd);

// Struct definition from inotify(7) man page.
struct inotify_event {
  int wd;           // Watch descriptor
  uint32_t mask;    // Mask describing event
  uint32_t cookie;  // Unique cookie associating related events (for rename(2))
  uint32_t len;     // Size of name field
  char name[];      // Optional null-terminated name
};

#ifdef __cplusplus
}  // extern "C"
#endif
#endif  // ASYLO_PLATFORM_POSIX_INCLUDE_SYS_INOTIFY_H_
