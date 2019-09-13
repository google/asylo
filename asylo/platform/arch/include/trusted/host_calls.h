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

#ifndef ASYLO_PLATFORM_ARCH_INCLUDE_TRUSTED_HOST_CALLS_H_
#define ASYLO_PLATFORM_ARCH_INCLUDE_TRUSTED_HOST_CALLS_H_

// Defines the C language interface to the untrusted host environment. These
// functions invoke code outside the enclave and secure applications must assume
// an adversarial implementation.

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <poll.h>
#include <pwd.h>
#include <sched.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#include "asylo/platform/core/shared_name_kind.h"

#ifdef __cplusplus
extern "C" {
#endif

// Unless otherwise specified, each of the following calls invokes the
// corresponding function on the host.

//////////////////////////////////////////////////
//          Untrusted Heap Allocations          //
//////////////////////////////////////////////////

// Allocates |count| buffers of size |size| on the untrusted heap, returning a
// pointer to an array of buffer pointers.
void **enc_untrusted_allocate_buffers(
    size_t count, size_t size);

// Releases memory on the untrusted heap pointed to by buffer pointers stored in
// |free_list|.
void enc_untrusted_deallocate_free_list(void **free_list, size_t count);

//////////////////////////////////////
//          Error Handling          //
//////////////////////////////////////

// Fetches the value of errno from the untrusted C runtime.
int enc_untrusted_get_errno();

//////////////////////////////////////
//          Input / Output          //
//////////////////////////////////////

ssize_t enc_untrusted_pread(int fd, void *buf, size_t count, off_t offset);

//////////////////////////////////////
//            Sockets               //
//////////////////////////////////////

const char *enc_untrusted_inet_ntop(int af, const void *src, char *dst,
                                    socklen_t size);
int enc_untrusted_inet_pton(int af, const char *src, void *dst);
int enc_untrusted_getaddrinfo(const char *node, const char *service,
                              const struct addrinfo *hints,
                              struct addrinfo **res);
void enc_untrusted_freeaddrinfo(struct addrinfo *res);

//////////////////////////////////////
//            Threading             //
//////////////////////////////////////

// Exits the enclave and, if the value stored at |futex| equals |expected|,
// suspends the calling thread until it is resumed by a call to
// enc_untrusted_sys_futex_wake. Otherwise returns immediately.
void enc_untrusted_sys_futex_wait(int32_t *futex, int32_t expected);

// Exits the enclave and wakes a suspended thread blocked on |futex|.
void enc_untrusted_sys_futex_wake(int32_t *futex);

//////////////////////////////////////
//            poll.h                //
//////////////////////////////////////

int enc_untrusted_poll(struct pollfd *fds, nfds_t nfds, int timeout);

//////////////////////////////////////
//            epoll.h               //
//////////////////////////////////////

int enc_untrusted_epoll_create(int size);
int enc_untrusted_epoll_ctl(int epfd, int op, int fd,
                            struct epoll_event *event);
int enc_untrusted_epoll_wait(int epfd, struct epoll_event *events,
                             int maxevents, int timeout);

//////////////////////////////////////
//            inotify.h             //
//////////////////////////////////////

int enc_untrusted_inotify_read(int fd, size_t count, char **serialized_events,
                               size_t *serialized_events_len);

//////////////////////////////////////
//            ifaddrs.h             //
//////////////////////////////////////

int enc_untrusted_getifaddrs(struct ifaddrs **ifap);
void enc_untrusted_freeifaddrs(struct ifaddrs *ifa);

//////////////////////////////////////
//              pwd.h               //
//////////////////////////////////////

struct passwd *enc_untrusted_getpwuid(uid_t uid);

//////////////////////////////////////
//            signal.h              //
//////////////////////////////////////

int enc_untrusted_register_signal_handler(
    int signum,
    void (*bridge_sigaction)(int, struct bridge_siginfo_t *, void *),
    const sigset_t mask, int flags, const char *enclave_name);

int enc_untrusted_sigprocmask(int how, const sigset_t *set, sigset_t *oldset);

//////////////////////////////////////
//        sys/resource.h            //
//////////////////////////////////////

int enc_untrusted_getrusage(int who, struct rusage *usage);

//////////////////////////////////////
//         sys/syslog.h             //
//////////////////////////////////////

void enc_untrusted_openlog(const char *ident, int option, int facility);
void enc_untrusted_syslog(int priority, const char *message);

//////////////////////////////////////
//         sys/utsname.h            //
//////////////////////////////////////

int enc_untrusted_uname(struct utsname *utsname_buf);

//////////////////////////////////////
//            time.h                //
//////////////////////////////////////

int enc_untrusted_times(struct tms *buf);
int enc_untrusted_getitimer(int which, struct itimerval *curr_value);
int enc_untrusted_setitimer(int which, const struct itimerval *new_value,
                            struct itimerval *old_value);

//////////////////////////////////////
//            unistd.h              //
//////////////////////////////////////

void enc_untrusted__exit(int rc);
pid_t enc_untrusted_fork(const char *enclave_name, bool restore_snapshot);

//////////////////////////////////////
//            utime.h               //
//////////////////////////////////////

int enc_untrusted_utime(const char *filename, const struct utimbuf *times);
int enc_untrusted_utimes(const char *filename, const struct timeval times[2]);

//////////////////////////////////////
//           wait.h                 //
//////////////////////////////////////

pid_t enc_untrusted_wait3(int *wstatus, int options, struct rusage *usage);
pid_t enc_untrusted_waitpid(pid_t pid, int *wstatus, int options);

//////////////////////////////////////
//            Debugging             //
//////////////////////////////////////

// Prints a buffer to standard error as hex.
void enc_untrusted_hex_dump(const void *buf, int nbytes);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // ASYLO_PLATFORM_ARCH_INCLUDE_TRUSTED_HOST_CALLS_H_
