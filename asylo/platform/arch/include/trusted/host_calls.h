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

// Allocates memory on the untrusted heap. This function never returns nullptr.
// Instead of returning nullptr, it will abort in the following cases:
//   * If the memory allocation fails
//   * If the host call fails for any reason (this may be backend-specific)
void *enc_untrusted_malloc(size_t size);

// Reallocates memory on the untrusted heap.
void *enc_untrusted_realloc(void *ptr, size_t size);

// Releases memory on the untrusted heap.
void enc_untrusted_free(void *ptr);

//////////////////////////////////////
//          Error Handling          //
//////////////////////////////////////

// Fetches the value of errno from the untrusted C runtime.
int enc_untrusted_get_errno();

//////////////////////////////////////
//          Input / Output          //
//////////////////////////////////////

int enc_untrusted_open(const char *path_name, int flags, ...);
int enc_untrusted_close(int fd);
ssize_t enc_untrusted_read(int fd, void *buf, size_t len);
ssize_t enc_untrusted_write(int fd, const void *buf, size_t len);
int enc_untrusted_puts(const char *str);
off_t enc_untrusted_lseek(int fd, off_t offset, int whence);
int enc_untrusted_unlink(const char *path_name);
int enc_untrusted_fcntl(int fd, int cmd, ...);
int enc_untrusted_fsync(int fd);
int enc_untrusted_access(const char *path_name, int mode);
int enc_untrusted_chown(const char *path, uid_t owner, gid_t group);
int enc_untrusted_link(const char *from, const char *to);
ssize_t enc_untrusted_readlink(const char *path, char *buf, size_t bufsize);
int enc_untrusted_stat(const char *pathname, struct stat *stat_buffer);
int enc_untrusted_lstat(const char *pathname, struct stat *stat_buffer);
int enc_untrusted_symlink(const char *from, const char *to);
int enc_untrusted_fstat(int fd, struct stat *stat_buffer);
int enc_untrusted_isatty(int file);
ssize_t enc_untrusted_writev(int fd, const struct iovec *iov, int iovcnt);
ssize_t enc_untrusted_readv(int fd, const struct iovec *iov, int iovcnt);

//////////////////////////////////////
//            Sockets               //
//////////////////////////////////////

int enc_untrusted_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int enc_untrusted_bind(int sockfd, const struct sockaddr *addr,
                       socklen_t addrlen);
int enc_untrusted_connect(int sockfd, const struct sockaddr *addr,
                          socklen_t addrlen);
int enc_untrusted_listen(int sockfd, int backlog);
int enc_untrusted_setsockopt(int socket, int level, int option_name,
                             const void *option_value, socklen_t option_len);
int enc_untrusted_shutdown(int sockfd, int how);
int enc_untrusted_socket(int domain, int type, int protocol);
const char *enc_untrusted_inet_ntop(int af, const void *src, char *dst,
                                    socklen_t size);
int enc_untrusted_inet_pton(int af, const char *src, void *dst);
ssize_t enc_untrusted_send(int sockfd, const void *buf, size_t len, int flags);
ssize_t enc_untrusted_sendmsg(int sockfd, const struct msghdr *msg, int flags);
ssize_t enc_untrusted_recvmsg(int sockfd, struct msghdr *msg, int flags);
int enc_untrusted_getaddrinfo(const char *node, const char *service,
                              const struct addrinfo *hints,
                              struct addrinfo **res);
void enc_untrusted_freeaddrinfo(struct addrinfo *res);
int enc_untrusted_getsockopt(int sockfd, int level, int optname, void *optval,
                             socklen_t *optlen);
int enc_untrusted_getsockname(int sockfd, struct sockaddr *addr,
                              socklen_t *addrlen);
int enc_untrusted_getpeername(int sockfd, struct sockaddr *addr,
                              socklen_t *addrlen);
ssize_t enc_untrusted_recvfrom(int sockfd, void *buf, size_t len, int flags,
                               struct sockaddr *src_addr, socklen_t *addrlen);

//////////////////////////////////////
//            Threading             //
//////////////////////////////////////

// Exits and creates a new thread to invoke the EnterAndDonateThread entry point
// of the named enclave.
int enc_untrusted_create_thread(const char *name);

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

int enc_untrusted_inotify_init1(int non_block);
int enc_untrusted_inotify_add_watch(int fd, const char *pathname,
                                    uint32_t mask);
int enc_untrusted_inotify_rm_watch(int fd, int wd);
int enc_untrusted_inotify_read(int fd, size_t count, char **serialized_events,
                               size_t *serialized_events_len);

//////////////////////////////////////
//            ifaddrs.h             //
//////////////////////////////////////

int enc_untrusted_getifaddrs(struct ifaddrs **ifap);
void enc_untrusted_freeifaddrs(struct ifaddrs *ifa);

//////////////////////////////////////
//            sched.h               //
//////////////////////////////////////

// Returns -1 and sets |errno| to |EINVAL| if |cpusetsize| is less than
// |sizeof(/*enclave-native*/ cpu_set_t)|.
int enc_untrusted_sched_getaffinity(pid_t pid, size_t cpusetsize,
                                    cpu_set_t *mask);
int enc_untrusted_sched_yield();

//////////////////////////////////////
//            signal.h              //
//////////////////////////////////////

int enc_untrusted_register_signal_handler(
    int signum,
    void (*bridge_sigaction)(int, struct bridge_siginfo_t *, void *),
    const sigset_t mask, const char *enclave_name);

int enc_untrusted_sigprocmask(int how, const sigset_t *set, sigset_t *oldset);

int enc_untrusted_raise(int sig);

//////////////////////////////////////
//        sys/resource.h            //
//////////////////////////////////////

int enc_untrusted_getrusage(int who, struct rusage *usage);

//////////////////////////////////////
//          sys/file.h              //
//////////////////////////////////////

int enc_untrusted_flock(int fd, int operation);

//////////////////////////////////////
//         sys/select.h             //
//////////////////////////////////////

int enc_untrusted_select(int nfds, fd_set *readfds, fd_set *writefds,
                         fd_set *exceptfds, struct timeval *timeout);

//////////////////////////////////////
//          sys/stat.h              //
//////////////////////////////////////

int enc_untrusted_mkdir(const char *path, int mode);
mode_t enc_untrusted_umask(mode_t mask);
int enc_untrusted_chmod(const char *pathname, mode_t mode);

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

int enc_untrusted_nanosleep(const struct timespec *req, struct timespec *rem);
int enc_untrusted_gettimeofday(struct timeval *tv, void *tz);
int enc_untrusted_times(struct tms *buf);
int enc_untrusted_clock_gettime(clockid_t clk_id, struct timespec *tp);
int enc_untrusted_setitimer(int which, const struct itimerval *new_value,
                            struct itimerval *old_value);

//////////////////////////////////////
//            unistd.h              //
//////////////////////////////////////

int enc_untrusted_pipe(int pipefd[2]);
int64_t enc_untrusted_sysconf(int name);
uint32_t enc_untrusted_sleep(uint32_t seconds);
int enc_untrusted_usleep(useconds_t usec);
uid_t enc_untrusted_getuid();
uid_t enc_untrusted_geteuid();
gid_t enc_untrusted_getgid();
gid_t enc_untrusted_getegid();
pid_t enc_untrusted_getpid();
pid_t enc_untrusted_getppid();
pid_t enc_untrusted_setsid();
int enc_untrusted_truncate(const char *path, off_t length);
int enc_untrusted_ftruncate(int fd, off_t length);

//////////////////////////////////////
//            utime.h               //
//////////////////////////////////////

int enc_untrusted_utime(const char *filename, const struct utimbuf *times);

//////////////////////////////////////
//           wait.h                 //
//////////////////////////////////////

int enc_untrusted_wait(int *wstatus);
pid_t enc_untrusted_wait3(int *wstatus, int options, struct rusage *rusage);

//////////////////////////////////////
//            Runtime support       //
//////////////////////////////////////

// Acquires a shared resource for non-exclusive use by incrementing its
// reference count and returning a pointer to untrusted memory. Returns nullptr
// if the named resource does not exist. The caller is responsible for releasing
// the resource once it is no longer needed.
void *enc_untrusted_acquire_shared_resource(enum SharedNameKind kind,
                                            const char *name);

// Releases a shared resource by decrementing its reference count and, if this
// is a managed resource, deleting it once its count reaches zero (0). Returns 0
// on success.
int enc_untrusted_release_shared_resource(enum SharedNameKind kind,
                                          const char *name);

//////////////////////////////////////
//            Debugging             //
//////////////////////////////////////

// Prints a buffer to standard error as hex.
void enc_untrusted_hex_dump(const void *buf, int nbytes);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // ASYLO_PLATFORM_ARCH_INCLUDE_TRUSTED_HOST_CALLS_H_
