/*
 *
 * Copyright 2019 Asylo authors
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

#ifndef ASYLO_PLATFORM_HOST_CALL_TRUSTED_HOST_CALLS_H_
#define ASYLO_PLATFORM_HOST_CALL_TRUSTED_HOST_CALLS_H_

// Defines the C language interface to the untrusted host environment. These
// functions invoke code outside the enclave and secure applications must assume
// an adversarial implementation. Some functions like enc_freeaddrinfo() do not
// exit the enclave but should be used in conjunction with addrinfo related host
// calls, like enc_untrusted_getaddrinfo().

#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sched.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <type_traits>

#include "asylo/platform/host_call/trusted/host_call_dispatcher.h"
#include "asylo/platform/primitives/util/message.h"
#include "asylo/platform/system_call/sysno.h"
#include "asylo/platform/system_call/system_call.h"

namespace internal {
// Technique to verify all values are true. This works by effectively comparing
// the list of bools with true both prefixed and suffixed. e.g.
//   If the input is (t, t), then we compare (t, t, t) with (t, t, t) == true.
//   If Input is (t, f), then we compare (t, t, f) with (t, f, t) == false.
//
// This works by having `AllTrue`
// "shift" the list of bool values passed to BoolPack left and right by a "true"
// value then compares the resulting types. This ensures that both the
// pre-pended and appended lists of bools are the same.
template <bool...>
struct BoolPack;

template <bool... bs>
using AllTrue = std::is_same<BoolPack<true, bs...>, BoolPack<bs..., true>>;

template <typename T>
struct IsPointerOrInt {
  static constexpr bool value = std::is_pointer<T>::value ||
                                std::is_integral<T>::value ||
                                std::is_null_pointer<T>::value;
};

template <typename... Ts>
using AllPointerOrInt = AllTrue<IsPointerOrInt<Ts>::value...>;

}  // namespace internal

// Ensures that the host call library is initialized, then dispatches the
// syscall to enc_untrusted_syscall.
template <typename... Ts>
int64_t EnsureInitializedAndDispatchSyscall(
    typename std::enable_if<internal::AllPointerOrInt<Ts...>::value, int>::type
        sysno,
    Ts... args) {
  if (!enc_is_syscall_dispatcher_set()) {
    enc_set_dispatch_syscall(asylo::host_call::SystemCallDispatcher);
  }
  if (!enc_is_error_handler_set()) {
    enc_set_error_handler(
        asylo::primitives::TrustedPrimitives::BestEffortAbort);
  }
  return enc_untrusted_syscall(sysno, args...);
}

// Verifies the return status of the host call and checks if the expected number
// of parameters are received on the MessageReader.
void CheckStatusAndParamCount(const asylo::primitives::PrimitiveStatus &status,
                              const asylo::primitives::MessageReader &output,
                              const char *name, int expected_params,
                              bool match_exact_params = true);

#ifdef __cplusplus
extern "C" {
#endif

// Unless otherwise specified, each of the following calls invokes the
// corresponding function on the host.
int enc_untrusted_access(const char *path_name, int mode);
pid_t enc_untrusted_getpid();
pid_t enc_untrusted_getppid();
pid_t enc_untrusted_setsid();
uid_t enc_untrusted_getuid();
gid_t enc_untrusted_getgid();
uid_t enc_untrusted_geteuid();
gid_t enc_untrusted_getegid();
int enc_untrusted_kill(pid_t pid, int sig);
int enc_untrusted_link(const char *oldpath, const char *newpath);
off_t enc_untrusted_lseek(int fd, off_t offset, int whence);
int enc_untrusted_mkdir(const char *pathname, mode_t mode);
int enc_untrusted_open(const char *pathname, int flags, ...);
int enc_untrusted_unlink(const char *pathname);
int enc_untrusted_rename(const char *oldpath, const char *newpath);
ssize_t enc_untrusted_read(int fd, void *buf, size_t count);
ssize_t enc_untrusted_write(int fd, const void *buf, size_t count);
int enc_untrusted_symlink(const char *target, const char *linkpath);
ssize_t enc_untrusted_readlink(const char *pathname, char *buf, size_t bufsiz);
int enc_untrusted_truncate(const char *path, off_t length);
int enc_untrusted_ftruncate(int fd, off_t length);
int enc_untrusted_rmdir(const char *path);
int enc_untrusted_pipe2(int pipefd[2], int flags);
int enc_untrusted_socket(int domain, int type, int protocol);
int enc_untrusted_listen(int sockfd, int backlog);
int enc_untrusted_shutdown(int sockfd, int how);
ssize_t enc_untrusted_send(int sockfd, const void *buf, size_t len, int flags);
int enc_untrusted_fcntl(int fd, int cmd, ... /* arg */);
int enc_untrusted_chown(const char *pathname, uid_t owner, gid_t group);
int enc_untrusted_fchown(int fd, uid_t owner, gid_t group);
int enc_untrusted_setsockopt(int sockfd, int level, int optname,
                             const void *optval, socklen_t optlen);
int enc_untrusted_flock(int fd, int operation);
int enc_untrusted_inotify_init1(int flags);
int enc_untrusted_inotify_add_watch(int fd, const char *pathname,
                                    uint32_t mask);
int enc_untrusted_inotify_rm_watch(int fd, int wd);
mode_t enc_untrusted_umask(mode_t mask);
int enc_untrusted_chmod(const char *path, mode_t mode);
int enc_untrusted_fchmod(int fd, mode_t mode);
int enc_untrusted_sched_yield();
int enc_untrusted_sched_getaffinity(pid_t pid, size_t cpusetsize,
                                    cpu_set_t *mask);
int enc_untrusted_fstat(int fd, struct stat *statbuf);
int enc_untrusted_fstatfs(int fd, struct statfs *statbuf);
int enc_untrusted_lstat(const char *pathname, struct stat *statbuf);
int enc_untrusted_stat(const char *pathname, struct stat *statbuf);
int enc_untrusted_statfs(const char *pathname, struct statfs *statbuf);
ssize_t enc_untrusted_getxattr(const char *path, const char *name, void *value,
                               size_t size);
ssize_t enc_untrusted_lgetxattr(const char *path, const char *name, void *value,
                                size_t size);
ssize_t enc_untrusted_fgetxattr(int fd, const char *name, void *value,
                                size_t size);
int enc_untrusted_setxattr(const char *path, const char *name,
                           const void *value, size_t size, int flags);
int enc_untrusted_lsetxattr(const char *path, const char *name,
                            const void *value, size_t size, int flags);
int enc_untrusted_fsetxattr(int fd, const char *name, const void *value,
                            size_t size, int flags);
ssize_t enc_untrusted_listxattr(const char *path, char *list, size_t size);
ssize_t enc_untrusted_llistxattr(const char *path, char *list, size_t size);
ssize_t enc_untrusted_flistxattr(int fd, char *list, size_t size);
int enc_untrusted_pread64(int fd, void *buf, size_t count, off_t offset);
int enc_untrusted_pwrite64(int fd, const void *buf, size_t count, off_t offset);
int enc_untrusted_wait(int *wstatus);
int enc_untrusted_close(int fd);
int enc_untrusted_nanosleep(const struct timespec *req, struct timespec *rem);
int enc_untrusted_clock_getcpuclockid(pid_t pid, clockid_t *clock_id);
int enc_untrusted_bind(int sockfd, const struct sockaddr *addr,
                       socklen_t addrlen);
int enc_untrusted_connect(int sockfd, const struct sockaddr *addr,
                          socklen_t addrlen);
int enc_untrusted_gettimeofday(struct timeval *tv, struct timezone *tz);
int enc_untrusted_fsync(int fd);
int enc_untrusted_getitimer(int which, struct itimerval *curr_value);
int enc_untrusted_setitimer(int which, const struct itimerval *new_value,
                            struct itimerval *old_value);
clock_t enc_untrusted_times(struct tms *buf);
int enc_untrusted_poll(struct pollfd *fds, nfds_t nfds, int timeout);
int enc_untrusted_epoll_create(int size);
int enc_untrusted_epoll_ctl(int epfd, int op, int fd,
                            struct epoll_event *event);
int enc_untrusted_epoll_wait(int epfd, struct epoll_event *events,
                             int maxevents, int timeout);
int enc_untrusted_utimes(const char *filename, const struct timeval times[2]);
int enc_untrusted_utime(const char *filename, const struct utimbuf *times);
int enc_untrusted_getrusage(int who, struct rusage *usage);
int enc_untrusted_uname(struct utsname *buf);
void enc_untrusted_syslog(int priority, const char *message, int len);
int enc_untrusted_ioctl1(int fd, uint64_t request);

// Calls to library functions delegated to the host are defined below.
int enc_untrusted_clock_gettime(clockid_t clk_id, struct timespec *tp);
int enc_untrusted_isatty(int fd);
int enc_untrusted_usleep(useconds_t usec);
int64_t enc_untrusted_sysconf(int name);
void *enc_untrusted_realloc(void *ptr, size_t size);
uint32_t enc_untrusted_sleep(uint32_t seconds);
ssize_t enc_untrusted_sendmsg(int sockfd, const struct msghdr *msg, int flags);
ssize_t enc_untrusted_recvmsg(int sockfd, struct msghdr *msg, int flags);
int enc_untrusted_getsockname(int sockfd, struct sockaddr *addr,
                              socklen_t *addrlen);
int enc_untrusted_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int enc_untrusted_getpeername(int sockfd, struct sockaddr *addr,
                              socklen_t *addrlen);
ssize_t enc_untrusted_recvfrom(int sockfd, void *buf, size_t len, int flags,
                               struct sockaddr *src_addr, socklen_t *addrlen);
int enc_untrusted_select(int nfds, fd_set *readfds, fd_set *writefds,
                         fd_set *exceptfds, struct timeval *timeout);
int enc_untrusted_raise(int sig);
int enc_untrusted_getsockopt(int sockfd, int level, int optname, void *optval,
                             socklen_t *optlen);
int enc_untrusted_getaddrinfo(const char *node, const char *service,
                              const struct addrinfo *hints,
                              struct addrinfo **res);
int enc_untrusted_inet_pton(int af, const char *src, void *dst);
const char *enc_untrusted_inet_ntop(int af, const void *src, char *dst,
                                    socklen_t size);
int enc_untrusted_sigprocmask(int how, const sigset_t *set, sigset_t *oldset);
unsigned int enc_untrusted_if_nametoindex(const char *ifname);
char *enc_untrusted_if_indextoname(unsigned int ifindex, char *ifname);
int enc_untrusted_getifaddrs(struct ifaddrs **ifap);
pid_t enc_untrusted_wait3(int *status, int options, struct rusage *rusage);
pid_t enc_untrusted_wait4(pid_t pid, int *status, int options,
                          struct rusage *rusage);
pid_t enc_untrusted_waitpid(pid_t pid, int *status, int options);
struct passwd *enc_untrusted_getpwuid(uid_t uid);
void enc_untrusted_hex_dump(const void *buf, size_t nbytes);
void enc_untrusted_openlog(const char *ident, int option, int facility);
int enc_untrusted_inotify_read(int fd, size_t count, char **serialized_events,
                               size_t *serialized_events_len);

// Untrusted futex host calls, where the futex word |*futex| lies in the
// untrusted local memory. Callers must not assume access to the untrusted futex
// word.
int enc_untrusted_sys_futex_wait(int32_t *futex, int32_t expected,
                                 int64_t timeout_microsec);
int enc_untrusted_sys_futex_wake(int32_t *futex, int32_t num);

// Calls that are not delegated to the host or depend on other host calls are
// defined below.
void enc_freeaddrinfo(struct addrinfo *res);
void enc_freeifaddrs(struct ifaddrs *ifa);

// Returns a new, empty wait queue. The queue will reside in untrusted memory.
// The queue will have waiting disabled when it’s created.
int32_t *enc_untrusted_create_wait_queue();

// Destroys the |queue|, and releases all corresponding resources. All threads
// currently waiting will remain asleep indefinitely.
void enc_untrusted_destroy_wait_queue(int32_t *const queue);

// Enqueues the calling thread in the given |queue|, and wakes it up after
// `timeout_microsec` microseconds if it hasn't been woken earlier. Returns
// immediately if the |queue| is not in the enabled state.
void enc_untrusted_thread_wait(int32_t *const queue,
                               uint64_t timeout_microsec = 0);

// Wake |num_threads| threads currently waiting on the |queue|.
void enc_untrusted_notify(int32_t *const queue, int32_t num_threads = 1);

// Disable waiting on the given |queue|.
void enc_untrusted_disable_waiting(int32_t *const queue);

// Enable waiting on the given |queue|.
void enc_untrusted_enable_waiting(int32_t *const queue);

// Set the |queue| state to a specific |value|.
void enc_untrusted_wait_queue_set_value(int32_t *const queue, int32_t value);

// Wait on the |queue|, returning immediately if wait queue state isn't the
// given value.
void enc_untrusted_thread_wait_value(int32_t *const queue, int32_t value,
                                     uint64_t timeout_microsec = 0);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // ASYLO_PLATFORM_HOST_CALL_TRUSTED_HOST_CALLS_H_
