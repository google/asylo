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

#include "asylo/platform/system_call/sysno.h"
#include "asylo/platform/system_call/system_call.h"

// Ensures that the host call library is initialized, then dispatches the
// syscall to enc_untrusted_syscall.
template <class... Ts>
int64_t EnsureInitializedAndDispatchSyscall(int sysno, Ts... args);

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
int enc_untrusted_pread64(int fd, void *buf, size_t count, off_t offset);
int enc_untrusted_pwrite64(int fd, const void *buf, size_t count, off_t offset);
int enc_untrusted_wait(int *wstatus);
int enc_untrusted_close(int fd);
int enc_untrusted_nanosleep(const struct timespec *req, struct timespec *rem);
int enc_untrusted_clock_gettime(clockid_t clk_id, struct timespec *tp);
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
int enc_untrusted_utimes(const char *filename, const struct timeval times[2]);
int enc_untrusted_utime(const char *filename, const struct utimbuf *times);

// Calls to library functions delegated to the host are defined below.
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

// Calls that are not delegated to the host are defined below.
void enc_freeaddrinfo(struct addrinfo *res);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // ASYLO_PLATFORM_HOST_CALL_TRUSTED_HOST_CALLS_H_
