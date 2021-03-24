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

#ifndef ASYLO_PLATFORM_SYSTEM_CALL_TYPE_CONVERSIONS_MANUAL_TYPES_FUNCTIONS_H_
#define ASYLO_PLATFORM_SYSTEM_CALL_TYPE_CONVERSIONS_MANUAL_TYPES_FUNCTIONS_H_

// This file provides the manually written type conversion functions for types
// (enums, structs etc.) between enclave and target host implementation.

#include <netinet/in.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/utsname.h>

#include "absl/types/optional.h"
#include "asylo/platform/system_call/type_conversions/generated_types.h"
#include "asylo/platform/system_call/type_conversions/kernel_types.h"

// Converts a Linux based errno to an enclave based errno. If the error number
// is not known, then this function returns 0x8000 | klinux_errno to facilitate
// ease of debugging when things go wrong.
int FromkLinuxErrno(int klinux_errno);

// Converts an enclave based socket type to a Linux socket type value. Returns
// -1 if socket type is not recognized.
absl::optional<int> TokLinuxSocketType(int input);

// Converts a Linux based socket type to an enclave based socket type. Returns
// -1 if socket type is not recognized.
absl::optional<int> FromkLinuxSocketType(int input);

// Converts an enclave based socket option name to a Linux socket option.
// Returns -1 if socket type is not recognized.
absl::optional<int> TokLinuxOptionName(int level, int option_name);

// Converts a Linux based socket option name to an enclave based socket option.
// Returns -1 if socket type is not recognized.
absl::optional<int> FromkLinuxOptionName(int level, int klinux_option_name);

// Converts a kernel stat to an enclave stat.
bool FromkLinuxStat(const struct klinux_stat *input, struct stat *output);

// Converts an enclave stat to a kernel stat.
bool TokLinuxStat(const struct stat *input, struct klinux_stat *output);

// Converts an enclave based sockaddr, |*input| to a host based kernel
// sockaddr_un struct. Requires the input sockaddr to have the domain AF_UNIX or
// AF_LOCAL.
bool SockaddrTokLinuxSockaddrUn(const struct sockaddr *input,
                                socklen_t input_addrlen,
                                struct klinux_sockaddr_un *output);

// Converts an enclave based sockaddr, |*input| to a host based kernel
// sockaddr_in struct. Requires the input sockaddr to have the domain AF_INET.
bool SockaddrTokLinuxSockaddrIn(const struct sockaddr *input,
                                socklen_t input_addrlen,
                                struct klinux_sockaddr_in *output);

// Converts an enclave based sockaddr, |*input| to a host based kernel
// sockaddr_in6 struct. Requires the input sockaddr to have the domain AF_INET6.
bool SockaddrTokLinuxSockaddrIn6(const struct sockaddr *input,
                                 socklen_t input_addrlen,
                                 struct klinux_sockaddr_in6 *output);

// Converts a Linux based sockaddr_un to an enclave based sockaddr_un.
bool FromkLinuxSockAddrUn(const struct klinux_sockaddr_un *input,
                          struct sockaddr_un *output);

// Converts a Linux based sockaddr_in to an enclave based sockaddr_in.
bool FromkLinuxSockAddrIn(const struct klinux_sockaddr_in *input,
                          struct sockaddr_in *output);

// Converts a Linux based sockaddr_in6 to an enclave based sockaddr_in6.
bool FromkLinuxSockAddrIn6(const struct klinux_sockaddr_in6 *input,
                           struct sockaddr_in6 *output);

// Converts a Linux based statfs to an enclave based statfs.
bool FromkLinuxStatFs(const struct klinux_statfs *input, struct statfs *output);

// Converts an enclave based statfs to a Linux based statfs.
bool TokLinuxStatFs(const struct statfs *input, struct klinux_statfs *output);

// Converts a Linux based statfs flag set to an enclave based statfs flag set.
int64_t FromkLinuxStatFsFlags(int64_t input);

// Converts a enclave based statfs flag set to a Linux based flag set.
int64_t TokLinuxStatFsFlags(int64_t input);

// Converts a Linux based sockaddr to an enclave based sockaddr. Aborts if an
// unrecognized AF family is encountered. Since this function can be called both
// from the trusted as well as untrusted side, it uses an external handler to
// perform an appropriate abort based on the context.
// |output_len| is used as an input-output argument. As an input, it indicates
// the size of |output| provided by the caller. The returned |*output| is
// truncated if the buffer provided is too small; in this case, |*output_len|
// will return a value greater than was supplied to the call.
bool FromkLinuxSockAddr(const struct klinux_sockaddr *input,
                        socklen_t input_len, struct sockaddr *output,
                        socklen_t *output_len,
                        void (*abort_handler)(const char *message));

// Converts an enclave based sockaddr to kernel based sockaddr. Aborts if an
// unrecognized AF family is encountered. Since this function can be called both
// from the trusted as well as untrusted side, it uses an external handler to
// perform an appropriate abort based on the context.
// |output_len| is used as an input-output argument. As an input, it indicates
// the size of |output| provided by the caller. The returned |*output| is
// truncated if the buffer provided is too small; in this case, |*output_len|
// will return a value greater than was supplied to the call.
bool TokLinuxSockAddr(const struct sockaddr *input, socklen_t input_len,
                      struct klinux_sockaddr *output, socklen_t *output_len,
                      void (*abort_handler)(const char *message));

// Converts a Linux based file descriptor set to a native file descriptor set.
bool FromkLinuxFdSet(const struct klinux_fd_set *input, fd_set *output);

// Converts a native file descriptor set to a Linux based file descriptor set.
bool TokLinuxFdSet(const fd_set *input, struct klinux_fd_set *output);

// Converts a kernel based signal number (including realtime signals) to an
// enclave based signal.
absl::optional<int> FromkLinuxSignalNumber(int input);

// Converts an enclave based signal number (including realtime signals) to a
// kernel based signal.
absl::optional<int> TokLinuxSignalNumber(int input);

// Converts a Linux based cpu set bitmask to an enclave based cpu set bitmask.
bool FromkLinuxCpuSet(klinux_cpu_set_t *input, cpu_set_t *output);

// Converts an enclave based itimerval struct to a kernel based itimerval
// struct.
bool TokLinuxItimerval(const struct itimerval *input,
                       struct klinux_itimerval *output);

// Converts a kernel based itimerval struct to an enclave based itimerval
// struct.
bool FromkLinuxItimerval(const struct klinux_itimerval *input,
                         struct itimerval *output);

// Converts an enclave based pollfd struct to a kernel based pollfd struct. Also
// converts the poll events included by pollfd to their klinux poll event
// counterparts.
bool TokLinuxPollfd(const struct pollfd *input, struct klinux_pollfd *output);

// Converts a kernel based pollfd struct to an enclave based pollfd struct. Also
// converts the klinux_ poll events included by kernel pollfd to their enclave
// poll event counterparts.
bool FromkLinuxPollfd(const struct klinux_pollfd *input, struct pollfd *output);

// Converts an enclave based sigset to a kernel based sigset.
bool TokLinuxSigset(const sigset_t *input, klinux_sigset_t *output);

// Converts a kernel based sigset to an enclave based sigset.
bool FromkLinuxSigset(const klinux_sigset_t *input, sigset_t *output);

// Converts an enclave based epoll event to a kernel based epoll event.
bool TokLinuxEpollEvent(const struct epoll_event *input,
                        struct klinux_epoll_event *output);

// Converts a kernel based epoll event to an enclave based epoll event.
bool FromkLinuxEpollEvent(const struct klinux_epoll_event *input,
                          struct epoll_event *output);

// Converts a kernel based rusage to an enclave based rusage.
bool FromkLinuxRusage(const struct klinux_rusage *input, struct rusage *output);

// Converts an enclave based rusage to a kernel based rusage.
bool TokLinuxRusage(const struct rusage *input, struct klinux_rusage *output);

// Converts a kernel based wstatus word to a newlib based wstatus inside the
// enclave.
int FromkLinuxToNewlibWstatus(int input);

// Converts a kernel based utsname struct to an enclave based utsname.
bool FromkLinuxUtsName(const struct klinux_utsname *input,
                       struct utsname *output);

// Converts an enclave based syslog priority value to a kernel based syslog
// priority.
absl::optional<int> TokLinuxSyslogPriority(int input);

// Converts a Linux based siginfo_t struct to an enclave based siginfo struct.
// Only performs conversions on fields of interest currently, i.e. si_signo and
// si_code, keeping others members intact.
bool FromkLinuxSiginfo(const klinux_siginfo_t *input, siginfo_t *output);

#endif  // ASYLO_PLATFORM_SYSTEM_CALL_TYPE_CONVERSIONS_MANUAL_TYPES_FUNCTIONS_H_
