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
#include <sys/socket.h>
#include <sys/un.h>

#include "asylo/platform/system_call/type_conversions/generated_types.h"
#include "asylo/platform/system_call/type_conversions/kernel_types.h"

// Converts an enclave based socket type, |*input| to a Linux socket type value.
// Returns -1 if socket type is not recognized.
void TokLinuxSocketType(const int *input, int *output);

// Converts a Linux based socket type |*input| to an enclave based socket type.
// Returns -1 if socket type is not recognized.
void FromkLinuxSocketType(const int *input, int *output);

// Converts an enclave based socket option name, |*input| to a Linux socket
// option. Returns -1 if socket type is not recognized.
void TokLinuxOptionName(const int *level, const int *option_name, int *output);

// Converts a Linux based socket option name, |*input| to an enclave based
// socket option. Returns -1 if socket type is not recognized.
void FromkLinuxOptionName(const int *level, const int *klinux_option_name,
                          int *output);

// Converts a kernel stat to an enclave stat.
void FromkLinuxStat(const struct klinux_stat *input, struct stat *output);

// Converts an enclave stat to a kernel stat.
void TokLinuxStat(const struct stat *input, struct klinux_stat *output);

// Converts an enclave based sockaddr, |*input| to a host based kernel
// sockaddr_un struct. Requires the input sockaddr to have the domain AF_UNIX or
// AF_LOCAL.
void SockaddrTokLinuxSockaddrUn(const struct sockaddr *input,
                                socklen_t input_addrlen,
                                klinux_sockaddr_un *output);

// Converts an enclave based sockaddr, |*input| to a host based kernel
// sockaddr_in struct. Requires the input sockaddr to have the domain AF_INET.
void SockaddrTokLinuxSockaddrIn(const struct sockaddr *input,
                                socklen_t input_addrlen,
                                klinux_sockaddr_in *output);

// Converts an enclave based sockaddr, |*input| to a host based kernel
// sockaddr_in6 struct. Requires the input sockaddr to have the domain AF_INET6.
void SockaddrTokLinuxSockaddrIn6(const struct sockaddr *input,
                                 socklen_t input_addrlen,
                                 klinux_sockaddr_in6 *output);

// Converts a Linux based sockaddr_un to an enclave based sockaddr_un.
void FromkLinuxSockAddrUn(const struct klinux_sockaddr_un *input,
                          struct sockaddr_un *output);

// Converts a Linux based sockaddr_in to an enclave based sockaddr_in.
void FromkLinuxSockAddrIn(const struct klinux_sockaddr_in *input,
                          struct sockaddr_in *output);

// Converts a Linux based sockaddr_in6 to an enclave based sockaddr_in6.
void FromkLinuxSockAddrIn6(const struct klinux_sockaddr_in6 *input,
                           struct sockaddr_in6 *output);

// Converts a Linux based statfs to an enclave based statfs.
void FromkLinuxStatFs(const struct klinux_statfs *input, struct statfs *output);

// Converts an enclave based statfs to a Linux based statfs.
void TokLinuxStatFs(const struct statfs *input, struct klinux_statfs *output);

// Converts a Linux based statfs flag set to an enclave based statfs flag set.
void FromkLinuxStatFsFlags(int64_t input, int64_t *output);

// Converts a enclave based statfs flag set to a Linux based flag set.
void TokLinuxStatFsFlags(int64_t input, int64_t *output);

// Converts a Linux based sockaddr to an enclave based sockaddr. Aborts if an
// unrecognized AF family is encountered. Since this function can be called both
// from the trusted as well as untrusted side, it uses an external handler to
// perform an appropriate abort based on the context.
// |output_len| is used as an input-output argument. As an input, it indicates
// the size of |output| provided by the caller. The returned |*output| is
// truncated if the buffer provided is too small; in this case, |*output_len|
// will return a value greater than was supplied to the call.
void FromkLinuxSockAddr(const struct klinux_sockaddr *input,
                        socklen_t input_len, struct sockaddr *output,
                        socklen_t *output_len,
                        void (*abort_handler)(const char *message));

// Converts a Linux based file descriptor set to a native file descriptor set.
void FromkLinuxFdSet(const struct klinux_fd_set *input, fd_set *output);

// Converts a native file descriptor set to a Linux based file descriptor set.
void TokLinuxFdSet(const fd_set *input, struct klinux_fd_set *output);

// Converts a kernel based signal number (including realtime signals) to an
// enclave based signal.
void FromkLinuxSignalNumber(const int *input, int *output);

// Converts an enclave based signal number (including realtime signals) to a
// kernel based signal.
void TokLinuxSignalNumber(const int *input, int *output);

#endif  // ASYLO_PLATFORM_SYSTEM_CALL_TYPE_CONVERSIONS_MANUAL_TYPES_FUNCTIONS_H_
