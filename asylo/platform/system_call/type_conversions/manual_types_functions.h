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

// Converts an enclave based socket type to a Linux socket type value. Returns
// -1 if socket type is not recognized.
int TokLinuxSocketType(int input);

// Converts a Linux based socket type to an enclave based socket type. Returns
// -1 if socket type is not recognized.
int FromkLinuxSocketType(int input);

// Converts an enclave based socket option name to a Linux socket option.
// Returns -1 if socket type is not recognized.
int TokLinuxOptionName(int level, int option_name);

// Converts a Linux based socket option name to an enclave based socket option.
// Returns -1 if socket type is not recognized.
int FromkLinuxOptionName(int level, int klinux_option_name);

// Converts a kernel stat to an enclave stat.
bool FromkLinuxStat(const struct klinux_stat *input, struct stat *output);

// Converts an enclave stat to a kernel stat.
bool TokLinuxStat(const struct stat *input, struct klinux_stat *output);

// Converts an enclave based sockaddr, |*input| to a host based kernel
// sockaddr_un struct. Requires the input sockaddr to have the domain AF_UNIX or
// AF_LOCAL.
bool SockaddrTokLinuxSockaddrUn(const struct sockaddr *input,
                                socklen_t input_addrlen,
                                klinux_sockaddr_un *output);

// Converts an enclave based sockaddr, |*input| to a host based kernel
// sockaddr_in struct. Requires the input sockaddr to have the domain AF_INET.
bool SockaddrTokLinuxSockaddrIn(const struct sockaddr *input,
                                socklen_t input_addrlen,
                                klinux_sockaddr_in *output);

// Converts an enclave based sockaddr, |*input| to a host based kernel
// sockaddr_in6 struct. Requires the input sockaddr to have the domain AF_INET6.
bool SockaddrTokLinuxSockaddrIn6(const struct sockaddr *input,
                                 socklen_t input_addrlen,
                                 klinux_sockaddr_in6 *output);

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
int FromkLinuxSignalNumber(int input);

// Converts an enclave based signal number (including realtime signals) to a
// kernel based signal.
int TokLinuxSignalNumber(int input);

#endif  // ASYLO_PLATFORM_SYSTEM_CALL_TYPE_CONVERSIONS_MANUAL_TYPES_FUNCTIONS_H_
