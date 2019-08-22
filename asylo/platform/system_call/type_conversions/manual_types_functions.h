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

// Converts an enclave based sockaddr, |*from| to a host based kernel
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

#endif  // ASYLO_PLATFORM_SYSTEM_CALL_TYPE_CONVERSIONS_MANUAL_TYPES_FUNCTIONS_H_
