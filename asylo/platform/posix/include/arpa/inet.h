/*
 *
 * Copyright 2017 Asylo authors
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

#ifndef ASYLO_PLATFORM_POSIX_INCLUDE_ARPA_INET_H_
#define ASYLO_PLATFORM_POSIX_INCLUDE_ARPA_INET_H_

#include <netinet/in.h>
#include <stdint.h>
#include <sys/socket.h>

#ifdef __cplusplus
extern "C" {
#endif

#define INADDR_NONE 0xffffffff

uint32_t htonl(uint32_t hostlong);
uint16_t htons(uint16_t hostshort);
uint32_t ntohl(uint32_t netlong);
uint16_t ntohs(uint16_t netshort);

const char *inet_ntop(int af, const void *src, char *dst, socklen_t size);
int inet_pton(int af, const char *src, void *dst);

int inet_aton(const char *cp, struct in_addr *inp);

// No implementation provided (accepts a larger grammar than inet_pton).
in_addr_t inet_addr(const char *cp);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // ASYLO_PLATFORM_POSIX_INCLUDE_ARPA_INET_H_
