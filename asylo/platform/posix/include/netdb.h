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

#ifndef ASYLO_PLATFORM_POSIX_INCLUDE_NETDB_H_
#define ASYLO_PLATFORM_POSIX_INCLUDE_NETDB_H_

#ifdef __cplusplus
extern "C" {
#endif

/* No implementation provided. */
const char *gai_strerror(int ecode);

#define _NETDB_H 1

#include <netinet/in.h>

/* Values for 'ai_flags' field in 'addrinfo' structure. */
#define AI_CANONNAME 0x0002
#define AI_NUMERICHOST 0x0004

// Description of data base entry for a single host.
struct hostent {
  char *h_name;                // Official name of host.
  char **h_aliases;            // Alias list.
  int h_addrtype;              // Host address type.
  int h_length;                // Length of address.
  char **h_addr_list;          // List of addresses from name server.
#define h_addr h_addr_list[0]  // Address, for backward compatibility.
};

// Description of data base entry for a single service.
struct servent {
  char *s_name;      // Official service name.
  char **s_aliases;  // Alias list.
  int s_port;        // Port number.
  char *s_proto;     // Protocol to use.
};

// No implementation provided
extern struct servent *getservbyport(int port, const char *proto);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // ASYLO_PLATFORM_POSIX_INCLUDE_NETDB_H_
