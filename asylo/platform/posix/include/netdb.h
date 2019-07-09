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

// Values for 'ai_flags' field in 'addrinfo' structure.
#define AI_CANONNAME 0x0002
#define AI_NUMERICHOST 0x0004
#define AI_V4MAPPED 0x0008
#define AI_ADDRCONFIG 0x0010
#define AI_ALL 0x0020
#define AI_PASSIVE 0x0040
#define AI_NUMERICSERV 0x0080
#define AI_IDN 0x0100
#define AI_CANONIDN 0x0200

// Error values for getaddrinfo
#define EAI_BADFLAGS -1       // Invalid value for `ai_flags' field.
#define EAI_NONAME -2         // NAME or SERVICE is unknown.
#define EAI_AGAIN -3          // Temporary failure in name resolution.
#define EAI_FAIL -4           // Non-recoverable failure in name res.
#define EAI_FAMILY -6         // `ai_family' not supported.
#define EAI_SOCKTYPE -7       // `ai_socktype' not supported.
#define EAI_SERVICE -8        // SERVICE not supported for `ai_socktype'.
#define EAI_MEMORY -10        // Memory allocation failure.
#define EAI_SYSTEM -11        // System error returned in `errno'.
#define EAI_OVERFLOW -12      // Argument buffer overflow.
#define EAI_NODATA -5         // No address associated with NAME.
#define EAI_ADDRFAMILY -9     // Address family for NAME not supported.
#define EAI_INPROGRESS -100   // Processing request in progress.
#define EAI_CANCELED -101     // Request canceled.
#define EAI_NOTCANCELED -102  // Request not canceled.
#define EAI_ALLDONE -103      // All requests done.
#define EAI_INTR -104         // Interrupted by a signal.
#define EAI_IDN_ENCODE -105   // IDN encoding failed.

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
extern struct servent *getservbyname(const char *name, const char *proto);
extern struct servent *getservbyport(int port, const char *proto);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // ASYLO_PLATFORM_POSIX_INCLUDE_NETDB_H_
