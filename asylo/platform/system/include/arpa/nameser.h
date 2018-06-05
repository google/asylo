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

#ifndef ASYLO_PLATFORM_SYSTEM_INCLUDE_ARPA_NAMESER_H_
#define ASYLO_PLATFORM_SYSTEM_INCLUDE_ARPA_NAMESER_H_

#define NS_HFIXEDSZ 12     // #/bytes of fixed data in header.
#define NS_MAXCDNAME 255   // maximum compressed domain name.
#define NS_MAXLABEL 63     // maximum length of domain label.
#define NS_QFIXEDSZ 4      // #/bytes of fixed data in query.
#define NS_RRFIXEDSZ 10    // #/bytes of fixed data in r record.
#define NS_DEFAULTPORT 53  // For both TCP and UDP.
#define NS_PACKETSZ 512    // default UDP packet size.
#define NS_CMPRSFLGS 0xc0  // Flag bits indicating name compression.
#define NS_INADDRSZ 4      // IPv4 T_A
#define NS_IN6ADDRSZ 16    // IPv6 T_AAAA

// Values for class field.
typedef enum __ns_class {
  ns_c_invalid = 0,  // Cookie.
  ns_c_in = 1,       // Internet.
} ns_class;

// Currently defined type values for resources and queries.
typedef enum __ns_type {
  ns_t_invalid = 0,  // Cookie.
  ns_t_a = 1,        // Host address.
  ns_t_ns = 2,       // Authoritative server.
  ns_t_cname = 5,    // Canonical name.

  ns_t_ptr = 12,  // Domain name pointer.
  ns_t_mx = 15,   // Mail routing information.
  ns_t_txt = 16,  // Text strings.

  ns_t_aaaa = 28,  // Ip6 Address.

  ns_t_max = 65536
} ns_type;

// Currently defined opcodes.
typedef enum __ns_opcode {
  ns_o_query = 0,  // Standard query.
} ns_opcode;

// Currently defined response codes.
typedef enum __ns_rcode {
  ns_r_noerror = 0,   // No error occurred.
  ns_r_formerr = 1,   // Format error.
  ns_r_servfail = 2,  // Server failure.
  ns_r_nxdomain = 3,  // Name error.
  ns_r_notimpl = 4,   // Unimplemented.
  ns_r_refused = 5,   // Operation refused.
} ns_rcode;

#include <arpa/nameser_compat.h>

#endif  // ASYLO_PLATFORM_SYSTEM_INCLUDE_ARPA_NAMESER_H_
