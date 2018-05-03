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

#ifndef ASYLO_PLATFORM_SYSTEM_INCLUDE_ARPA_NAMESER_COMPAT_H_
#define ASYLO_PLATFORM_SYSTEM_INCLUDE_ARPA_NAMESER_COMPAT_H_

#define HFIXEDSZ NS_HFIXEDSZ
#define MAXCDNAME NS_MAXCDNAME
#define MAXLABEL NS_MAXLABEL
#define QFIXEDSZ NS_QFIXEDSZ
#define RRFIXEDSZ NS_RRFIXEDSZ

#define QUERY ns_o_query

#define NOERROR ns_r_noerror
#define FORMERR ns_r_formerr
#define NXDOMAIN ns_r_nxdomain
#define NOTIMP ns_r_notimpl
#define REFUSED ns_r_refused
#define SERVFAIL ns_r_servfail

#define T_A ns_t_a
#define T_NS ns_t_ns
#define T_CNAME ns_t_cname
#define T_PTR ns_t_ptr
#define T_MX ns_t_mx
#define T_TXT ns_t_txt
#define T_AAAA ns_t_aaaa

#define C_IN ns_c_in

#define PACKETSZ NS_PACKETSZ
#define NAMESERVER_PORT NS_DEFAULTPORT
#define INDIR_MASK NS_CMPRSFLGS

#endif  // ASYLO_PLATFORM_SYSTEM_INCLUDE_ARPA_NAMESER_COMPAT_H_
