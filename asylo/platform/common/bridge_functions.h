/*
 *
 * Copyright 2018 Asylo authors
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

#ifndef ASYLO_PLATFORM_COMMON_BRIDGE_FUNCTIONS_H_
#define ASYLO_PLATFORM_COMMON_BRIDGE_FUNCTIONS_H_

#include <netdb.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pwd.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <utime.h>

#include <csignal>
#include <cstdint>

#include "asylo/platform/common/bridge_types.h"

namespace asylo {

// Converts |bridge_wait_options| to runtime wait options. Returns 0 if no
// supported wait options are provided.
int FromBridgeWaitOptions(int bridge_wait_options);

// Converts |wait_options| to bridge wait options. Returns 0 if no supported
// wait options are provided.
int ToBridgeWaitOptions(int wait_options);

// Converts |bridge_rusage_target| to a runtime rusage target. Returns -1 if
// unsuccessful.
int FromBridgeRUsageTarget(enum RUsageTarget bridge_rusage_target);

// Converts |rusage_target| to a bridge rusage target. Returns
// BRIDGE_RUSAGE_UNKNOWN if unsuccessful.
enum RUsageTarget ToBridgeRUsageTarget(int rusage_target);

// Converts the sigpromask action |bridge_how| to a runtime signal mask action.
// Returns -1 if unsuccessful.
int FromBridgeSigMaskAction(int bridge_how);

// Converts the sigprocmask action |how| to a bridge signal mask action. Returns
// -1 if unsuccessful.
int ToBridgeSigMaskAction(int how);

// Converts |bridge_set| to a runtime signal mask set. Returns nullptr if
// unsuccessful.
sigset_t *FromBridgeSigSet(const bridge_sigset_t *bridge_set, sigset_t *set);

// Converts |set| to a bridge signal mask set. Returns nullptr if unsuccessful.
bridge_sigset_t *ToBridgeSigSet(const sigset_t *set,
                                bridge_sigset_t *bridge_set);

// Converts |bridge_signum| to a runtime signal number. Returns -1 if
// unsuccessful.
int FromBridgeSignal(int bridge_signum);

// Converts |signum| to a bridge signal number. Returns -1 if unsuccessful.
int ToBridgeSignal(int signum);

// Converts |bridge_si_code| to a runtime signal code. Returns -1 if
// unsuccessful.
int FromBridgeSignalCode(int bridge_si_code);

// Converts |si_code| to a bridge signal code. Returns -1 if unsuccessful.
int ToBridgeSignalCode(int si_code);

// Converts |bridge_siginfo| to a runtime siginfo_t. Returns nullptr if
// unsuccessful.
siginfo_t *FromBridgeSigInfo(const struct bridge_siginfo_t *bridge_siginfo,
                             siginfo_t *siginfo);

// Converts |siginfo| to a bridge siginfo_t. Returns nullptr if unsuccessful.
struct bridge_siginfo_t *ToBridgeSigInfo(
    const siginfo_t *siginfo, struct bridge_siginfo_t *bridge_siginfo);

// Converts |bridge_sa_flags| to a runtime sa_flags. Returns 0 if no supported
// flags are provided.
int FromBridgeSignalFlags(int bridge_sa_flags);

// Converts |sa_flags| to a bridge sa_flags. Returns 0 if no supported flags are
// provided.
int ToBridgeSignalFlags(int sa_flags);

// Converts |bridge_syslog_option| to a runtime syslog option. Returns 0 if
// |bridge_syslog_option| does not contain any supported options.
int FromBridgeSysLogOption(int bridge_syslog_option);

// Converts |syslog_option| to a bridge syslog option. Returns 0 if
// |syslog_option| does not contain any supported options.
int ToBridgeSysLogOption(int syslog_option);

// Converts |bridge_syslog_facility| to a runtime syslog facility. Returns 0 if
// |bridge_syslog_facility| does not map to a supported facility.
int FromBridgeSysLogFacility(int bridge_syslog_facility);

// Converts |syslog_facility| to a bridge syslog facility. Returns 0 if
// |syslog_facility| does not map to a supported facility.
int ToBridgeSysLogFacility(int syslog_facility);

// Converts |bridge_syslog_priority| to a runtime syslog priority. Returns 0 if
// |bridge_syslog_priority| does not contain a supported facility or level.
int FromBridgeSysLogPriority(int bridge_syslog_priority);

// Converts |syslog_priority| to a bridge syslog priority. Returns 0 if
// |syslog_priority| does not contain a supported facility or level.
int ToBridgeSysLogPriority(int syslog_priority);

// Converts |af_family| to a bridge af family. Returns BRIDGE_AF_UNSUPPORTED if
// |af_family| is not supported.
AfFamily ToBridgeAfFamily(int af_family);

// Converts |bridge_af_family| to a host af family. Returns -1 if
// |bridge_af_family| is not supported.
int FromBridgeAfFamily(int bridge_af_family);

// Converts |ut| to a runtime timespec.
struct utimbuf *FromBridgeUtimbuf(const struct bridge_utimbuf *bridge_ut,
                                  struct utimbuf *ut);

// Converts |ut| to a bridge timespec.
struct bridge_utimbuf *ToBridgeUtimbuf(const struct utimbuf *ut,
                                       struct bridge_utimbuf *bridge_ut);

// Converts |bridge_tv| to a runtime timeval.
struct timeval *FromBridgeTimeVal(const struct bridge_timeval *bridge_tv,
                                  struct timeval *tv);

// Converts |tv| to a bridge timeval.
struct bridge_timeval *ToBridgeTimeVal(const struct timeval *tv,
                                       struct bridge_timeval *bridge_tv);

// Converts |fd| to a bridge pollfd. Returns nullptr if unsuccessful.
struct pollfd *FromBridgePollfd(const struct bridge_pollfd *bridge_fd,
                                struct pollfd *fd);

// Converts |bridge_fd| to a runtime pollfd. Returns nullptr if unsuccessful.
struct bridge_pollfd *ToBridgePollfd(const struct pollfd *fd,
                                     struct bridge_pollfd *bridge_fd);

// Converts |host_wstatus| to a runtime wstatus.
// This only works when converting into an enclave runtime wstatus, not on host.
int FromBridgeWStatus(struct BridgeWStatus bridge_wstatus);

// Converts |wstatus| to a bridge wstatus.
struct BridgeWStatus ToBridgeWStatus(int wstatus);

// Converts |bridge_rusage| to a runtime rusage. Returns nullptr if
// unsuccessful.
struct rusage *FromBridgeRUsage(const struct BridgeRUsage *bridge_rusage,
                                struct rusage *rusage);

// Converts |rusage| to a bridge rusage. Returns nullptr if unsuccessful.
struct BridgeRUsage *ToBridgeRUsage(const struct rusage *rusage,
                                    struct BridgeRUsage *bridge_rusage);

// Converts |bridge_password| to a runtime passwd. Returns nullptr if
// unsuccessful. This method does not copy and data, just sets the pointers in
// |passwd| to point to the buffers in |bridge_password|.
struct passwd *FromBridgePassWd(struct BridgePassWd *bridge_password,
                                struct passwd *password);

// Converts |password| to a bridge passwd. Returns nullptr if unsuccessful. This
// method copies all buffers from |password| to |bridge_password|.
struct BridgePassWd *ToBridgePassWd(const struct passwd *password,
                                    struct BridgePassWd *bridge_password);

// Copies all the string fields from |source_bridge_passwd| to
// |destination_bridge_password|. This is used to copy the data from untrusted
// side to a global buffer inside the enclave.
struct BridgePassWd *CopyBridgePassWd(
    const struct BridgePassWd *source_bridge_password,
    struct BridgePassWd *destination_bridge_password);

// Copies the C string |source_buf| into |dest_buf|. Only copies up to size-1
// non-null characters. Always terminates the copied string with a null byte on
// a successful write.
//
// Fails if |source_buf| contains more than |size| bytes (including the
// terminating null byte).
bool CStringCopy(const char *source_buf, char *dest_buf, size_t size);

// Copies |source_utsname| into |*dest_utsname|, which may have a different
// type. Both SrcUtsNameType and DstUtsNameType must have public fixed-length
// char array fields called:
//   * sysname
//   * nodename
//   * release
//   * version
//   * machine
//   * domainname
// If SrcUtsNameType has state outside of these fields, it is not copied. If
// DstUtsNameType has state outside of these fields, it is not set.
template <typename SrcUtsNameType, typename DstUtsNameType>
bool ConvertUtsName(const SrcUtsNameType &source_utsname,
                    DstUtsNameType *dest_utsname) {
  if (!dest_utsname) {
    return false;
  }

  return CStringCopy(source_utsname.sysname, dest_utsname->sysname,
                     sizeof(dest_utsname->sysname)) &&
         CStringCopy(source_utsname.nodename, dest_utsname->nodename,
                     sizeof(dest_utsname->nodename)) &&
         CStringCopy(source_utsname.release, dest_utsname->release,
                     sizeof(dest_utsname->release)) &&
         CStringCopy(source_utsname.version, dest_utsname->version,
                     sizeof(dest_utsname->version)) &&
         CStringCopy(source_utsname.machine, dest_utsname->machine,
                     sizeof(dest_utsname->machine)) &&
         CStringCopy(source_utsname.domainname, dest_utsname->domainname,
                     sizeof(dest_utsname->domainname));
}

}  // namespace asylo

#endif  // ASYLO_PLATFORM_COMMON_BRIDGE_FUNCTIONS_H_
