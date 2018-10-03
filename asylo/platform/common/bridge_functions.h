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
#include <signal.h>
#include <stdint.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <utime.h>

#include "asylo/platform/common/bridge_types.h"

namespace asylo {

// Converts |bridge_flock_operation| to a runtime flock operation. Returns 0 if
// unsuccessful.
int FromBridgeFLockOperation(int bridge_flock_operation);

// Converts |flock_operation| to bridge flock operation. Returns 0 if no
// supported options are provided.
int ToBridgeFLockOperation(int flock_operation);

// Converts |bridge_sysconf_constant| to a runtime sysconf constant. Returns -1
// if unsuccessful.
int FromBridgeSysconfConstants(enum SysconfConstants bridge_sysconf_constant);

// Converts |sysconf_constant| to a bridge constant. Returns BRIDGE_SC_UNKNOWN
// if unsuccessful.
enum SysconfConstants ToBridgeSysconfConstants(int sysconf_constant);

// Converts |bridge_timer_type| to a runtime timer type. Returns -1 if
// unsuccessful.
int FromBridgeTimerType(enum TimerType bridge_timer_type);

// Converts |timer_type| to a bridge constant. Returns BRIDGE_ITIMER_UNKNOWN if
// unsuccessful.
enum TimerType ToBridgeTimerType(int timer_type);

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

// Converts |bridge_ai_flag| to a runtime file flag. Returns 0 if no supported
// flags are provided.
int FromBridgeAddressInfoFlags(int bridge_ai_flag);

// Converts |ai_flag| to a bridge address info flag. Returns 0 if no supported
// flags are provided.
int ToBridgeAddressInfoFlags(int ai_flag);

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

// Converts |bridge_file_flag| to a runtime file flag.
int FromBridgeFileFlags(int bridge_file_flag);

// Converts |file_flag| to a bridge file flag.
int ToBridgeFileFlags(int file_flag);

// Converts |bridge_fd_flag| to a runtime file flag.
int FromBridgeFDFlags(int bridge_fd_flag);

// Converts |fd_flag| to a bridge FD flag.
int ToBridgeFDFlags(int fd_flag);

// Converts |bridge_option_name| to a runtime option name.
int FromBridgeOptionName(int level, int bridge_option_name);

// Converts |option_name| to a bridge option name.
int ToBridgeOptionName(int level, int option_name);

// Converts |bridge_st| to a runtime stat. Returns nullptr if unsuccessful.
struct stat *FromBridgeStat(const struct bridge_stat *bridge_statbuf,
                            struct stat *statbuf);

// Converts |st| to a bridge stat. Returns nullptr if unsuccessful.
struct bridge_stat *ToBridgeStat(const struct stat *statbuf,
                                 struct bridge_stat *bridge_statbuf);

// Converts |af_family| to a bridge af family. If |af_family| is not supported,
// we return a special value (BRIDGE_AF_UNSUPPORTED) to indicate this.
AfFamily ToBridgeAfFamily(int af_family);

// Converts |bridge_af_family| to a host af family. If this value is not
// supported, we return -1.
int FromBridgeAfFamily(AfFamily bridge_af_family);

// Copies |bridge_addr| to a runtime sockaddr up to sizeof(struct
// bridge_sockaddr). Returns nullptr if unsuccessful.
struct sockaddr *FromBridgeSockaddr(const struct bridge_sockaddr *bridge_addr,
                                    struct sockaddr *addr, socklen_t *addrlen);

// Copies |addr| to a bridge sockaddr up to sizeof(struct bridge_sockaddr).
// Returns nullptr if unsuccessful.
struct bridge_sockaddr *ToBridgeSockaddr(const struct sockaddr *addr,
                                         socklen_t addrlen,
                                         struct bridge_sockaddr *bridge_addr);

// Converts |bridge_times| to a runtime tms.
struct tms *FromBridgeTms(const struct BridgeTms *bridge_times,
                          struct tms *times);

// Converts |times| to a bridge tms.
struct BridgeTms *ToBridgeTms(const struct tms *times,
                              struct BridgeTms *bridge_times);

// Converts |bridge_tp| to a runtime timespec.
struct timespec *FromBridgeTimespec(const struct bridge_timespec *bridge_tp,
                                    struct timespec *tp);

// Converts |tp| to a bridge timespec.
struct bridge_timespec *ToBridgeTimespec(const struct timespec *tp,
                                         struct bridge_timespec *bridge_tp);

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

// Converts |bridge_timerval| to a runtime itimerval.
struct itimerval *FromBridgeITimerVal(
    const struct BridgeITimerVal *bridge_timerval, struct itimerval *timerval);

// Converts |timerval| to a bridge itimerval.
struct BridgeITimerVal *ToBridgeITimerVal(
    const struct itimerval *timerval, struct BridgeITimerVal *bridge_timerval);

// Converts |fd| to a bridge pollfd. Returns nullptr if unsuccessful.
struct pollfd *FromBridgePollfd(const struct bridge_pollfd *bridge_fd,
                                struct pollfd *fd);

// Converts |bridge_fd| to a runtime pollfd. Returns nullptr if unsuccessful.
struct bridge_pollfd *ToBridgePollfd(const struct pollfd *fd,
                                     struct bridge_pollfd *bridge_fd);

// Converts |bridge_msg| to a runtime msghdr. This only does a shallow copy of
// the pointers. A deep copy of the |iovec| array is done in a helper class
// |BridgeMsghdrWrapper| in host_calls. Returns nullptr if unsuccessful.
struct msghdr *FromBridgeMsgHdr(const struct bridge_msghdr *bridge_msg,
                                struct msghdr *msg);

// Converts |msg| to a bridge msghdr. This only does a shallow copy of the
// pointers. A deep copy of the |iovec| array is done in a helper class
// |BridgeMsghdrWrapper| in host_calls. Returns nullptr if unsuccessful.
struct bridge_msghdr *ToBridgeMsgHdr(const struct msghdr *msg,
                                     struct bridge_msghdr *bridge_msg);

// Copies all the iovec buffers from |bridge_msg| to |msg|. This conversion does
// not allocate memory, just copies data to already allocated memory. Returns
// nullptr if unsuccessful.
struct msghdr *FromBridgeIovecArray(const struct bridge_msghdr *bridge_msg,
                                    struct msghdr *msg);

// Copies all the iovec buffers from |msg| to |bridge_msg|. This conversion does
// not allocate memory, just copies data to already allocated memory. Returns
// nullptr is unsuccessful.
struct bridge_msghdr *ToBridgeIovecArray(const struct msghdr *msg,
                                         struct bridge_msghdr *bridge_msg);

// Converts |bridge_iov| to a runtime iovec. Returns nullptr if unsuccessful.
struct iovec *FromBridgeIovec(const struct bridge_iovec *bridge_iov,
                              struct iovec *iov);

// Converts |iov| to a bridge iovec. Returns nullptr if unsuccessful.
struct bridge_iovec *ToBridgeIovec(const struct iovec *iov,
                                   struct bridge_iovec *bridge_iov);

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

// Converts |bridge_fds| to a runtime fd_set. Returns nullptr if unsuccessful.
fd_set *FromBridgeFDSet(const struct BridgeFDSet *bridge_fds, fd_set *fds);

// Converts |fds| to a bridge fd_set. Returns nullptr if unsuccessful.
struct BridgeFDSet *ToBridgeFDSet(const fd_set *fds,
                                  struct BridgeFDSet *bridge_fds);

// These functions follow the standard for the analogous functions in
// http://man7.org/linux/man-pages/man3/CPU_SET.3.html.

void BridgeCpuSetZero(struct BridgeCpuSet *set);

void BridgeCpuSetAddBit(int cpu, struct BridgeCpuSet *set);

int BridgeCpuSetCheckBit(int cpu, struct BridgeCpuSet *set);

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
