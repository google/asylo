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

// If the function invoked on the host sets the value of host errno, the new
// value is propagated back into the enclave. In this case, the value of errno
// in the enclave will reflect the error set by the host. Otherwise, the value
// of enclave errno is not altered.

#include "asylo/platform/arch/include/trusted/host_calls.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <utime.h>

#include <cstring>
#include <string>
#include <vector>

#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "asylo/util/logging.h"
#include "asylo/platform/arch/sgx/trusted/generated_bridge_t.h"
#include "asylo/platform/common/bridge_functions.h"
#include "asylo/platform/common/bridge_proto_serializer.h"
#include "asylo/platform/common/bridge_types.h"
#include "asylo/platform/common/memory.h"
#include "asylo/platform/primitives/sgx/sgx_error_space.h"
#include "asylo/platform/primitives/util/trusted_memory.h"
#include "asylo/util/status.h"
#include "include/sgx_trts.h"

namespace asylo {
namespace {

#define CHECK_OCALL(status_)                                                 \
  do {                                                                       \
    sgx_status_t status##__COUNTER__ = status_;                              \
    if (status##__COUNTER__ != SGX_SUCCESS) {                                \
      enc_untrusted_puts(                                                    \
          absl::StrCat(                                                      \
              __FILE__, ":", __LINE__, ": ",                                 \
              asylo::Status(status##__COUNTER__, "ocall failed").ToString()) \
              .c_str());                                                     \
      abort();                                                               \
    }                                                                        \
  } while (0)

// A global passwd struct. The address of it is used as the return value of
// getpwuid.
struct passwd global_password;

}  // namespace
}  // namespace asylo

extern "C" {

///////////////////////////////////////
//              IO                   //
///////////////////////////////////////

void **enc_untrusted_allocate_buffers(size_t count, size_t size) {
  void **buffers;
  CHECK_OCALL(ocall_enc_untrusted_allocate_buffers(
      &buffers,
      static_cast<bridge_size_t>(count),
      static_cast<bridge_size_t>(size)));
  if (!buffers || !sgx_is_outside_enclave(buffers, size)) {
    abort();
  }
  return buffers;
}

void enc_untrusted_deallocate_free_list(void **free_list, size_t count) {
  CHECK_OCALL(ocall_enc_untrusted_deallocate_free_list(
      free_list, static_cast<bridge_size_t>(count)));
}

int enc_untrusted_puts(const char *str) {
  int result;
  CHECK_OCALL(ocall_enc_untrusted_puts(&result, str));
  return result;
}

//////////////////////////////////////
//             Sockets              //
//////////////////////////////////////

int enc_untrusted_accept(int sockfd, struct sockaddr *addr,
                         socklen_t *addrlen) {
  int ret;
  struct bridge_sockaddr tmp;
  CHECK_OCALL(ocall_enc_untrusted_accept(&ret, sockfd, &tmp));
  if (ret == -1) {
    return ret;
  }
  if (addr != nullptr && addrlen != nullptr) {
    asylo::FromBridgeSockaddr(&tmp, addr, addrlen);
  }
  return ret;
}

const char *enc_untrusted_inet_ntop(int af, const void *src, char *dst,
                                    socklen_t size) {
  char *ret;
  bridge_size_t src_size;
  if (af == AF_INET) {
    src_size = static_cast<bridge_size_t>(sizeof(struct in_addr));
  } else if (af == AF_INET6) {
    src_size = static_cast<bridge_size_t>(sizeof(struct in6_addr));
  } else {
    errno = EAFNOSUPPORT;
    return nullptr;
  }
  CHECK_OCALL(ocall_enc_untrusted_inet_ntop(&ret, af, src, src_size, dst,
                                            static_cast<bridge_size_t>(size)));
  // Instead of returning |ret| (which points to untrusted memory), we return
  // |dst| upon success (when |ret| is non-null) and nullptr upon failure.
  if (!ret) {
    return nullptr;
  }
  return dst;
}

int enc_untrusted_inet_pton(int af, const char *src, void *dst) {
  int ret = 0;
  bridge_size_t dst_size = 0;
  if (af == AF_INET) {
    dst_size = static_cast<bridge_size_t>(sizeof(struct in_addr));
  } else if (af == AF_INET6) {
    dst_size = static_cast<bridge_size_t>(sizeof(struct in6_addr));
  } else {
    errno = EINVAL;
    return -1;
  }
  CHECK_OCALL(ocall_enc_untrusted_inet_pton(&ret, asylo::ToBridgeAfFamily(af),
                                            src, dst, dst_size));
  return ret;
}

int enc_untrusted_getaddrinfo(const char *node, const char *service,
                              const struct addrinfo *hints,
                              struct addrinfo **res) {
  std::string serialized_hints;
  struct addrinfo bridge_hints;
  if (hints) {
    bridge_hints = *hints;
    bridge_hints.ai_flags =
        asylo::ToBridgeAddressInfoFlags(bridge_hints.ai_flags);
  }
  // Some serialization failures may lead to specified behavior. If a value is
  // invalid, some EAI_* error code may need to be returned.
  int bridge_error_code = BRIDGE_EAI_UNKNOWN;
  // Serialize an empty addrinfo if |hints| is nullptr.
  if (!asylo::SerializeAddrinfo(hints ? &bridge_hints : nullptr,
                                &serialized_hints, &bridge_error_code)) {
    if (bridge_error_code == BRIDGE_EAI_UNKNOWN) {
      LOG(ERROR) << "Bad addrinfo";
    }
    return asylo::FromBridgeAddressInfoErrors(bridge_error_code);
  }

  int ret;
  char *tmp_serialized_res_start;
  bridge_size_t tmp_serialized_res_len;
  CHECK_OCALL(ocall_enc_untrusted_getaddrinfo(
      &ret, node, service, serialized_hints.c_str(),
      static_cast<bridge_size_t>(serialized_hints.length()),
      &tmp_serialized_res_start, &tmp_serialized_res_len));
  ret = asylo::FromBridgeAddressInfoErrors(ret);
  if (ret != 0) {
    return ret;
  }
  if (!sgx_is_outside_enclave(tmp_serialized_res_start,
                              static_cast<size_t>(tmp_serialized_res_len))) {
    LOG(ERROR) << "getaddrinfo response pointer not from host address space";
    return -1;
  }

  // Copy then free serialized res from untrusted memory
  std::string serialized_res(tmp_serialized_res_start,
                             tmp_serialized_res_start +
                             static_cast<size_t>(tmp_serialized_res_len));
  CHECK_OCALL(ocall_untrusted_local_free(tmp_serialized_res_start));
  if (!asylo::DeserializeAddrinfo(&serialized_res, res)) {
    LOG(ERROR) << "Invalid addrinfo in getaddrinfo response";
    return -1;
  }
  return ret;
}

void enc_untrusted_freeaddrinfo(struct addrinfo *res) {
  asylo::FreeDeserializedAddrinfo(res);
}

int enc_untrusted_getsockopt(int sockfd, int level, int optname, void *optval,
                             socklen_t *optlen) {
  int ret;
  unsigned int host_optlen = *optlen;
  CHECK_OCALL(ocall_enc_untrusted_getsockopt(
      &ret, sockfd, level, asylo::ToBridgeOptionName(level, optname), optval,
      host_optlen, &host_optlen));
  *optlen = host_optlen;
  return ret;
}

int enc_untrusted_getpeername(int sockfd, struct sockaddr *addr,
                              socklen_t *addrlen) {
  if (!asylo::IsValidEnclaveAddress<struct sockaddr>(addr) ||
      !asylo::IsValidEnclaveAddress<socklen_t>(addrlen)) {
    errno = EFAULT;
    return -1;
  }

  // Guard against -1 being passed as addrlen even though it's unsigned.
  if (*addrlen == 0 || *addrlen > INT32_MAX) {
    errno = EINVAL;
    return -1;
  }
  int ret;
  struct bridge_sockaddr tmp;
  CHECK_OCALL(ocall_enc_untrusted_getpeername(&ret, sockfd, &tmp));
  if (ret == 0) {
    asylo::FromBridgeSockaddr(&tmp, addr, addrlen);
  }
  return ret;
}

ssize_t enc_untrusted_recvfrom(int sockfd, void *buf, size_t len, int flags,
                               struct sockaddr *src_addr, socklen_t *addrlen) {
  ssize_t ret = 0;
  char *serialized_args = nullptr;
  size_t serialized_len = 0;
  if (!asylo::SerializeRecvFromArgs(sockfd, len, flags, &serialized_args,
                                    &serialized_len)) {
    errno = EINVAL;
    return -1;
  }
  asylo::MallocUniquePtr<char[]> args_ptr(serialized_args);
  char *serialized_output = nullptr;
  char **serialized_output_ptr = src_addr ? &serialized_output : nullptr;
  char *output_buf = nullptr;
  bridge_ssize_t output_len = 0;
  CHECK_OCALL(ocall_enc_untrusted_recvfrom(&ret, serialized_args,
                                           serialized_len, &output_buf,
                                           serialized_output_ptr, &output_len));
  asylo::UntrustedUniquePtr<char[]> output_buf_ptr(output_buf);
  if (ret < 0) {
    // errno is propagated.
    return -1;
  }
  if (!sgx_is_outside_enclave(output_buf, ret)) {
    abort();
  }
  memcpy(buf, output_buf, ret);
  if (src_addr) {
    struct sockaddr *src_addr_copy = nullptr;
    asylo::UntrustedUniquePtr<char[]> output_unique_ptr(serialized_output);
    if (!sgx_is_outside_enclave(serialized_output, output_len)) {
      abort();
    }
    std::string serialized_output_str(serialized_output, output_len);
    if (!addrlen || !asylo::DeserializeRecvFromSrcAddr(serialized_output_str,
                                                       &src_addr_copy)) {
      errno = EINVAL;
      return -1;
    }
    asylo::MallocUniquePtr<struct sockaddr> src_addr_ptr(src_addr_copy);
    if (src_addr_copy->sa_family == AF_INET) {
      memcpy(
          src_addr, src_addr_copy,
          std::min(static_cast<size_t>(*addrlen), sizeof(struct sockaddr_in)));
      *addrlen = sizeof(struct sockaddr_in);
    } else if (src_addr_copy->sa_family == AF_INET6) {
      memcpy(
          src_addr, src_addr_copy,
          std::min(static_cast<size_t>(*addrlen), sizeof(struct sockaddr_in6)));
      *addrlen = sizeof(struct sockaddr_in6);
    } else {
      errno = EINVAL;
      return -1;
    }
  }
  return ret;
}

//////////////////////////////////////
//           poll.h                 //
//////////////////////////////////////

int enc_untrusted_poll(struct pollfd *fds, nfds_t nfds, int timeout) {
  int ret;
  auto tmp = absl::make_unique<bridge_pollfd[]>(nfds);
  for (int i = 0; i < nfds; ++i) {
    if (!asylo::ToBridgePollfd(&fds[i], &tmp[i])) {
      errno = EFAULT;
      return -1;
    }
  }
  CHECK_OCALL(ocall_enc_untrusted_poll(&ret, tmp.get(), nfds, timeout));
  for (int i = 0; i < nfds; ++i) {
    if (!asylo::FromBridgePollfd(&tmp[i], &fds[i])) {
      LOG(ERROR) << "Invalid bridge poll fd in poll response";
      errno = EFAULT;
      return -1;
    }
  }
  return ret;
}

//////////////////////////////////////
//           epoll.h                //
//////////////////////////////////////

int enc_untrusted_epoll_create(int size) {
  int ret = 0;
  CHECK_OCALL(ocall_enc_untrusted_epoll_create(&ret, size));
  return ret;
}

int enc_untrusted_epoll_ctl(int epfd, int op, int fd,
                            struct epoll_event *event) {
  char *serialized_args = nullptr;
  asylo::MallocUniquePtr<char[]> args_ptr(serialized_args);
  size_t len = 0;
  if (!asylo::SerializeEpollCtlArgs(epfd, op, fd, event, &serialized_args,
                                    &len)) {
    errno = EINVAL;
    return -1;
  }
  bridge_size_t serialized_args_len = static_cast<bridge_size_t>(len);
  int ret = 0;
  CHECK_OCALL(ocall_enc_untrusted_epoll_ctl(&ret, serialized_args,
                                            serialized_args_len));
  return ret;
}

int enc_untrusted_epoll_wait(int epfd, struct epoll_event *events,
                             int maxevents, int timeout) {
  char *serialized_args = nullptr;
  asylo::MallocUniquePtr<char[]> args_ptr(serialized_args);
  size_t len = 0;
  if (!asylo::SerializeEpollWaitArgs(epfd, maxevents, timeout, &serialized_args,
                                     &len)) {
    errno = EINVAL;
    return -1;
  }

  bridge_size_t serialized_args_len = static_cast<bridge_size_t>(len);
  int ret = 0;
  char *serialized_event_list = nullptr;
  bridge_size_t serialized_event_list_len = 0;
  CHECK_OCALL(ocall_enc_untrusted_epoll_wait(
      &ret, serialized_args, serialized_args_len, &serialized_event_list,
      &serialized_event_list_len));
  if (!sgx_is_outside_enclave(serialized_event_list,
                              serialized_event_list_len)) {
    abort();
  }
  asylo::UntrustedUniquePtr<char[]>
      serialized_events_ptr(serialized_event_list);
  // The line below intentially copies |serialized_event_list| into trusted
  // memory.
  std::string event_list_str(serialized_event_list, serialized_event_list_len);
  int numevents = 0;
  if (!asylo::DeserializeEvents(event_list_str, events, &numevents)) {
    errno = EBADE;
    return -1;
  }
  // Check if the number of events in the deserialized results (|numevents|) is
  // the same as the return value of epoll_wait (|ret|). An inconsistency would
  // suggest malicious behavior, therefore, we would abort().
  if (numevents != ret) {
    abort();
  }
  return ret;
}

//////////////////////////////////////
//           inotify.h              //
//////////////////////////////////////

int enc_untrusted_inotify_read(int fd, size_t count, char **serialized_events,
                               size_t *serialized_events_len) {
  int ret = 0;
  CHECK_OCALL(ocall_enc_untrusted_inotify_read(
      &ret, fd, count, serialized_events, serialized_events_len));
  return ret;
}

//////////////////////////////////////
//           ifaddrs.h              //
//////////////////////////////////////

int enc_untrusted_getifaddrs(struct ifaddrs **ifap) {
  char *serialized_ifaddrs = nullptr;
  bridge_ssize_t serialized_ifaddrs_len = 0;
  int ret = 0;
  CHECK_OCALL(ocall_enc_untrusted_getifaddrs(&ret, &serialized_ifaddrs,
                                             &serialized_ifaddrs_len));
  if (ret != 0) {
    return ret;
  }
  if (!sgx_is_outside_enclave(serialized_ifaddrs,
                              static_cast<size_t>(serialized_ifaddrs_len))) {
    LOG(ERROR) << "serialized_ifaddrs not from host address space";
    return -1;
  }
  asylo::UntrustedUniquePtr<char> ifaddrs_str_ptr(serialized_ifaddrs);
  std::string ifaddrs_str(serialized_ifaddrs, serialized_ifaddrs_len);
  if (!asylo::DeserializeIfAddrs(ifaddrs_str, ifap)) return -1;
  return ret;
}

void enc_untrusted_freeifaddrs(struct ifaddrs *ifa) {
  asylo::FreeDeserializedIfAddrs(ifa);
}

//////////////////////////////////////
//            pwd.h                 //
//////////////////////////////////////

struct passwd *enc_untrusted_getpwuid(uid_t uid) {
  struct BridgePassWd bridge_password;
  int ret = 0;
  CHECK_OCALL(ocall_enc_untrusted_getpwuid(&ret, uid, &bridge_password));
  if (ret != 0) {
    return nullptr;
  }

  // Store the buffers in static storage wrapped in struct BridgePassWd, and
  // direct the pointers in |global_password| to those buffers.
  static struct BridgePassWd password_buffers;

  if (!asylo::CopyBridgePassWd(&bridge_password, &password_buffers) ||
      !asylo::FromBridgePassWd(&password_buffers, &asylo::global_password)) {
    errno = EFAULT;
    return nullptr;
  }

  return &asylo::global_password;
}

//////////////////////////////////////
//           sched.h                //
//////////////////////////////////////

int enc_untrusted_sched_getaffinity(pid_t pid, size_t cpusetsize,
                                    cpu_set_t *mask) {
  if (cpusetsize < sizeof(cpu_set_t)) {
    errno = EINVAL;
    return -1;
  }

  int ret;
  BridgeCpuSet bridge_mask;
  CHECK_OCALL(ocall_enc_untrusted_sched_getaffinity(
      &ret, static_cast<int64_t>(pid), &bridge_mask));

  // Translate from bridge_cpu_set_t to enclave cpu_set_t.
  CPU_ZERO(mask);
  for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
    if (asylo::BridgeCpuSetCheckBit(cpu, &bridge_mask)) {
      CPU_SET(cpu, mask);
    }
  }

  return ret;
}

//////////////////////////////////////
//           signal.h               //
//////////////////////////////////////

int enc_untrusted_register_signal_handler(
    int signum, void (*bridge_sigaction)(int, bridge_siginfo_t *, void *),
    const sigset_t mask, int flags, const char *enclave_name) {
  int bridge_signum = asylo::ToBridgeSignal(signum);
  if (bridge_signum < 0) {
    errno = EINVAL;
    return -1;
  }
  BridgeSignalHandler handler;
  handler.sigaction = bridge_sigaction;
  asylo::ToBridgeSigSet(&mask, &handler.mask);
  handler.flags = asylo::ToBridgeSignalFlags(flags);
  int ret;
  CHECK_OCALL(ocall_enc_untrusted_register_signal_handler(
      &ret, bridge_signum, &handler, enclave_name));
  return ret;
}

int enc_untrusted_sigprocmask(int how, const sigset_t *set, sigset_t *oldset) {
  bridge_sigset_t bridge_set;
  asylo::ToBridgeSigSet(set, &bridge_set);
  bridge_sigset_t bridge_old_set;
  int ret;
  CHECK_OCALL(ocall_enc_untrusted_sigprocmask(
      &ret, asylo::ToBridgeSigMaskAction(how), &bridge_set, &bridge_old_set));
  asylo::FromBridgeSigSet(&bridge_old_set, oldset);
  return ret;
}

int enc_untrusted_raise(int sig) {
  int bridge_sig = asylo::ToBridgeSignal(sig);
  if (bridge_sig < 0) {
    errno = EINVAL;
    return -1;
  }
  int ret;
  CHECK_OCALL(ocall_enc_untrusted_raise(&ret, bridge_sig));
  return ret;
}

//////////////////////////////////////
//         sys/resource.h           //
//////////////////////////////////////

int enc_untrusted_getrusage(int who, struct rusage *usage) {
  int ret;
  BridgeRUsage bridge_usage;
  CHECK_OCALL(ocall_enc_untrusted_getrusage(
      &ret, asylo::ToBridgeRUsageTarget(who), &bridge_usage));
  asylo::FromBridgeRUsage(&bridge_usage, usage);
  return ret;
}

//////////////////////////////////////
//          sys/select.h            //
//////////////////////////////////////

int enc_untrusted_select(int nfds, fd_set *readfds, fd_set *writefds,
                         fd_set *exceptfds, struct timeval *timeout) {
  BridgeFDSet bridge_readfds, bridge_writefds, bridge_exceptfds;
  if (readfds && !asylo::ToBridgeFDSet(readfds, &bridge_readfds)) {
    errno = EBADE;
    return -1;
  }
  if (writefds && !asylo::ToBridgeFDSet(writefds, &bridge_writefds)) {
    errno = EBADE;
    return -1;
  }
  if (exceptfds && !asylo::ToBridgeFDSet(exceptfds, &bridge_exceptfds)) {
    errno = EBADE;
    return -1;
  }
  bridge_timeval bridge_timeout;
  if (!asylo::ToBridgeTimeVal(timeout, &bridge_timeout)) {
    errno = EBADE;
    return -1;
  }
  int ret;
  CHECK_OCALL(ocall_enc_untrusted_select(&ret, nfds, &bridge_readfds,
                                         &bridge_writefds, &bridge_exceptfds,
                                         &bridge_timeout));

  if (readfds && !asylo::FromBridgeFDSet(&bridge_readfds, readfds)) {
    errno = EBADE;
    return -1;
  }
  if (writefds && !asylo::FromBridgeFDSet(&bridge_writefds, writefds)) {
    errno = EBADE;
    return -1;
  }
  if (exceptfds && !asylo::FromBridgeFDSet(&bridge_exceptfds, exceptfds)) {
    errno = EBADE;
    return -1;
  }
  return ret;
}

//////////////////////////////////////
//          sys/syslog.h            //
//////////////////////////////////////

void enc_untrusted_openlog(const char *ident, int option, int facility) {
  CHECK_OCALL(
      ocall_enc_untrusted_openlog(ident, asylo::ToBridgeSysLogOption(option),
                                  asylo::ToBridgeSysLogFacility(facility)));
}

void enc_untrusted_syslog(int priority, const char *message) {
  CHECK_OCALL(ocall_enc_untrusted_syslog(
      asylo::ToBridgeSysLogPriority(priority), message));
}

//////////////////////////////////////
//           time.h                 //
//////////////////////////////////////

int enc_untrusted_times(struct tms *buf) {
  int ret;
  BridgeTms bridge_buf;
  CHECK_OCALL(ocall_enc_untrusted_times(&ret, &bridge_buf));
  if (!asylo::FromBridgeTms(&bridge_buf, buf)) {
    errno = EFAULT;
    return -1;
  }
  return ret;
}

int enc_untrusted_getitimer(int which, struct itimerval *curr_value) {
  int ret;
  struct BridgeITimerVal bridge_curr_value;
  CHECK_OCALL(ocall_enc_untrusted_getitimer(
      &ret, asylo::ToBridgeTimerType(which), &bridge_curr_value));
  if (curr_value == nullptr ||
      !asylo::FromBridgeITimerVal(&bridge_curr_value, curr_value)) {
    errno = EFAULT;
    return -1;
  }
  return ret;
}

int enc_untrusted_setitimer(int which, const struct itimerval *new_value,
                            struct itimerval *old_value) {
  int ret;
  struct BridgeITimerVal bridge_new_value, bridge_old_value;
  if (!asylo::ToBridgeITimerVal(new_value, &bridge_new_value)) {
    errno = EFAULT;
    return -1;
  }
  CHECK_OCALL(
      ocall_enc_untrusted_setitimer(&ret, asylo::ToBridgeTimerType(which),
                                    &bridge_new_value, &bridge_old_value));
  // Set |old_value| if it's not a nullptr.
  if (old_value != nullptr &&
      !asylo::FromBridgeITimerVal(&bridge_old_value, old_value)) {
    errno = EFAULT;
    return -1;
  }
  return ret;
}

//////////////////////////////////////
//           sys/time.h             //
//////////////////////////////////////

int enc_untrusted_gettimeofday(struct timeval *tv, void *tz) {
  int ret;
  CHECK_OCALL(ocall_enc_untrusted_gettimeofday(
      &ret, reinterpret_cast<bridge_timeval *>(tv), nullptr));
  return ret;
}

//////////////////////////////////////
//         sys/utsname.h            //
//////////////////////////////////////

int enc_untrusted_uname(struct utsname *utsname_val) {
  if (!utsname_val) {
    errno = EFAULT;
    return -1;
  }

  struct BridgeUtsName bridge_utsname_val;
  int ret;
  CHECK_OCALL(ocall_enc_untrusted_uname(&ret, &bridge_utsname_val));
  if (ret != 0) {
    return ret;
  }

  if (!asylo::ConvertUtsName(bridge_utsname_val, utsname_val)) {
    LOG(FATAL) << "uname returned an ill-formed utsname";
  }

  return ret;
}

//////////////////////////////////////
//            unistd.h              //
//////////////////////////////////////

void enc_untrusted__exit(int rc) { ocall_enc_untrusted__exit(rc); }

pid_t enc_untrusted_fork(const char *enclave_name, const char *config,
                         size_t config_len, bool restore_snapshot) {
  pid_t ret;
  sgx_status_t status = ocall_enc_untrusted_fork(
      &ret, enclave_name, config, static_cast<bridge_size_t>(config_len),
      restore_snapshot);
  if (status != SGX_SUCCESS) {
    errno = EINTR;
    return -1;
  }
  return ret;
}

//////////////////////////////////////
//             wait.h               //
//////////////////////////////////////

pid_t enc_untrusted_wait3(int *wstatus, int options, struct rusage *usage) {
  pid_t ret;
  struct BridgeWStatus bridge_wstatus;
  BridgeRUsage bridge_usage;
  CHECK_OCALL(ocall_enc_untrusted_wait3(&ret, &bridge_wstatus,
                                        asylo::ToBridgeWaitOptions(options),
                                        &bridge_usage));
  if (wstatus) {
    *wstatus = asylo::FromBridgeWStatus(bridge_wstatus);
  }
  asylo::FromBridgeRUsage(&bridge_usage, usage);
  return ret;
}

pid_t enc_untrusted_waitpid(pid_t pid, int *wstatus, int options) {
  pid_t ret;
  struct BridgeWStatus bridge_wstatus;
  CHECK_OCALL(ocall_enc_untrusted_waitpid(&ret, pid, &bridge_wstatus,
                                          asylo::ToBridgeWaitOptions(options)));
  if (wstatus) {
    *wstatus = asylo::FromBridgeWStatus(bridge_wstatus);
  }
  return ret;
}

//////////////////////////////////////
//           utime.h                //
//////////////////////////////////////

int enc_untrusted_utime(const char *filename, const struct utimbuf *times) {
  int ret;
  struct bridge_utimbuf tmp_bridge_utimbuf;
  CHECK_OCALL(ocall_enc_untrusted_utime(
      &ret, filename, asylo::ToBridgeUtimbuf(times, &tmp_bridge_utimbuf)));
  return ret;
}

int enc_untrusted_utimes(const char *filename, const struct timeval times[2]) {
  int ret;
  bridge_timeval bridge_access_time;
  bridge_timeval bridge_modification_time;
  if (!asylo::ToBridgeTimeVal(&times[0], &bridge_access_time) ||
      !asylo::ToBridgeTimeVal(&times[1], &bridge_modification_time)) {
    errno = EBADE;
    return -1;
  }
  CHECK_OCALL(ocall_enc_untrusted_utimes(&ret, filename, &bridge_access_time,
                                         &bridge_modification_time));
  return ret;
}

//////////////////////////////////////
//           Runtime support        //
//////////////////////////////////////

void *enc_untrusted_acquire_shared_resource(enum SharedNameKind kind,
                                            const char *name) {
  void *ret;
  CHECK_OCALL(ocall_enc_untrusted_acquire_shared_resource(&ret, kind, name));
  return ret;
}

int enc_untrusted_release_shared_resource(enum SharedNameKind kind,
                                          const char *name) {
  int ret;
  CHECK_OCALL(ocall_enc_untrusted_release_shared_resource(&ret, kind, name));
  return ret ? 0 : -1;
}

//////////////////////////////////////
//           Debugging              //
//////////////////////////////////////

void enc_untrusted_hex_dump(const void *buf, int nbytes) {
  CHECK_OCALL(ocall_enc_untrusted_hex_dump(buf, nbytes));
}

}  // extern "C"
