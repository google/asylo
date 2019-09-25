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
      int res;                                                               \
      ocall_untrusted_debug_puts(                                            \
          &res,                                                              \
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
      &buffers, static_cast<bridge_size_t>(count),
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

//////////////////////////////////////
//           epoll.h                //
//////////////////////////////////////

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
  asylo::UntrustedUniquePtr<char[]> serialized_events_ptr(
      serialized_event_list);
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

//////////////////////////////////////
//           Debugging              //
//////////////////////////////////////

void enc_untrusted_hex_dump(const void *buf, int nbytes) {
  CHECK_OCALL(ocall_enc_untrusted_hex_dump(buf, nbytes));
}

}  // extern "C"
