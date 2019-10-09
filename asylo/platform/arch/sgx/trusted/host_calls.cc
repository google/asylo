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
//           Debugging              //
//////////////////////////////////////

void enc_untrusted_hex_dump(const void *buf, int nbytes) {
  CHECK_OCALL(ocall_enc_untrusted_hex_dump(buf, nbytes));
}

}  // extern "C"
