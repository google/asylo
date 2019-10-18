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

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <cstring>
#include <string>

#include "absl/strings/str_cat.h"
#include "asylo/platform/arch/sgx/trusted/generated_bridge_t.h"
#include "asylo/platform/common/memory.h"
#include "asylo/platform/primitives/sgx/sgx_error_space.h"
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

}  // namespace
}  // namespace asylo

extern "C" {

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

}  // extern "C"
