/*
 *
 * Copyright 2019 Asylo authors
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

#include "asylo/platform/host_call/untrusted/host_call_handlers_util.h"

#include "absl/status/status.h"
#include "asylo/platform/common/futex.h"

namespace asylo {
namespace host_call {

Status SysFutexWaitHelper(primitives::MessageReader *input,
                          primitives::MessageWriter *output) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*input, 3);
  int32_t *futex = input->next<int32_t *>();  // Pop uint64_t value as a pointer
                                              // to address of type in32_t.
  int32_t expected = input->next<int32_t>();
  int64_t timeout_microsec = input->next<int64_t>();
  output->Push<int>(sys_futex_wait(futex, expected, timeout_microsec));
  output->Push<int>(errno);
  return absl::OkStatus();
}

Status SysFutexWakeHelper(primitives::MessageReader *input,
                          primitives::MessageWriter *output) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*input, 2);
  int32_t *futex = input->next<int32_t *>();
  int32_t num = input->next<int32_t>();
  output->Push<int>(sys_futex_wake(futex, num));
  output->Push<int>(errno);
  return absl::OkStatus();
}

}  // namespace host_call
}  // namespace asylo
