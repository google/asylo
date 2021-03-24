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

#include <errno.h>

#include "asylo/platform/host_call/exit_handler_constants.h"
#include "asylo/platform/host_call/trusted/host_call_dispatcher.h"
#include "asylo/platform/host_call/trusted/host_calls.h"
#include "asylo/platform/primitives/trusted_primitives.h"
#include "asylo/platform/system_call/type_conversions/manual_types_functions.h"
#include "asylo/platform/system_call/type_conversions/types_functions.h"

using ::asylo::host_call::NonSystemCallDispatcher;
using ::asylo::primitives::MessageReader;
using ::asylo::primitives::MessageWriter;
using ::asylo::primitives::TrustedPrimitives;

static constexpr int32_t kWaitQueueEnabled = 0;
static constexpr int32_t kWaitQueueDisabled = 1;

extern "C" {

int enc_untrusted_sys_futex_wait(int32_t *futex, int32_t expected,
                                 int64_t timeout_microsec) {
  if (!TrustedPrimitives::IsOutsideEnclave(futex, sizeof(int32_t))) {
    TrustedPrimitives::BestEffortAbort(
        "enc_untrusted_sys_futex_wait: futex word should be in untrusted "
        "local memory.");
  }

  MessageWriter input;
  MessageReader output;
  input.Push<uint64_t>(reinterpret_cast<uint64_t>(futex));
  input.Push<int32_t>(expected);
  input.Push<int64_t>(timeout_microsec);
  const auto status = NonSystemCallDispatcher(
      ::asylo::host_call::kSysFutexWaitHandler, &input, &output);
  CheckStatusAndParamCount(status, output, "enc_untrusted_sys_futex_wait", 2);
  int result = output.next<int>();
  int klinux_errno = output.next<int>();

  // If FUTEX_WAIT successfully causes the thread to be suspended in the kernel,
  // it returns a zero when the caller is woken up. Otherwise, it returns the
  // appropriate errno.
  if (result != 0) {
    errno = FromkLinuxErrno(klinux_errno);
  }
  return result;
}

int enc_untrusted_sys_futex_wake(int32_t *futex, int32_t num) {
  if (!TrustedPrimitives::IsOutsideEnclave(futex, sizeof(int32_t))) {
    TrustedPrimitives::BestEffortAbort(
        "enc_untrusted_sys_futex_wake: futex word should be in untrusted "
        "local memory.");
  }

  MessageWriter input;
  MessageReader output;
  input.Push<uint64_t>(reinterpret_cast<uint64_t>(futex));
  input.Push<int32_t>(num);
  const auto status = NonSystemCallDispatcher(
      ::asylo::host_call::kSysFutexWakeHandler, &input, &output);
  CheckStatusAndParamCount(status, output, "enc_untrusted_sys_futex_wake", 2);
  int result = output.next<int>();
  int klinux_errno = output.next<int>();
  if (result == -1) {
    errno = FromkLinuxErrno(klinux_errno);
  }
  return result;
}

int32_t *enc_untrusted_create_wait_queue() {
  MessageWriter input;
  MessageReader output;
  input.Push<uint64_t>(sizeof(int32_t));
  const auto status = NonSystemCallDispatcher(
      ::asylo::host_call::kLocalLifetimeAllocHandler, &input, &output);
  CheckStatusAndParamCount(status, output, "enc_untrusted_create_wait_queue",
                           2);
  int32_t *queue = reinterpret_cast<int32_t *>(output.next<uintptr_t>());
  if (!TrustedPrimitives::IsOutsideEnclave(queue, sizeof(int32_t))) {
    TrustedPrimitives::BestEffortAbort(
        "enc_untrusted_create_wait_queue: queue should be in untrusted memory");
  }
  int klinux_errno = output.next<int>();
  if (queue == nullptr) {
    errno = FromkLinuxErrno(klinux_errno);
  }
  enc_untrusted_disable_waiting(queue);
  return queue;
}

void enc_untrusted_destroy_wait_queue(int32_t *const queue) {
  // This is a no op on purpose. Wait queue pointers are now
  // registered to be freed on enclave exit.
}

void enc_untrusted_thread_wait(int32_t *const queue,
                               uint64_t timeout_microsec) {
  enc_untrusted_thread_wait_value(queue, kWaitQueueEnabled, timeout_microsec);
}

void enc_untrusted_notify(int32_t *const queue, int32_t num_threads) {
  enc_untrusted_sys_futex_wake(queue, num_threads);
}

void enc_untrusted_disable_waiting(int32_t *const queue) {
  enc_untrusted_wait_queue_set_value(queue, kWaitQueueDisabled);
}

void enc_untrusted_enable_waiting(int32_t *const queue) {
  enc_untrusted_wait_queue_set_value(queue, kWaitQueueEnabled);
}

void enc_untrusted_wait_queue_set_value(int32_t *const queue, int32_t value) {
  TrustedPrimitives::UntrustedLocalMemcpy(queue, &value, sizeof(int32_t));
}

void enc_untrusted_thread_wait_value(int32_t *const queue, int32_t value,
                                     uint64_t timeout_microsec) {
  enc_untrusted_sys_futex_wait(queue, value, timeout_microsec);
}

}  // extern "C"
