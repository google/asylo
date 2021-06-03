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

#include "asylo/platform/system_call/system_call.h"

#include <errno.h>

#include <array>
#include <cstdarg>
#include <cstdint>
#include <memory>

#include "asylo/platform/system_call/metadata.h"
#include "asylo/platform/system_call/serialize.h"
#include "asylo/platform/system_call/type_conversions/manual_types_functions.h"
#include "asylo/platform/system_call/type_conversions/types_functions.h"

namespace {

// Deleter object for malloc() allocated buffers.
struct MallocDeleter {
  void operator()(uint8_t *buffer) { free(buffer); }
};

// Default abort handler if none provided.
void default_error_handler(const char *message) { abort(); }

syscall_dispatch_callback global_syscall_callback = nullptr;
void (*error_handler)(const char *message) = nullptr;

}  // namespace

extern "C" bool enc_is_syscall_dispatcher_set() {
  return global_syscall_callback != nullptr;
}

extern "C" bool enc_is_error_handler_set() { return error_handler != nullptr; }

extern "C" void enc_set_dispatch_syscall(syscall_dispatch_callback callback) {
  global_syscall_callback = callback;
}

extern "C" void enc_set_error_handler(
    void (*abort_handler)(const char *message)) {
  error_handler = abort_handler;
}

extern "C" int64_t enc_untrusted_syscall(int sysno, ...) {
  if (!enc_is_error_handler_set()) {
    enc_set_error_handler(default_error_handler);
  }

  asylo::system_call::SystemCallDescriptor descriptor{sysno};
  if (!descriptor.is_valid()) {
    error_handler("system_call.cc: Invalid SystemCallDescriptor encountered.");
  }

  // Collect the passed parameter list into an array.
  std::array<uint64_t, asylo::system_call::kParameterMax> parameters;
  va_list args;
  va_start(args, sysno);
  for (int i = 0; i < descriptor.parameter_count(); i++) {
    parameters[i] = va_arg(args, uint64_t);
  }
  va_end(args);

  // Allocate a buffer for the serialized request.
  asylo::primitives::Extent request;
  asylo::primitives::PrimitiveStatus status;
  status = asylo::system_call::SerializeRequest(sysno, parameters, &request);
  if (!status.ok()) {
    error_handler(
        "system_call.cc: Encountered serialization error when serializing "
        "syscall parameters.");
  }

  std::unique_ptr<uint8_t, MallocDeleter> request_owner(request.As<uint8_t>());

  // Invoke the system call dispatch callback to execute the system call.
  uint8_t *response_buffer;
  size_t response_size;

  if (!enc_is_syscall_dispatcher_set()) {
    error_handler("system_.cc: system call dispatcher not set.");
  }
  status = global_syscall_callback(request.As<uint8_t>(), request.size(),
                                   &response_buffer, &response_size);
  if (!status.ok()) {
    error_handler(
        "system_call.cc: Callback from syscall dispatcher was unsuccessful.");
  }

  std::unique_ptr<uint8_t, MallocDeleter> response_owner(response_buffer);

  if (!response_buffer) {
    error_handler(
        "system_call.cc: null response buffer received for the syscall.");
  }

  // Copy outputs back into pointer parameters.
  auto response_reader =
      asylo::system_call::MessageReader({response_buffer, response_size});
  if (response_reader.sysno() != sysno) {
    error_handler("system_call.cc: Unexpected sysno in response");
  }
  const asylo::primitives::PrimitiveStatus response_status =
      response_reader.Validate();
  if (!response_status.ok()) {
    error_handler(
        "system_call.cc: Error deserializing response buffer into response "
        "reader.");
  }

  for (int i = 0; i < asylo::system_call::kParameterMax; i++) {
    asylo::system_call::ParameterDescriptor parameter = descriptor.parameter(i);
    if (parameter.is_out()) {
      size_t size;
      if (parameter.is_fixed()) {
        size = parameter.size();
      } else {
        size = parameters[parameter.size()] * parameter.element_size();
      }
      const void *src = response_reader.parameter_address(i);
      void *dst = reinterpret_cast<void *>(parameters[i]);
      if (dst != nullptr) {
        memcpy(dst, src, size);
      }
    }
  }

  uint64_t result = response_reader.header()->result;
  if (static_cast<int64_t>(result) == -1) {
    int klinux_errno = response_reader.header()->error_number;

    // Simply having a return value of -1 from a syscall is not a necessary
    // condition that the syscall failed. Some syscalls can return -1 when
    // successful (eg., lseek). The reliable way to check for syscall failure is
    // to therefore check both return value and presence of a non-zero errno.
    if (klinux_errno != 0) {
      errno = FromkLinuxErrno(klinux_errno);
    }
  }
  return result;
}
