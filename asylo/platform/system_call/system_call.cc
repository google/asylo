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

#include <array>
#include <cstdarg>
#include <cstdint>
#include <memory>

#include "asylo/platform/system_call/metadata.h"
#include "asylo/platform/system_call/serialize.h"

namespace {

// Deleter object for malloc() allocated buffers.
struct MallocDeleter {
  void operator()(uint8_t *buffer) { free(buffer); }
};

syscall_dispatch_callback global_syscall_callback = nullptr;

}  // namespace

extern "C" void enc_set_dispatch_syscall(syscall_dispatch_callback callback) {
  global_syscall_callback = callback;
}

extern "C" int64_t enc_untrusted_syscall(int sysno, ...) {
  asylo::system_call::SystemCallDescriptor descriptor{sysno};
  if (!descriptor.is_valid()) {
    abort();
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
    abort();
  }

  std::unique_ptr<uint8_t, MallocDeleter> request_owner(request.As<uint8_t>());

  // Invoke the system call dispatch callback to execute the system call.
  uint8_t *response_buffer;
  size_t response_size;

  status = global_syscall_callback(request.As<uint8_t>(), request.size(),
                                   &response_buffer, &response_size);
  if (!status.ok()) {
    abort();
  }

  std::unique_ptr<uint8_t, MallocDeleter> response_owner(response_buffer);

  if (!response_buffer) {
    abort();
  }

  // Copy outputs back into pointer parameters.
  auto response_reader =
      asylo::system_call::MessageReader({response_buffer, response_size});
  for (int i = 0; i < asylo::system_call::kParameterMax; i++) {
    asylo::system_call::ParameterDescriptor parameter = descriptor.parameter(i);
    if (parameter.is_out()) {
      size_t size;
      if (parameter.is_fixed()) {
        size = parameter.size();
      } else {
        size = parameters[parameter.size()];
      }
      const void *src = response_reader.parameter_address(i);
      void *dst = reinterpret_cast<void *>(parameters[i]);
      memcpy(dst, src, size);
    }
  }

  uint64_t result = response_reader.header()->result;
  return result;
}
