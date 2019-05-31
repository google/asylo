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

#include "asylo/platform/host_call/untrusted/host_call_handlers.h"
#include "asylo/platform/primitives/util/status_conversions.h"
#include "asylo/platform/system_call/untrusted_invoke.h"
#include "asylo/util/status_macros.h"

namespace asylo {
namespace host_call {

Status SystemCallHandler(const std::shared_ptr<primitives::Client> &client,
                         void *context,
                         primitives::NativeParameterStack *parameters) {
  if (parameters->empty()) {
    return Status(
        error::GoogleError::FAILED_PRECONDITION,
        "Received no serialized host call request. No syscall to be called!");
  }

  auto request = parameters->Pop();
  if (!parameters->empty()) {
    return Status(
        error::GoogleError::FAILED_PRECONDITION,
        "Received more data (requests) than expected for this host call. This "
        "function is capable of calling only one system call at a time, using "
        "one serialized request. No syscall to be called!");
  }

  primitives::Extent response;  // To be owned by parameters.
  auto response_extent_allocator = [parameters](size_t size) {
    return parameters->PushAlloc(size);
  };

  primitives::PrimitiveStatus status = system_call::UntrustedInvoke(
      *request, &response, response_extent_allocator);

  return primitives::MakeStatus(status);
}

}  // namespace host_call
}  // namespace asylo
