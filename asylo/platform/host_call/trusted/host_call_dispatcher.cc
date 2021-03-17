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

#include "asylo/platform/host_call/trusted/host_call_dispatcher.h"

#include "absl/status/status.h"
#include "asylo/platform/host_call/exit_handler_constants.h"
#include "asylo/platform/primitives/extent.h"
#include "asylo/platform/primitives/primitive_status.h"
#include "asylo/platform/primitives/trusted_primitives.h"
#include "asylo/platform/primitives/util/message.h"
#include "asylo/util/status_macros.h"

namespace asylo {
namespace host_call {

primitives::PrimitiveStatus SystemCallDispatcher(const uint8_t* request_buffer,
                                                 size_t request_size,
                                                 uint8_t** response_buffer,
                                                 size_t* response_size) {
  if (request_size == 0 || request_buffer == nullptr) {
    return primitives::PrimitiveStatus{
        primitives::AbslStatusCode::kFailedPrecondition,
        "Zero-sized request or null request provided. Need a valid request to "
        "dispatch the host call."};
  }

  // |request_buffer| is owned by the caller and only accessible inside the
  // enclave; have parameters own the request to make it accessible by the
  // untrusted code.
  primitives::MessageWriter input;
  input.PushByReference(primitives::Extent{request_buffer, request_size});
  primitives::MessageReader output;
  ASYLO_RETURN_IF_ERROR(primitives::TrustedPrimitives::UntrustedCall(
      kSystemCallHandler, &input, &output));

  // The output should only contain the serialized response.
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(output, 1);

  auto response = output.next();
  *response_size = response.size();

  // Copy |response| to *response_buffer before it goes out of scope.
  // *response_buffer is expected to be owned by the caller, so we wouldn't
  // worry about freeing the memory we allocate here.
  *response_buffer = reinterpret_cast<uint8_t*>(malloc(*response_size));
  if (!response_buffer) {
    return primitives::PrimitiveStatus{
        primitives::AbslStatusCode::kResourceExhausted,
        "Failed to malloc response buffer"};
  }
  memcpy(*response_buffer, response.As<uint8_t>(), *response_size);

  return primitives::PrimitiveStatus::OkStatus();
}

primitives::PrimitiveStatus NonSystemCallDispatcher(
    uint64_t exit_selector, primitives::MessageWriter* input,
    primitives::MessageReader* output) {
  if (!input) {
    return primitives::PrimitiveStatus{
        primitives::AbslStatusCode::kFailedPrecondition,
        "NonSystemCallDispatcher: Null input provided. Need a valid request to "
        "dispatch the host call"};
  }

  ASYLO_RETURN_IF_ERROR(primitives::TrustedPrimitives::UntrustedCall(
      exit_selector, input, output));

  // Output should at least contain the host call return value.
  if (output->empty()) {
    return primitives::PrimitiveStatus{
        primitives::AbslStatusCode::kFailedPrecondition,
        "No response received for the host call, or response lost while "
        "crossing the enclave boundary."};
  }

  return primitives::PrimitiveStatus::OkStatus();
}

}  // namespace host_call
}  // namespace asylo
