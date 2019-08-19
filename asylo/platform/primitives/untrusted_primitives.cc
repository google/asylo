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

#include "asylo/platform/primitives/untrusted_primitives.h"

#include <cstdint>
#include <memory>
#include <utility>

#include "asylo/platform/primitives/extent.h"
#include "asylo/platform/primitives/primitive_status.h"
#include "asylo/platform/primitives/primitives.h"
#include "asylo/platform/primitives/util/status_conversions.h"
#include "asylo/util/asylo_macros.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace primitives {

thread_local Client *Client::current_client_ = nullptr;

Status Client::EnclaveCall(uint64_t selector, MessageWriter *input,
                           MessageReader *output) {
  if (IsClosed()) {
    return Status{error::GoogleError::FAILED_PRECONDITION,
                  "Cannot make an enclave call to a closed enclave."};
  }
  ScopedCurrentClient scoped_client(this);
  return EnclaveCallInternal(selector, input, output);
}

Status Client::DeliverSignal(MessageWriter *input, MessageReader *output) {
  ScopedCurrentClient scoped_client(this);
  return DeliverSignalInternal(input, output);
}

PrimitiveStatus Client::ExitCallback(uint64_t untrusted_selector,
                                     MessageReader *in, MessageWriter *out) {
  if (!current_client_->exit_call_provider()) {
    return PrimitiveStatus{error::GoogleError::FAILED_PRECONDITION,
                           "Exit call provider not set yet"};
  }
  return MakePrimitiveStatus(
      current_client_->exit_call_provider()->InvokeExitHandler(
          untrusted_selector, in, out, current_client_));
}

}  // namespace primitives
}  // namespace asylo
