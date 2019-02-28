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

thread_local EnclaveClient *EnclaveClient::current_client_ = nullptr;

Status EnclaveClient::EnclaveCall(uint64_t selector,
                                  UntrustedParameterStack *params) {
  ScopedCurrentClient scoped_client(this);
  return EnclaveCallInternal(selector, params);
}

PrimitiveStatus EnclaveClient::ExitCallback(uint64_t untrusted_selector,
                                            UntrustedParameterStack *params) {
  if (!current_client_->exit_call_provider()) {
    return PrimitiveStatus{error::GoogleError::FAILED_PRECONDITION,
                           "Exit call provider not set yet"};
  }
  return MakePrimitiveStatus(
      current_client_->exit_call_provider()->InvokeExitHandler(
          untrusted_selector, params, current_client_));
}

// External functions below need to be dynamically linked to the loaded enclave
// binary. This is a responsibility of the respective backend loader.
extern "C" PrimitiveStatus asylo_exit_call(uint64_t untrusted_selector,
                                           UntrustedParameterStack *params) {
  return EnclaveClient::ExitCallback(untrusted_selector, params);
}

extern "C" void *asylo_local_alloc_handler(size_t size) { return malloc(size); }

extern "C" void asylo_local_free_handler(void *ptr) { return free(ptr); }

}  // namespace primitives
}  // namespace asylo
