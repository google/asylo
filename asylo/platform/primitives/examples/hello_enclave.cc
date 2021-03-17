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
#include "asylo/platform/primitives/examples/hello_enclave.h"

#include <string>

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "asylo/platform/primitives/extent.h"
#include "asylo/platform/primitives/primitive_status.h"
#include "asylo/platform/primitives/trusted_primitives.h"
#include "asylo/platform/primitives/util/message.h"
#include "asylo/util/status_macros.h"

using asylo::primitives::EntryHandler;
using asylo::primitives::PrimitiveStatus;
using asylo::primitives::TrustedPrimitives;

namespace asylo {
namespace primitives {

namespace {

// Message handler that aborts the enclave.
PrimitiveStatus Abort(void *context, MessageReader *in, MessageWriter *out) {
  ASYLO_RETURN_IF_READER_NOT_EMPTY(*in);
  TrustedPrimitives::BestEffortAbort("Aborting enclave");
  return PrimitiveStatus::OkStatus();
}

// Message handler that says hello
PrimitiveStatus Hello(void *context, MessageReader *in, MessageWriter *out) {
  ASYLO_RETURN_IF_READER_NOT_EMPTY(*in);

  const char world_str[] = ", World!";

  MessageWriter external_input;
  MessageReader external_output;
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::UntrustedCall(
      kExternalHelloHandler, &external_input, &external_output));
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(external_output, 1);
  auto hello_str = external_output.next();
  std::string hello_world =
      absl::StrCat(reinterpret_cast<const char *>(hello_str.data()), world_str);
  out->PushString(hello_world);
  return PrimitiveStatus::OkStatus();
}

}  // namespace
}  // namespace primitives
}  // namespace asylo

// Implements the required enclave initialization function.
extern "C" PrimitiveStatus asylo_enclave_init() {
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::primitives::kAbortEnclaveSelector,
      EntryHandler{asylo::primitives::Abort}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::primitives::kHelloEnclaveSelector,
      EntryHandler{asylo::primitives::Hello}));
  return PrimitiveStatus::OkStatus();
}

// Implements the required enclave finalization function.
extern "C" PrimitiveStatus asylo_enclave_fini() {
  return PrimitiveStatus::OkStatus();
}
