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

#include "asylo/platform/primitives/extent.h"
#include "asylo/platform/primitives/primitive_status.h"
#include "asylo/platform/primitives/trusted_primitives.h"
#include "asylo/util/status_macros.h"

namespace asylo {
namespace primitives {

namespace {

// Message handler that aborts the enclave.
PrimitiveStatus Abort(void *context, TrustedParameterStack *params) {
  TrustedPrimitives::BestEffortAbort("Aborting enclave");
  return PrimitiveStatus::OkStatus();
}

// Message handler that says hello
PrimitiveStatus Hello(void *context, TrustedParameterStack *params) {
  char world_str[] = ", World!";
  int world_len = strlen(world_str);

  TrustedParameterStack external_params;
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::UntrustedCall(kExternalHelloHandler,
                                                         &external_params));
  auto hello_extent = external_params.Pop();
  int hello_len = hello_extent->size();
  char *hello_str = hello_extent->As<char>();

  int len = hello_len + world_len + 1;  // add one for null termination
  // Use the parameter stack to allocate memory
  // This memory is visible to Untrusted code
  Extent hello_world = params->PushAlloc(len);
  memcpy(hello_world.As<char>(), hello_str, hello_len);
  memcpy(hello_world.As<char>() + hello_len, world_str, world_len);
  hello_world.As<char>()[len - 1] = '\0';
  return PrimitiveStatus::OkStatus();
}

}  // namespace

extern "C" PrimitiveStatus asylo_enclave_init() {
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      kAbortEnclaveSelector, EntryHandler{Abort}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      kHelloEnclaveSelector, EntryHandler{Hello}));
  return PrimitiveStatus::OkStatus();
}

extern "C" PrimitiveStatus asylo_enclave_fini() {
  return PrimitiveStatus::OkStatus();
}

}  // namespace primitives
}  // namespace asylo
