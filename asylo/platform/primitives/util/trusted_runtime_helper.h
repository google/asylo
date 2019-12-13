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

#ifndef ASYLO_PLATFORM_PRIMITIVES_UTIL_TRUSTED_RUNTIME_HELPER_H_
#define ASYLO_PLATFORM_PRIMITIVES_UTIL_TRUSTED_RUNTIME_HELPER_H_

#include <cstdio>

#include "asylo/platform/primitives/primitive_status.h"
#include "asylo/platform/primitives/trusted_primitives.h"
#include "asylo/platform/primitives/util/message.h"

// This file declares a trivial trusted runtime interface which can be
// used to implement primitive backends. This interface ships with a default
// implementation and is currently intended to be utilized by the trusted
// runtime implementations for the simulator and SGX backends.

namespace asylo {
namespace primitives {

// Registers backend-specific entry handlers on enclave initialization.
// Implemented by backends utilizing this helper.
void RegisterInternalHandlers();

// Registers a mapping between |trusted_selector| and |handler| in the entry
// table.
PrimitiveStatus RegisterEntryHandler(uint64_t trusted_selector,
                                     const EntryHandler &handler);

// Invokes the enclave entry handler mapped to |selector|. Inputs are provided
// through trusted MessageReader |in|, and outputs are written to trusted
// MessageWriter |out|. Both |in| and |out| are owned by the caller.
PrimitiveStatus InvokeEntryHandler(uint64_t selector, MessageReader *in,
                                   MessageWriter *out);

// Marks enclave intitialized.
void MarkEnclaveInitialized();

// Marks enclave as aborted.
void MarkEnclaveAborted();

// Copies untrusted data to a new trusted buffer, returning a unique_ptr to the
// trusted data. Aborts if input data is found to not be in untrusted memory.
std::unique_ptr<char[]> CopyFromUntrusted(const void *untrusted_data,
                                          size_t size);

// Copies trusted data to untrusted memory, returning raw pointer to the
// untrusted memory. Aborts if input data is found to not be in trusted memory.
// The caller (or untrusted code) is responsible for freeing the untrusted data.
void *CopyToUntrusted(void *trusted_data, size_t size);

}  // namespace primitives
}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_UTIL_TRUSTED_RUNTIME_HELPER_H_
