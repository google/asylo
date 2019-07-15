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

#ifndef ASYLO_PLATFORM_PRIMITIVES_TRUSTED_PRIMITIVES_H_
#define ASYLO_PLATFORM_PRIMITIVES_TRUSTED_PRIMITIVES_H_

#include <cstddef>
#include <cstdint>

#include "asylo/platform/primitives/extent.h"
#include "asylo/platform/primitives/parameter_stack.h"
#include "asylo/platform/primitives/primitive_status.h"
#include "asylo/platform/primitives/primitives.h"
#include "asylo/platform/primitives/util/message.h"
#include "asylo/util/asylo_macros.h"

namespace asylo {
namespace primitives {

// This file declares the primitive API available to trusted application code
// running inside an Asylo enclave. Each Asylo backend is responsible for
// providing an implementation of this interface.

struct EntryHandler;

// Trusted runtime primitive interface.
class TrustedPrimitives {
 public:
  // Aborts the enclave on a best-effort basis. Since it may not be possible to
  // destroy the enclave completely without the cooperation of untrusted code,
  // the implementation should clearly document the behavior of aborting on a
  // particular backend.
  static void BestEffortAbort(const char *message);

  // Writes a message to a stream suitable for debug output. This API is
  // intended for low-level debugging and should:
  //  * Take as few dependencies as possible.
  //  * Make as few assumptions about the runtime as possible.
  //  * Flush as immediately as possible.
  //  * Not assume that the I/O or logging subsystems are usable.
  static void DebugPuts(const char *message);

  // Returns true if a `size` byte value at an address `addr` falls inside the
  // TCB and may not be modified by untrusted code.
  static bool IsTrustedExtent(const void *addr,
                              size_t size) ASYLO_MUST_USE_RESULT;

  // Allocates `size` bytes of untrusted local memory, which must later be freed
  // by calling UntrustedLocalFree or by free call in local untrusted code.
  // Local untrusted memory is addressable by the enclave directly, but its
  // contents is not secure; one must assume that an attacker can read and write
  // it. Note that untrusted local memory is not the same as host memory, and
  // that untrusted local memory is not expected to be addressable from the
  // untrusted application. Even if it is addressable, the application should
  // not use it directly, only local primitives should use it.
  static void *UntrustedLocalAlloc(size_t size) noexcept ASYLO_MUST_USE_RESULT;

  // Calls untrusted local counterpart to free memory allocated by malloc in
  // local untrusted code or by calling UntrustedLocalAlloc.
  static void UntrustedLocalFree(void *ptr) noexcept;

  // Exits the enclave synchronously at an entry point to untrusted code
  // designated by `untrusted_selector`. Inputs and results are passed through
  // |params|. |params| and its extent data can be located in trusted or
  // untrusted memory. If |params| is declared in trusted memory, a new
  // untrusted stack is initialized in untrusted memory, and all the trusted
  // data held by |params| is copied to the untrusted stack before making the
  // ocall. Also in this case, after returning from the ocall, the resulting
  // items on the untrusted stack are copied back to |params|, which now owns
  // the extents, and the untrusted stack and its extents are deallocated. If
  // |params| and its data extents point to untrusted memory, we skip the copy
  // and directly make the ocall using the untrusted |params|.
  static PrimitiveStatus UntrustedCall(
      uint64_t untrusted_selector,
      ParameterStack<TrustedPrimitives::UntrustedLocalAlloc,
                     TrustedPrimitives::UntrustedLocalFree> *params)
      ASYLO_MUST_USE_RESULT;

  // Registers a callback as the handler routine for an enclave entry point
  // trusted_selector. Returns an error code if a handler has already been
  // registered for `trusted_selector` or if an invalid selector value is
  // passed.
  static PrimitiveStatus RegisterEntryHandler(uint64_t trusted_selector,
                                              const EntryHandler &handler)
      ASYLO_MUST_USE_RESULT;
};

// ParameterStack to be used in trusted code.
using TrustedParameterStack =
    ParameterStack<TrustedPrimitives::UntrustedLocalAlloc,
                   TrustedPrimitives::UntrustedLocalFree>;

// Callback structure for dispatching messages passed to the enclave.
struct EntryHandler {
  using Callback = PrimitiveStatus (*)(void *context, MessageReader *in,
                                       MessageWriter *out);

  EntryHandler() : callback(nullptr), context(nullptr) {}

  // Initializes an entry handler with a callback.
  explicit EntryHandler(Callback callback)
      : callback(callback), context(nullptr) {}

  // Initializes an entry handler with a callback and a context pointer.
  EntryHandler(Callback callback, void *context)
      : callback(callback), context(context) {}

  // Returns true if this handler is uninitialized.
  bool IsNull() const { return callback == nullptr; }

  // Callback function to invoke for this entry.
  Callback callback;

  // Uninterpreted data passed by the runtime to invocations of the handler.
  void *context;
};

}  // namespace primitives
}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_TRUSTED_PRIMITIVES_H_
