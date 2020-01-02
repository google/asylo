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
#include "asylo/platform/primitives/primitive_status.h"
#include "asylo/platform/primitives/primitives.h"
#include "asylo/platform/primitives/util/message.h"
#include "asylo/util/asylo_macros.h"

namespace asylo {
namespace primitives {

struct EntryHandler;

/// \class TrustedPrimitives trusted_primitives.h @trusted_primitives
/// Trusted runtime primitive interface.
///
/// This class declares the primitive API available to trusted application code
/// running inside an Asylo enclave. Each Asylo backend is responsible for
/// providing an implementation of this interface.
class TrustedPrimitives {
 public:
  /// Aborts the enclave on a best-effort basis. Since it may not be possible to
  /// destroy the enclave completely without the cooperation of untrusted code,
  /// the implementation should clearly document the behavior of aborting on a
  /// particular backend.
  ///
  /// \param message A message for the abort method to print or log.
  ///    May be nullptr.
  static void BestEffortAbort(const char *message);

  /// Writes a message to a stream suitable for debug output. This API is
  /// intended for low-level debugging and should:
  ///
  ///  *   Take as few dependencies as possible.
  ///  *   Make as few assumptions about the runtime as possible.
  ///  *   Flush as immediately as possible.
  ///  *   Not assume that the I/O or logging subsystems are usable.
  ///
  /// \param message The message to output.
  static void DebugPuts(const char *message);

  /// A predicate that decides if a region of memory is internal to the enclave.
  ///
  /// \param addr A pointer to the start of the memory region.
  /// \param size The number of bytes that will be tested for enclave residence.
  /// \returns true if every byte of a `size` byte range at an address `addr`
  ///    falls inside the TCB and may not be modified by untrusted code.
  static bool IsInsideEnclave(const void *addr,
                              size_t size) ASYLO_MUST_USE_RESULT;

  /// A predicate that decides if a region of memory is external to the enclave.
  ///
  /// \param addr A pointer to the start of the memory region.
  /// \param size The number of bytes that will be tested for enclave
  ///    non-residence.
  /// \returns true if every byte of a `size` byte range at an address `addr`
  ///    falls outside the TCB and may be modified by untrusted code.
  static bool IsOutsideEnclave(const void *addr,
                               size_t size) ASYLO_MUST_USE_RESULT;

  /// Allocates `size` bytes of untrusted local memory.
  ///
  /// The allocated memory must later be freed by calling UntrustedLocalFree or
  /// by free call in local untrusted code. Local untrusted memory may not be
  /// addressable by the enclave directly, as this is a backend-specific
  /// assumption. Untrusted memory contents are not secure. One must assume that
  /// an attacker can read and write it. Note that untrusted local memory is not
  /// the same as host memory, and that untrusted local memory is not expected
  /// to be addressable from the untrusted application. If a backend permits
  /// directly addressing untrusted memory, portable applications should not use
  /// that capability. Only local primitives should use direct addressibility.
  ///
  /// \param size The number of bytes to allocate.
  /// \returns A pointer to the allocated memory.
  static void *UntrustedLocalAlloc(size_t size) noexcept ASYLO_MUST_USE_RESULT;

  /// Calls untrusted local counterpart to free memory allocated by malloc in
  /// local untrusted code or by calling UntrustedLocalAlloc.
  ///
  /// \param ptr The pointer to untrusted memory to free.
  static void UntrustedLocalFree(void *ptr) noexcept;

  /// Copies `size` bytes of memory from `src` to `dest`.
  ///
  /// Backends seeking to access or copy untrusted local memory should not
  /// assume direct memory access, and instead use this function to copy to/from
  /// the untrusted local memory.
  ///
  /// \param dest The trusted or untrusted local destination memory.
  /// \param src The trusted or untrusted local source memory.
  /// \param size The number of bytes to be copied.
  /// \return The pointer to destination buffer where memory got copied.
  static void *UntrustedLocalMemcpy(void *dest, const void *src,
                                    size_t size) noexcept;

  /// Exits the enclave synchronously at an entry point to untrusted code
  /// designated by `untrusted_selector`. Inputs must be pushed into `input`.
  /// Results are returned in `output`. All extent data in `input` and `output`
  /// are owned by them and located in trusted memory.
  ///
  /// \param untrusted_selector The identification number to select a registered
  ///    handler in the untrusted space.
  /// \param input A pointer to a MessageWriter, into which all call inputs must
  ///    be pushed.
  /// \param output A pointer to a MessageReader from which to read outputs from
  ///    the call.
  /// \returns A status for the call action, since the call itself may fail.
  static PrimitiveStatus UntrustedCall(
      uint64_t untrusted_selector, MessageWriter *input,
      MessageReader *output) ASYLO_MUST_USE_RESULT;

  /// Registers a callback as the handler routine for an enclave entry point
  /// trusted_selector.
  ///
  /// \param trusted_selector A unique-to-this-enclave identification number
  ///    which will be used to select the given EntryHandler.
  /// \param handler The representation of a callable enclave function.
  /// \returns an error status if a handler has already been registered for
  ///    `trusted_selector` or if an invalid selector value is passed.
  static PrimitiveStatus RegisterEntryHandler(uint64_t trusted_selector,
                                              const EntryHandler &handler)
      ASYLO_MUST_USE_RESULT;

  /// Creates a new thread.
  ///
  /// Depending on the backend, the implementation might or might not need to
  /// exit the enclave for thread creation. The created thread is responsible
  /// for making a callback for querying the thread manager to register itself
  /// and then execute the callback function provided by the thread manager.
  ///
  /// \returns 0 on success.
  static int CreateThread();
};

/// \class EntryHandler trusted_primitives.h @trusted_primitives
/// Callback structure for dispatching messages passed to the enclave.
///
/// Each EntryHandler represents a call to inside the enclave, and will be
/// registered with TrustedPrimitives::RegisterEntryHandler.
struct EntryHandler {
  /// The type of all handler callbacks takes a type-erased context, a
  /// MessageReader from which to consume inputs, and a MessageWriter in which
  /// to write all return values.
  using Callback = PrimitiveStatus (*)(void *context, MessageReader *in,
                                       MessageWriter *out);

  /// Constructs a null handler.
  EntryHandler() : EntryHandler(/*callback=*/nullptr, /*context=*/nullptr) {}

  /// Constructs an entry handler with a callback and null context.
  ///
  /// \param callback The callback this handler uses.
  explicit EntryHandler(Callback callback)
      : EntryHandler(callback, /*context=*/nullptr) {}

  /// Initializes an entry handler with a callback and a context pointer.
  ///
  /// \param callback The callback this handler uses.
  /// \param context A type-erased non-owned pointer that is passed to the
  ///    callback when called. Since an EntryHandler is registered in an
  ///    enclave-global context, the object should live as long as the enclave.
  EntryHandler(Callback callback, void *context)
      : callback(callback), context(context) {}

  /// A predicate for whether the callback is initialized.
  ///
  /// \returns true if this handler is uninitialized.
  bool IsNull() const { return callback == nullptr; }

  /// Implicit bool conversion for null checks.
  operator bool() const { return IsNull(); }

  /// Callback function to invoke for this entry.
  Callback callback;

  /// Uninterpreted data passed by the runtime to invocations of the handler.
  void *context;
};

/// \class UntrustedDeleter trusted_primitives.h @trusted_primitives
/// Deleter for untrusted memory for use with std::unique_ptr. Calls
/// UntrustedLocalFree() internally.
struct UntrustedDeleter {
  inline void operator()(void *ptr) const {
    TrustedPrimitives::UntrustedLocalFree(ptr);
  }
};

/// An alias for unique_ptr that frees data with UntrustedDeleter.
template <typename T>
using UntrustedUniquePtr = std::unique_ptr<T, UntrustedDeleter>;

}  // namespace primitives
}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_TRUSTED_PRIMITIVES_H_
