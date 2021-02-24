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

#include "asylo/platform/primitives/util/trusted_runtime_helper.h"

#include <unistd.h>

#include <cstdio>
#include <cstring>

#include "absl/status/status.h"
#include "asylo/platform/core/trusted_spin_lock.h"
#include "asylo/platform/primitives/primitive_status.h"
#include "asylo/platform/primitives/primitives.h"
#include "asylo/platform/primitives/trusted_primitives.h"
#include "asylo/platform/primitives/trusted_runtime.h"
#include "asylo/platform/primitives/util/message.h"
#include "asylo/util/lock_guard.h"
#include "asylo/util/status_macros.h"

namespace asylo {
namespace primitives {

namespace {

// Maximum number of supported enclave entry points.
static constexpr size_t kEntryPointMax = 4096;

// Enclave status flag bits.
enum Flag : uint64_t { kInitialized = 0x1, kAborted = 0x2 };

// A statically initialized record describing the state of the enclave.
struct {
  // Lock ensuring thread-safe enclave initialization. Note that this lock must
  // always be acquired *before* flags_write_lock.
  TrustedSpinLock initialization_lock{/*is_recursive=*/true};

  // Status flag bitmap.
  uint64_t flags = 0;

  // Lock protecting writes to the flags bitmap.
  TrustedSpinLock flags_write_lock{/*is_recursive=*/true};

  // Table of enclave entry handlers.
  EntryHandler entry_table[kEntryPointMax];

  // Lock protecting entry_table.
  TrustedSpinLock entry_table_lock{/*is_recursive=*/true};
} enclave_state;

// Updates the state of the enclave.
void UpdateEnclaveState(const Flag &flag) {
  LockGuard lock(&enclave_state.flags_write_lock);
  enclave_state.flags |= flag;
}

PrimitiveStatus ReservedEntry(void *context, MessageReader *in,
                              MessageWriter *out) {
  return {primitives::AbslStatusCode::kInternal,
          "Invalid call to reserved selector."};
}

// Initializes the enclave if it has not been initialized already.
void EnsureInitialized() {
  LockGuard lock(&enclave_state.initialization_lock);
  if (!(enclave_state.flags & Flag::kInitialized)) {
    // Register placeholder handlers for reserved entry points.
    for (uint64_t i = kSelectorAsyloFini + 1; i < kSelectorUser; i++) {
      EntryHandler handler{ReservedEntry};
      if (!TrustedPrimitives::RegisterEntryHandler(i, handler).ok()) {
        TrustedPrimitives::BestEffortAbort("Could not register entry handler");
      }
    }

    // Invoke the user-defined initialization routine.
    if (!asylo_enclave_init().ok()) {
      TrustedPrimitives::BestEffortAbort(
          "asylo_enclave_init() returned failure.");
      return;
    }

    // Register runtime handlers. Implemented by backends utilizing this shim.
    RegisterInternalHandlers();

    MarkEnclaveInitialized();
  }
}

}  // namespace

PrimitiveStatus RegisterEntryHandler(uint64_t trusted_selector,
                                     const EntryHandler &handler) {
  LockGuard lock(&enclave_state.entry_table_lock);
  if (trusted_selector >= kEntryPointMax ||
      !enclave_state.entry_table[trusted_selector].IsNull()) {
    return {primitives::AbslStatusCode::kOutOfRange,
            "Invalid selector in RegisterEntryHandler."};
  }

  enclave_state.entry_table[trusted_selector] = handler;
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus InvokeEntryHandler(uint64_t selector, MessageReader *in,
                                   MessageWriter *out) {
  // Initialize the enclave if necessary.
  EnsureInitialized();

  // Ensure the enclave has not been aborted.
  if (enclave_state.flags & Flag::kAborted) {
    return {primitives::AbslStatusCode::kAborted,
            "Invalid call to aborted enclave."};
  }

  // Bounds check the passed selector.
  if (selector >= kEntryPointMax ||
      enclave_state.entry_table[selector].IsNull()) {
    return {primitives::AbslStatusCode::kOutOfRange,
            "Invalid selector passed in call to asylo_enclave_call."};
  }

  // Invoke the entry point handler.
  auto &handler = enclave_state.entry_table[selector];

  ASYLO_RETURN_IF_ERROR(handler.callback(handler.context, in, out));
  return PrimitiveStatus::OkStatus();
}

void MarkEnclaveInitialized() { UpdateEnclaveState(Flag::kInitialized); }

void MarkEnclaveAborted() { UpdateEnclaveState(Flag::kAborted); }

std::unique_ptr<char[]> CopyFromUntrusted(const void *untrusted_data,
                                          size_t size) {
  if (untrusted_data && size > 0) {
    if (!TrustedPrimitives::IsOutsideEnclave(untrusted_data, size)) {
      TrustedPrimitives::BestEffortAbort(
          "Input should lie within untrusted memory.");
    }
    std::unique_ptr<char[]> trusted_input(new char[size]);
    memcpy(trusted_input.get(), untrusted_data, size);
    return trusted_input;
  }
  return nullptr;
}

void *CopyToUntrusted(void *trusted_data, size_t size) {
  if (trusted_data && size > 0) {
    if (!TrustedPrimitives::IsInsideEnclave(trusted_data, size)) {
      TrustedPrimitives::BestEffortAbort(
          "Input should lie within trusted memory.");
    }
    void *untrusted_data = TrustedPrimitives::UntrustedLocalAlloc(size);
    memcpy(untrusted_data, trusted_data, size);
    return untrusted_data;
  }
  return nullptr;
}

}  // namespace primitives
}  // namespace asylo
