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

#include <unistd.h>
#include <cstdio>
#include <cstring>

#include "asylo/platform/primitives/primitives.h"
#include "asylo/platform/primitives/sim/shared_sim.h"
#include "asylo/platform/primitives/trusted_primitives.h"
#include "asylo/platform/primitives/util/primitive_locks.h"
#include "asylo/platform/primitives/x86/spin_lock.h"
#include "asylo/util/error_codes.h"
#include "asylo/util/status_macros.h"

namespace asylo {
namespace primitives {

namespace {

// Maximum number of supported enclave entry points.
static constexpr size_t kEntryPointMax = 4096;

// Size of the enclave heap in bytes, set here to 128 megabytes for rough parity
// with Intel SGX. This is the size of the nominally secure heap considered
// "trusted" for purposes of the simulation.
constexpr size_t kSimulatorHeapSize = 128 * 1024 * 1024;

// Enclave status flag bits.
enum Flag : uint64_t { kInitialized = 0x1, kAborted = 0x2 };

// A statically initialized record describing the state of the simulator.
struct {
  // Lock ensuring thread-safe enclave initialization. Note that this lock must
  // always be acquired *before* flags_write_lock.
  asylo_spinlock_t initialization_lock = ASYLO_SPIN_LOCK_INITIALIZER;

  // Status flag bitmap.
  uint64_t flags = 0;

  // Lock protecting writes to the flags bitmap.
  asylo_spinlock_t flags_write_lock = ASYLO_SPIN_LOCK_INITIALIZER;

  // Table of enclave entry handlers.
  EntryHandler entry_table[kEntryPointMax];

  // Lock protecting entry_table.
  asylo_spinlock_t entry_table_lock = ASYLO_SPIN_LOCK_INITIALIZER;

  // The simulator heap is implemented as a block of static storage allocated at
  // enclave load time by dlopen(). Note that the newlib malloc implementation
  // expects sbrk() to return maximally aligned addresses.
  uint8_t heap[kSimulatorHeapSize] __attribute__((aligned(8)));

  // The "program break," defined as the first location after the end of the of
  // the heap.
  uint8_t *brk = heap;
} simulator;

// Message handler installed by the runtime to finalize the enclave at the time
// it is destroyed.
PrimitiveStatus FinalizeEnclave(void *context, TrustedParameterStack *params) {
  if (!params->empty()) {
    return {error::GoogleError::INVALID_ARGUMENT,
            "FinalizeEnclave does not expect any parameters."};
  }
  PrimitiveStatus status = asylo_enclave_fini();
  memset(&simulator, 0, sizeof(simulator));
  return status;
}

// Placeholder message handler installed for selectors reserved by the runtime.
PrimitiveStatus ReservedEntry(void *context, TrustedParameterStack *params) {
  return {error::GoogleError::INTERNAL, "Invalid call to reserved selector."};
}

// Initialized the enclave if it has not been initialized already.
void EnsureInitialized() {
  if (GetSimTrampoline()->magic_number != kTrampolineMagicNumber ||
      GetSimTrampoline()->version != kTrampolineVersion) {
    TrustedPrimitives::BestEffortAbort(
        "Simulator trampoline version or magic number mismatch");
    return;
  }

  SpinLockGuard lock(&simulator.initialization_lock);
  if (!(simulator.flags & Flag::kInitialized)) {
    // Register the enclave finalization entry handler.
    EntryHandler handler{FinalizeEnclave};
    if (!TrustedPrimitives::RegisterEntryHandler(kSelectorAsyloFini, handler)
             .ok()) {
      TrustedPrimitives::BestEffortAbort("Could not register entry handler");
    }

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

    // Mark this enclave as initialized.
    {
      SpinLockGuard lock(&simulator.flags_write_lock);
      simulator.flags |= Flag::kInitialized;
    }
  }
}

}  // namespace

void TrustedPrimitives::BestEffortAbort(const char *message) {
  SpinLockGuard lock(&simulator.flags_write_lock);
  simulator.flags |= Flag::kAborted;
}

void TrustedPrimitives::DebugPuts(const char *message) {
  fputs(message, stderr);
}

PrimitiveStatus TrustedPrimitives::RegisterEntryHandler(
    uint64_t trusted_selector, const EntryHandler &handler) {
  SpinLockGuard lock(&simulator.entry_table_lock);
  if (trusted_selector >= kEntryPointMax ||
      !simulator.entry_table[trusted_selector].IsNull()) {
    return {error::GoogleError::OUT_OF_RANGE,
            "Invalid selector in RegisterEntryHandler."};
  }

  simulator.entry_table[trusted_selector] = handler;
  return PrimitiveStatus::OkStatus();
}

extern "C" void *enclave_sbrk(intptr_t increment) {
  if (simulator.brk + increment > simulator.heap + kSimulatorHeapSize) {
    return reinterpret_cast<void *>(INT64_C(-1));
  }
  void *result = simulator.brk;
  simulator.brk += increment;
  return result;
}

extern "C" PrimitiveStatus asylo_enclave_call(uint64_t selector,
                                              TrustedParameterStack *params) {
  // Initialize the enclave if necessary.
  EnsureInitialized();

  // Ensure the enclave has not been aborted.
  if (simulator.flags & Flag::kAborted) {
    return {error::GoogleError::ABORTED, "Invalid call to aborted enclave."};
  }

  // Bounds check the passed selector.
  if (selector >= kEntryPointMax || simulator.entry_table[selector].IsNull()) {
    return {error::GoogleError::OUT_OF_RANGE,
            "Invalid selector passed in call to asylo_enclave_call."};
  }

  // Invoke the entry point handler.
  auto &handler = simulator.entry_table[selector];
  return handler.callback(handler.context, params);
}

bool TrustedPrimitives::IsTrustedExtent(const void *addr, size_t size) {
  auto begin = reinterpret_cast<const uint8_t *>(&simulator);
  const uint8_t *end = begin + sizeof(simulator);
  return reinterpret_cast<const uint8_t *>(addr) >= begin &&
         reinterpret_cast<const uint8_t *>(addr) + size < end;
}

void *TrustedPrimitives::UntrustedLocalAlloc(size_t size) {
  return GetSimTrampoline()->asylo_local_alloc_handler(size);
}

void TrustedPrimitives::UntrustedLocalFree(void *ptr) {
  GetSimTrampoline()->asylo_local_free_handler(ptr);
}

PrimitiveStatus TrustedPrimitives::UntrustedCall(
    uint64_t untrusted_selector,
    ParameterStack<TrustedPrimitives::UntrustedLocalAlloc,
                   TrustedPrimitives::UntrustedLocalFree> *params) {
  return GetSimTrampoline()->asylo_exit_call(untrusted_selector, params);
}

}  // namespace primitives
}  // namespace asylo
