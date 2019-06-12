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
#include "asylo/platform/primitives/primitive_status.h"
#include "asylo/platform/primitives/trusted_primitives.h"
#include "asylo/platform/primitives/util/trusted_runtime_helper.h"
#include "asylo/util/status_macros.h"

namespace asylo {
namespace primitives {

namespace {

// Size of the enclave heap in bytes, set here to 128 megabytes for rough parity
// with Intel SGX. This is the size of the nominally secure heap considered
// "trusted" for purposes of the simulation.
constexpr size_t kSimulatorHeapSize = 128 * 1024 * 1024;

// A statically initialized record describing the state of the simulator.
struct {
  // The simulator heap is implemented as a block of static storage allocated at
  // enclave load time by dlopen(). Note that the newlib malloc implementation
  // expects sbrk() to return maximally aligned addresses.
  uint8_t heap[kSimulatorHeapSize] __attribute__((aligned(8)));

  // The "program break," defined as the first location after the end of the of
  // the heap.
  uint8_t *brk = heap;
} simulator;

}  // namespace

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

// Registers simulator specific entry handlers.
void RegisterInternalHandlers() {
  // Register the enclave finalization entry handler.
  EntryHandler handler{FinalizeEnclave};
  if (!TrustedPrimitives::RegisterEntryHandler(kSelectorAsyloFini, handler)
             .ok()) {
    TrustedPrimitives::BestEffortAbort("Could not register entry handler");
  }
  // Invoke the user-defined initialization routine.
  if (!asylo_enclave_init().ok()) {
    TrustedPrimitives::BestEffortAbort(
        "asylo_enclave_init() returned failure.");
    return;
  }
}

void TrustedPrimitives::BestEffortAbort(const char *message) {
  MarkEnclaveAborted();
}

void TrustedPrimitives::DebugPuts(const char *message) {
  fputs(message, stderr);
}

PrimitiveStatus TrustedPrimitives::RegisterEntryHandler(
    uint64_t trusted_selector, const EntryHandler &handler) {
  return asylo::primitives::RegisterEntryHandler(trusted_selector, handler);
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
  if (GetSimTrampoline()->magic_number != kTrampolineMagicNumber ||
      GetSimTrampoline()->version != kTrampolineVersion) {
    TrustedPrimitives::BestEffortAbort(
        "Simulator trampoline version or magic number mismatch");
    return PrimitiveStatus::OkStatus();
  }
  return InvokeEntryHandler(selector, params);
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
