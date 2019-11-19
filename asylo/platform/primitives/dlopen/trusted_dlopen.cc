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

#include "asylo/platform/primitives/dlopen/shared_dlopen.h"
#include "asylo/platform/primitives/primitive_status.h"
#include "asylo/platform/primitives/primitives.h"
#include "asylo/platform/primitives/trusted_primitives.h"
#include "asylo/platform/primitives/trusted_runtime.h"
#include "asylo/platform/primitives/util/message.h"
#include "asylo/platform/primitives/util/trusted_runtime_helper.h"

namespace asylo {
namespace primitives {

namespace {

// Size of the enclave heap in bytes, set here to 128 megabytes for rough parity
// with Intel SGX. This is the size of the nominally secure heap considered
// "trusted" for purposes of the backend.
constexpr size_t kDlopenHeapSize = 128 * 1024 * 1024;

// A statically initialized record describing the state of the dlopen backend.
struct DlopenState {
  // The backend heap is implemented as a block of static storage allocated at
  // enclave load time by dlopen(). Note that the newlib malloc implementation
  // expects sbrk() to return maximally aligned addresses.
  uint8_t heap[kDlopenHeapSize] __attribute__((aligned(8)));

  // The "program break," defined as the first location after the end of the of
  // the heap.
  uint8_t *brk = heap;

  // Returns the singleton DlopenState instance.
  static DlopenState *GetInstance() {
    static DlopenState instance;
    return &instance;
  }
};

}  // namespace

// Message handler installed by the runtime to finalize the enclave at the time
// it is destroyed.
PrimitiveStatus FinalizeEnclave(void *context, MessageReader *in,
                                MessageWriter *out) {
  ASYLO_RETURN_IF_READER_NOT_EMPTY(*in);
  PrimitiveStatus status = asylo_enclave_fini();
  memset(DlopenState::GetInstance(), 0, sizeof(DlopenState));
  return status;
}

// Registers backend-specific entry handlers.
void RegisterInternalHandlers() {
  // Register the enclave finalization entry handler.
  EntryHandler handler{FinalizeEnclave};
  if (!TrustedPrimitives::RegisterEntryHandler(kSelectorAsyloFini, handler)
           .ok()) {
    TrustedPrimitives::BestEffortAbort("Could not register entry handler");
  }
}

void TrustedPrimitives::BestEffortAbort(const char *message) {
  DebugPuts(message);
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
  if (DlopenState::GetInstance()->brk + increment >
      DlopenState::GetInstance()->heap + kDlopenHeapSize) {
    return reinterpret_cast<void *>(INT64_C(-1));
  }
  void *result = DlopenState::GetInstance()->brk;
  DlopenState::GetInstance()->brk += increment;
  return result;
}

extern "C" PrimitiveStatus asylo_enclave_call(uint64_t selector,
                                              const void *input,
                                              size_t input_len, void **output,
                                              size_t *output_len) {
  if (GetDlopenTrampoline()->magic_number != kTrampolineMagicNumber ||
      GetDlopenTrampoline()->version != kTrampolineVersion) {
    TrustedPrimitives::BestEffortAbort(
        "DlopenState trampoline version or magic number mismatch");
    return PrimitiveStatus::OkStatus();
  }

  if (input) {
    if (!TrustedPrimitives::IsOutsideEnclave(input, input_len)) {
      return {error::GoogleError::INVALID_ARGUMENT,
              "input should lie in untrusted memory"};
    }
    if (input_len > 0) {
      // Copy untrusted |input| to trusted memory and pass that as input.
      void *trusted_input = malloc(input_len);
      memcpy(trusted_input, input, input_len);
      TrustedPrimitives::UntrustedLocalFree(const_cast<void *>(input));
      input = trusted_input;
    } else {
      input = nullptr;
    }
  }

  size_t output_size = 0;
  PrimitiveStatus status = InvokeEntryHandler(
      selector, input, static_cast<size_t>(input_len), output, &output_size);
  *output_len = output_size;

  if (*output) {
    if (!TrustedPrimitives::IsInsideEnclave(*output, output_size)) {
      return {error::GoogleError::INVALID_ARGUMENT,
              "output should lie in trusted memory"};
    }

    // Copy trusted |*output| to untrusted memory and pass that as
    // output. We also free trusted |*output| after it is copied to untrusted
    // side. The untrusted caller is still responsible for freeing |*output|,
    // which now points to untrusted memory.
    void *untrusted_output =
        TrustedPrimitives::UntrustedLocalAlloc(output_size);
    memcpy(untrusted_output, *output, output_size);
    free(*output);
    *output = untrusted_output;
  }

  return status;
}

bool TrustedPrimitives::IsInsideEnclave(const void *addr, size_t size) {
  auto enclave_begin =
      reinterpret_cast<const uint8_t *>(DlopenState::GetInstance());
  const uint8_t *enclave_end = enclave_begin + sizeof(DlopenState);
  auto *from = static_cast<const uint8_t *>(addr);
  auto *to = from + size;
  if (from > to) {
    return false;
  }
  return from >= enclave_begin && to < enclave_end;
}

bool TrustedPrimitives::IsOutsideEnclave(const void *addr, size_t size) {
  auto enclave_begin =
      reinterpret_cast<const uint8_t *>(DlopenState::GetInstance());
  const uint8_t *enclave_end = enclave_begin + sizeof(DlopenState);
  auto *from = static_cast<const uint8_t *>(addr);
  auto *to = from + size;

  // A range wrapping around the address space.
  if (to < from) {
    return to < enclave_begin && from >= enclave_end;
  }

  return (from < enclave_begin && to < enclave_begin) ||
         (from >= enclave_end && to >= enclave_end);
}

void *TrustedPrimitives::UntrustedLocalAlloc(size_t size) noexcept {
  return GetDlopenTrampoline()->asylo_local_alloc_handler(size);
}

void TrustedPrimitives::UntrustedLocalFree(void *ptr) noexcept {
  GetDlopenTrampoline()->asylo_local_free_handler(ptr);
}

PrimitiveStatus TrustedPrimitives::UntrustedCall(uint64_t untrusted_selector,
                                                 MessageWriter *input,
                                                 MessageReader *output) {
  size_t input_size = 0;
  void *input_buffer = nullptr;
  if (input) {
    input_size = input->MessageSize();
    if (input_size > 0) {
      input_buffer = TrustedPrimitives::UntrustedLocalAlloc(input_size);
      input->Serialize(input_buffer);
    }
  }
  size_t output_size = 0;
  void *output_buffer = nullptr;
  auto status = GetDlopenTrampoline()->asylo_exit_call(
      untrusted_selector, input_buffer, input_size, &output_buffer,
      &output_size);
  if (output_buffer) {
    // For the results obtained in |output_buffer|, copy them to |output| before
    // freeing the buffer.
    output->Deserialize(output_buffer, output_size);
    TrustedPrimitives::UntrustedLocalFree(output_buffer);
  }
  return status;
}

int TrustedPrimitives::CreateThread() {
  return 0;
}

// Provide a minimal implementation of enc_get_memory_layout.
extern "C" void enc_get_memory_layout(
    struct EnclaveMemoryLayout *enclave_memory_layout) {
  memset(enclave_memory_layout, 0, sizeof(EnclaveMemoryLayout));
  enclave_memory_layout->base = DlopenState::GetInstance();
  enclave_memory_layout->size = sizeof(DlopenState);
}

}  // namespace primitives
}  // namespace asylo
