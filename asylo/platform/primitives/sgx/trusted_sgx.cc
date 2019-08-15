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

#include "asylo/platform/primitives/sgx/trusted_sgx.h"

#include <errno.h>

#include <vector>

#include "absl/strings/str_cat.h"
#include "asylo/util/logging.h"
#include "asylo/platform/arch/sgx/trusted/generated_bridge_t.h"
#include "asylo/platform/primitives/extent.h"
#include "asylo/platform/primitives/primitive_status.h"
#include "asylo/platform/primitives/primitives.h"
#include "asylo/platform/primitives/sgx/sgx_error_space.h"
#include "asylo/platform/primitives/sgx/sgx_params.h"
#include "asylo/platform/primitives/trusted_primitives.h"
#include "asylo/platform/primitives/trusted_runtime.h"
#include "asylo/platform/primitives/util/message.h"
#include "asylo/platform/primitives/util/primitive_locks.h"
#include "asylo/platform/primitives/util/trusted_runtime_helper.h"
#include "asylo/platform/primitives/x86/spin_lock.h"
#include "asylo/util/cleanup.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "include/sgx_trts.h"

extern "C" int enc_untrusted_puts(const char *message);

namespace asylo {
namespace primitives {

namespace {

#define CHECK_OCALL(status_)                                                 \
  do {                                                                       \
    sgx_status_t status##__COUNTER__ = status_;                              \
    if (status##__COUNTER__ != SGX_SUCCESS) {                                \
      TrustedPrimitives::DebugPuts(                                          \
          absl::StrCat(                                                      \
              __FILE__, ":", __LINE__, ": ",                                 \
              asylo::Status(status##__COUNTER__, "ocall failed").ToString()) \
              .c_str());                                                     \
      abort();                                                               \
    }                                                                        \
  } while (0)

}  // namespace

// Handler installed by the runtime to finalize the enclave at the time it is
// destroyed.
PrimitiveStatus FinalizeEnclave(void *context, MessageReader *in,
                                MessageWriter *out) {
  if (in) {
    ASYLO_RETURN_IF_READER_NOT_EMPTY(*in);
  }
  return asylo_enclave_fini();
}

// Registers internal handlers, including entry handlers.
void RegisterInternalHandlers() {
  // Register the enclave finalization entry handler.
  EntryHandler handler{FinalizeEnclave};
  if (!TrustedPrimitives::RegisterEntryHandler(kSelectorAsyloFini, handler)
           .ok()) {
    TrustedPrimitives::BestEffortAbort("Could not register entry handler");
  }
}

void TrustedPrimitives::BestEffortAbort(const char *message) {
  enc_block_ecalls();
  MarkEnclaveAborted();
  abort();
}

PrimitiveStatus TrustedPrimitives::RegisterEntryHandler(
    uint64_t selector, const EntryHandler &handler) {
  return asylo::primitives::RegisterEntryHandler(selector, handler);
}

int asylo_enclave_call(uint64_t selector, void *buffer) {
  SgxParams *const sgx_params = reinterpret_cast<SgxParams *>(buffer);

  const void *input = sgx_params->input;
  size_t input_size = sgx_params->input_size;
  sgx_params->input = nullptr;
  sgx_params->input_size = 0;
  void *output = nullptr;
  size_t output_size = 0;

  if (input) {
    if (TrustedPrimitives::IsTrustedExtent(input, input_size)) {
      PrimitiveStatus status{error::GoogleError::INVALID_ARGUMENT,
                             "input should lie within untrusted memory."};
      return status.error_code();
    }
    if (input_size > 0) {
      // Copy untrusted |input| to trusted memory and pass that as input.
      void *trusted_input = malloc(input_size);
      memcpy(trusted_input, input, input_size);
      TrustedPrimitives::UntrustedLocalFree(const_cast<void *>(input));
      input = trusted_input;
    } else {
      TrustedPrimitives::UntrustedLocalFree(const_cast<void *>(input));
      input = nullptr;
    }
  }

  PrimitiveStatus status =
      InvokeEntryHandler(selector, input, input_size, &output, &output_size);

  if (output) {
    // Copy trusted |*output| to untrusted memory and pass that as
    // output. We also free trusted |*output| after it is copied to untrusted
    // side. The untrusted caller is still responsible for freeing |*output|,
    // which now points to untrusted memory.
    if (!TrustedPrimitives::IsTrustedExtent(output, output_size)) {
      PrimitiveStatus{error::GoogleError::INVALID_ARGUMENT,
                      "output should lie in trusted memory"};
      return status.error_code();
    }

    void *untrusted_output =
        TrustedPrimitives::UntrustedLocalAlloc(output_size);
    memcpy(untrusted_output, output, output_size);
    free(output);
    output = untrusted_output;
  }

  sgx_params->output = output;
  sgx_params->output_size = static_cast<uint64_t>(output_size);
  return status.error_code();
}

// For SGX, UntrustedLocalAlloc uses malloc() on the untrusted host to
// allocate memory.
void *TrustedPrimitives::UntrustedLocalAlloc(size_t size) noexcept {
  void *result;
  CHECK_OCALL(
      ocall_untrusted_local_alloc(&result, static_cast<bridge_size_t>(size)));
  if (result &&
      !sgx_is_outside_enclave(result, static_cast<bridge_size_t>(size))) {
    abort();
  }

  // On error, malloc returns nullptr and sets errno to ENOMEM.
  if (!result) {
    errno = ENOMEM;
    TrustedPrimitives::DebugPuts("UntrustedLocalAlloc on SGX failed.");
  }
  return result;
}

// For SGX, UntrustedLocalFree uses free() on the untrusted host to free the
// memory allocated by UntrustedLocalAlloc.
void TrustedPrimitives::UntrustedLocalFree(void *ptr) noexcept {
  CHECK_OCALL(ocall_untrusted_local_free(ptr));
}

bool TrustedPrimitives::IsTrustedExtent(const void *addr, size_t size) {
  return enc_is_within_enclave(addr, size);
}

void TrustedPrimitives::DebugPuts(const char *message) {
  enc_untrusted_puts(message);
}

PrimitiveStatus TrustedPrimitives::UntrustedCall(uint64_t untrusted_selector,
                                                 MessageWriter *input,
                                                 MessageReader *output) {
  int ret;

  SgxParams *const sgx_params = reinterpret_cast<SgxParams *>(
      TrustedPrimitives::UntrustedLocalAlloc(sizeof(SgxParams)));
  Cleanup clean_up(
      [sgx_params] { TrustedPrimitives::UntrustedLocalFree(sgx_params); });
  sgx_params->input_size = 0;
  sgx_params->input = nullptr;
  if (input) {
    sgx_params->input_size = input->MessageSize();
    if (sgx_params->input_size > 0) {
      sgx_params->input =
          TrustedPrimitives::UntrustedLocalAlloc(sgx_params->input_size);
      // Copy data to |input_buffer|.
      input->Serialize(const_cast<void *>(sgx_params->input));
    }
  }
  sgx_params->output_size = 0;
  sgx_params->output = nullptr;
  CHECK_OCALL(
      ocall_dispatch_untrusted_call(&ret, untrusted_selector, sgx_params));
  if (sgx_params->output) {
    // For the results obtained in |output_buffer|, copy them to |output|
    // before freeing the buffer.
    output->Deserialize(sgx_params->output, sgx_params->output_size);
    TrustedPrimitives::UntrustedLocalFree(sgx_params->output);
  }
  return PrimitiveStatus::OkStatus();
}

}  // namespace primitives
}  // namespace asylo
