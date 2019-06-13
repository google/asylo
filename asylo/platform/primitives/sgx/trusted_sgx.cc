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

#include <vector>

#include "absl/strings/str_cat.h"
#include "asylo/util/logging.h"
#include "asylo/platform/arch/sgx/trusted/generated_bridge_t.h"
#include "asylo/platform/core/entry_points.h"
#include "asylo/platform/primitives/extent.h"
#include "asylo/platform/primitives/primitive_status.h"
#include "asylo/platform/primitives/primitives.h"
#include "asylo/platform/primitives/sgx/sgx_error_space.h"
#include "asylo/platform/primitives/trusted_primitives.h"
#include "asylo/platform/primitives/trusted_runtime.h"
#include "asylo/platform/primitives/util/primitive_locks.h"
#include "asylo/platform/primitives/util/trusted_runtime_helper.h"
#include "asylo/platform/primitives/x86/spin_lock.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "include/sgx_trts.h"

extern "C" void *enc_untrusted_malloc(size_t size);
extern "C" void enc_untrusted_free(void *ptr);

namespace asylo {
namespace primitives {

namespace {

using UntrustedAllocatorStack =
    ParameterStack<TrustedPrimitives::UntrustedLocalAlloc,
                   TrustedPrimitives::UntrustedLocalFree>;

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

// Validates that the address-range [|address|, |address| +|size|) is fully
// contained outside of the enclave.
PrimitiveStatus VerifyUntrustedAddressRange(void *address, size_t size) {
  if (!enc_is_outside_enclave(address, size)) {
    return PrimitiveStatus(SGX_ERROR_INVALID_PARAMETER,
        "Unexpected reference to resource inside the enclave.");
  }
  return PrimitiveStatus::OkStatus();
}

// Handler installed by the runtime to initialize the enclave.
PrimitiveStatus Initialize(void *context, TrustedParameterStack *params) {
  ASYLO_RETURN_IF_INCORRECT_ARGUMENTS(params, 2);
  TrustedParameterStack::ExtentPtr input_extent = params->Pop();
  TrustedParameterStack::ExtentPtr name_extent = params->Pop();

  void *tmp_input = input_extent->data();
  size_t input_len = input_extent->size();
  ASYLO_RETURN_IF_ERROR(VerifyUntrustedAddressRange(tmp_input, input_len));
  std::unique_ptr<char> input(reinterpret_cast<char *>(malloc(input_len)));
  memcpy(input.get(), tmp_input, input_len);

  void *tmp_name = name_extent->data();
  size_t name_len = name_extent->size();
  ASYLO_RETURN_IF_ERROR(VerifyUntrustedAddressRange(tmp_name, name_len));
  std::unique_ptr<char> name(reinterpret_cast<char *>(malloc(name_len)));
  memcpy(name.get(), tmp_name, name_len);

  char *output = nullptr;
  size_t output_len = 0;
  int result = 0;
  try {
    result = asylo::__asylo_user_init(name.get(), /*config=*/input.get(),
                                      /*config_len=*/input_len, &output,
                                      &output_len);
  } catch (...) {
    TrustedPrimitives::BestEffortAbort("Uncaught exception in enclave");
  }
  if (!result) {
    params->PushByCopy(Extent{output, output_len});
  }
  enc_untrusted_free(output);
  return PrimitiveStatus(result);
}

// Handler installed by the runtime to invoke the enclave run entry point.
PrimitiveStatus Run(void *context, TrustedParameterStack *params) {
  ASYLO_RETURN_IF_INCORRECT_ARGUMENTS(params, 1);
  auto input_extent = params->Pop();
  void *tmp_input = input_extent->data();
  size_t input_len = input_extent->size();
  ASYLO_RETURN_IF_ERROR(VerifyUntrustedAddressRange(tmp_input, input_len));
  std::unique_ptr<char> input(reinterpret_cast<char *>(malloc(input_len)));
  memcpy(input.get(), tmp_input, input_len);

  char *output = nullptr;
  size_t output_len = 0;
  int result = 0;
  try {
    result = asylo::__asylo_user_run(input.get(), input_len, &output,
                                     &output_len);
  } catch (...) {
    TrustedPrimitives::BestEffortAbort("Uncaught exception in enclave");
  }
  if (!result) {
    params->PushByCopy(Extent{output, output_len});
  }
  enc_untrusted_free(output);
  return PrimitiveStatus(result);
}

// Handler installed by the runtime to invoke the enclave finalization entry
// point.
PrimitiveStatus Finalize(void *context, TrustedParameterStack *params) {
  ASYLO_RETURN_IF_INCORRECT_ARGUMENTS(params, 1);
  auto input_extent = params->Pop();
  void *tmp_input = input_extent->data();
  size_t input_len = input_extent->size();
  ASYLO_RETURN_IF_ERROR(VerifyUntrustedAddressRange(tmp_input, input_len));
  std::unique_ptr<char> input(reinterpret_cast<char *>(malloc(input_len)));
  memcpy(input.get(), tmp_input, input_len);

  char *output = nullptr;
  size_t output_len = 0;
  int result = 0;
  try {
    result = asylo::__asylo_user_fini(input.get(), input_len, &output,
                                     &output_len);
  } catch (...) {
    TrustedPrimitives::BestEffortAbort("Uncaught exception in enclave");
  }
  if (!result) {
    params->PushByCopy(Extent{output, output_len});
  }
  enc_untrusted_free(output);
  return PrimitiveStatus(result);
}

// Handler installed by the runtime to invoke the enclave donate thread entry
// point.
PrimitiveStatus DonateThread(void *context, TrustedParameterStack *params) {
  ASYLO_RETURN_IF_INCORRECT_ARGUMENTS(params, 0);
  int result = 0;
  try {
    result = asylo::__asylo_threading_donate();
  } catch (...) {
    TrustedPrimitives::BestEffortAbort("Uncaught exception in enclave");
  }
  return PrimitiveStatus(result);
}

std::unique_ptr<UntrustedAllocatorStack,
                decltype(TrustedPrimitives::UntrustedLocalFree) *>
InitUntrustedStack() {
  auto untrusted_stack =
      std::unique_ptr<UntrustedAllocatorStack,
                      decltype(TrustedPrimitives::UntrustedLocalFree) *>{
          reinterpret_cast<UntrustedAllocatorStack *>(
              TrustedPrimitives::UntrustedLocalAlloc(
                  sizeof(UntrustedAllocatorStack))),
          TrustedPrimitives::UntrustedLocalFree};

  // We cannot directly call the constructor on the untrusted side to initialize
  // untrusted_stack correctly. Therefore, we initialize an empty stack on the
  // trusted side and copy it to untrusted_stack.
  UntrustedAllocatorStack empty_stack;
  memcpy(reinterpret_cast<void *>(untrusted_stack.get()),
         reinterpret_cast<void *>(&empty_stack), sizeof(empty_stack));
  if (!enc_is_outside_enclave(untrusted_stack.get(),
                              sizeof(UntrustedAllocatorStack)) ||
      untrusted_stack.get()->size() != 0 || !untrusted_stack->empty()) {
    abort();
  }

  return untrusted_stack;
}

}  // namespace

// Register SGX backend entry handlers.
void RegisterInternalHandlers() {
  // Register the enclave initialization entry handler.
  EntryHandler init_handler(Initialize);
  if (!TrustedPrimitives::RegisterEntryHandler(kSelectorAsyloInit, init_handler)
           .ok()) {
    TrustedPrimitives::BestEffortAbort("Could not register entry handler");
  }

  // Register the enclave run entry handler.
  EntryHandler run_handler(Run);
  if (!TrustedPrimitives::RegisterEntryHandler(kSelectorAsyloRun, run_handler)
           .ok()) {
    TrustedPrimitives::BestEffortAbort("Could not register entry handler");
  }

  // Register the enclave finalization entry handler.
  EntryHandler finalize_handler{Finalize};
  if (!TrustedPrimitives::RegisterEntryHandler(
          kSelectorAsyloFini, finalize_handler).ok()) {
    TrustedPrimitives::BestEffortAbort("Could not register entry handler");
  }

  // Register the enclave donate thread entry handler.
  EntryHandler donate_thread_handler{DonateThread};
  if (!TrustedPrimitives::RegisterEntryHandler(
          kSelectorAsyloDonateThread, donate_thread_handler).ok()) {
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

int asylo_enclave_call(uint64_t selector, void *params) {
  PrimitiveStatus status = InvokeEntryHandler(
      selector, reinterpret_cast<TrustedParameterStack *>(params));
  return !status.ok();
}

void *TrustedPrimitives::UntrustedLocalAlloc(size_t size) {
  return enc_untrusted_malloc(size);
}

void TrustedPrimitives::UntrustedLocalFree(void *ptr) {
  enc_untrusted_free(ptr);
}

void TrustedPrimitives::DebugPuts(const char *message) {
  abort();
}

PrimitiveStatus TrustedPrimitives::UntrustedCall(
    uint64_t untrusted_selector, TrustedParameterStack *params) {
  int ret;

  // Check whether |params| already points to untrusted memory. If so, we need
  // not copy |params| and its data extents to a new untrusted stack, and can
  // directly make the ocall using |params|.
  if (enc_is_outside_enclave(params, sizeof(*params))) {
    CHECK_OCALL(ocall_dispatch_untrusted_call(
        &ret, untrusted_selector, reinterpret_cast<void *>(params)));
    return PrimitiveStatus(ret);
  }

  auto untrusted_stack = InitUntrustedStack();

  // Copy data to |untrusted_stack|. Once data in |params| is copied, trusted
  // data is not needed and can be cleaned up for efficient memory management.
  // We hold the params in a vector containing the extent unique pointers, which
  // go out of scope with the vector after the data is copied at the end of
  // context (defined by curly braces below).
  {
    std::vector<TrustedParameterStack::ExtentPtr> in_params;
    in_params.reserve(params->size());
    while (!params->empty()) {
      in_params.emplace_back(params->Pop());
    }

    // The order of parameters needs to be preserved, so we push the last
    // parameter first.
    for (auto it = in_params.rbegin(); it != in_params.rend(); ++it) {
      untrusted_stack->PushByCopy(Extent{(*it)->data(), (*it)->size()});

      if (!enc_is_outside_enclave(untrusted_stack->Top().data(),
                                  untrusted_stack->Top().size())) {
        abort();
      }
    }
  }

  CHECK_OCALL(ocall_dispatch_untrusted_call(
      &ret, untrusted_selector,
      reinterpret_cast<void *>(untrusted_stack.get())));

  // For the results obtained in untrusted_stack, copy them to params before
  // deleting untrusted_stack.
  std::vector<UntrustedAllocatorStack::ExtentPtr> result_params;
  result_params.reserve(untrusted_stack->size());
  while (!untrusted_stack->empty()) {
    result_params.emplace_back(untrusted_stack->Pop());
  }

  // The order of parameters needs to be preserved, so we push the last
  // parameter first. All the data on result_params is expected to be on the
  // untrusted side - copy it to params.
  for (auto it = result_params.rbegin(); it != result_params.rend(); ++it) {
    params->PushByCopy(Extent{(*it)->data(), (*it)->size()});
  }

  return PrimitiveStatus::OkStatus();
}

}  // namespace primitives
}  // namespace asylo
