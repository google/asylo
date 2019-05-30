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

#include <vector>

#include "asylo/platform/primitives/extent.h"
#include "asylo/platform/primitives/parameter_stack.h"
#include "asylo/platform/primitives/primitive_status.h"
#include "asylo/platform/primitives/test/test_selectors.h"
#include "asylo/platform/primitives/trusted_primitives.h"
#include "asylo/util/error_codes.h"
#include "asylo/util/status_macros.h"

namespace asylo {
namespace primitives {

namespace {

bool initialized = false;

// Constructor function to illustrate ExitCall before the enclave is fully
// initialized.
void __attribute__((constructor)) InitConstructor() {
  TrustedPrimitives::DebugPuts("InitConstructor start\n");
  constexpr char init_message[] = "InitConstructor";
  TrustedParameterStack init_params;
  init_params.PushByCopy(Extent{init_message, sizeof(init_message)});
  const auto status =
      TrustedPrimitives::UntrustedCall(kUntrustedInit, &init_params);
  TrustedPrimitives::DebugPuts("InitConstructor done: ");
  if (status.ok()) {
    const auto res = init_params.Pop();
    TrustedPrimitives::DebugPuts(reinterpret_cast<const char *>(res->data()));
    initialized = true;
  } else {
    TrustedPrimitives::DebugPuts(status.error_message());
  }
  TrustedPrimitives::DebugPuts("\n");
}

// Message handler that aborts the enclave.
PrimitiveStatus Abort(void *context, TrustedParameterStack *params) {
  if (!params->empty()) {
    return {error::GoogleError::INVALID_ARGUMENT,
            "Abort called with some argument(s)."};
  }
  TrustedPrimitives::BestEffortAbort("Aborting enclave");
  return PrimitiveStatus::OkStatus();
}

// Trivial example enclave message handler interpreting the only input item in
// `params` as an integer and returning two-times value as an output item pushed
// into `params`.
PrimitiveStatus MultiplyByTwo(void *context, TrustedParameterStack *params) {
  if (params->empty()) {
    return {error::GoogleError::INVALID_ARGUMENT,
            "MultiplyByTwo called with incorrect argument(s)."};
  }
  const int32_t input = params->Pop<int32_t>();
  if (!params->empty()) {
    return {error::GoogleError::INVALID_ARGUMENT,
            "MultiplyByTwo called with incorrect argument(s)."};
  }
  params->PushByCopy<int32_t>(2 * input);
  return PrimitiveStatus::OkStatus();
}

// Message handler receiving incoming numbers and returning a running average,
// using thread-local storage.
PrimitiveStatus AveragePerThread(void *context, TrustedParameterStack *params) {
  ABSL_CONST_INIT thread_local int64_t per_thread_sum = 0;
  ABSL_CONST_INIT thread_local int64_t per_thread_count = 0;
  if (params->empty()) {
    return {error::GoogleError::INVALID_ARGUMENT,
            "AveragePerThread called with incorrect argument(s)."};
  }
  const int64_t input = params->Pop<int64_t>();
  if (!params->empty()) {
    return {error::GoogleError::INVALID_ARGUMENT,
            "AveragePerThread called with incorrect argument(s)."};
  }
  // No lock is needed, since these are thread-local variables.
  per_thread_sum += input;
  ++per_thread_count;
  params->PushByCopy<int64_t>(per_thread_sum / per_thread_count);
  return PrimitiveStatus::OkStatus();
}

// Message handler computing a Fibonacci number, recursing into untrusted code.
// Input and result are both passed through `params`.
PrimitiveStatus TrustedFibonacci(void *context, TrustedParameterStack *params) {
  if (params->empty()) {
    return {error::GoogleError::INVALID_ARGUMENT,
            "TrustedFibonacci called with incorrent argument(s)."};
  }
  const int32_t n = params->Pop<int32_t>();
  if (!params->empty()) {
    return {error::GoogleError::INVALID_ARGUMENT,
            "TrustedFibonacci called with incorrent argument(s)."};
  }
  if (n >= 50) {
    return {error::GoogleError::INVALID_ARGUMENT,
            "TrustedFibonacci called with invalid input."};
  }

  PrimitiveStatus status;
  auto untrusted_fibonacci = [&status](int32_t n) -> int32_t {
    TrustedParameterStack nested_params;
    nested_params.PushByCopy<int32_t>(n);
    status =
        TrustedPrimitives::UntrustedCall(kUntrustedFibonacci, &nested_params);
    const int32_t res = nested_params.Pop<int32_t>();
    return res;
  };
  ASYLO_RETURN_IF_ERROR(status);

  params->PushByCopy<int32_t>(
      n <= 1 ? n : untrusted_fibonacci(n - 1) + untrusted_fibonacci(n - 2));
  return PrimitiveStatus{};
}

// Tests whether buffers returned by malloc satisfy IsTrustedExtent().
// Parameter is a single OUT.
PrimitiveStatus TrustedMallocTest(void *context,
                                  TrustedParameterStack *params) {
  if (!params->empty()) {
    return {error::GoogleError::INVALID_ARGUMENT,
            "TrustedMallocTest called with incorrent argument(s)."};
  }
  bool passed = true;
  for (int i = 0; i < 20; i++) {
    size_t sz = 1 << i;
    void *buffer = malloc(sz);
    passed = passed && TrustedPrimitives::IsTrustedExtent(buffer, sz);
    free(buffer);
  }
  params->PushByCopy<bool>(passed);
  return PrimitiveStatus::OkStatus();
}

// Tests whether any buffer returned by UntrustedLocalAlloc does not satisfy
// IsTrustedExtent(). Parameter is a single OUT.
PrimitiveStatus UntrustedLocalAllocTest(void *context,
                                        TrustedParameterStack *params) {
  if (!params->empty()) {
    return {error::GoogleError::INVALID_ARGUMENT,
            "UntrustedLocalAllocTest called with incorrent argument(s)."};
  }
  bool passed = true;
  for (int i = 0; i < 20; i++) {
    size_t sz = 1 << i;
    void *buffer = TrustedPrimitives::UntrustedLocalAlloc(sz);
    passed = passed && !TrustedPrimitives::IsTrustedExtent(buffer, sz);
    TrustedPrimitives::UntrustedLocalFree(buffer);
  }
  params->PushByCopy<bool>(passed);
  return PrimitiveStatus::OkStatus();
}

// Tests multiple parameters handling: copies them from IN to OUT stack.
PrimitiveStatus CopyMultipleParams(void *context,
                                   TrustedParameterStack *params) {
  // Retrieve IN parameters and stow them in a vector (ordered from top to
  // bottom).
  std::vector<TrustedParameterStack::ExtentPtr> params_vector;
  params_vector.reserve(params->size());
  while (!params->empty()) {
    params_vector.emplace_back(params->Pop());
  }
  // Now push them into the OUT stack in reverse order: former top becomes
  // bottom and vice versa.
  for (auto &param : params_vector) {
    params->PushByCopy(Extent{param->data(), param->size()});
    // Release IN parameter.
    param.reset();
  }
  // Add one more parameter at the top of the stack.
  static constexpr char foo[] = "Foo";
  params->PushByCopy<char>(foo, strlen(foo));
  return PrimitiveStatus::OkStatus();
}

// Running multiple random malloc/frees.
PrimitiveStatus StressMallocs(void *context, TrustedParameterStack *params) {
  if (params->size() != 2) {
    return {error::GoogleError::INVALID_ARGUMENT,
            "StressMallocs called with incorrent argument(s)."};
  }

  uint64_t num_allocs = params->Pop<uint64_t>();
  uint64_t max_alloc_size = params->Pop<uint64_t>();
  auto allocs = static_cast<void **>(calloc(num_allocs, sizeof(void *)));
  for (uint64_t i = 0; i < num_allocs; ++i) {
    allocs[i] = malloc(max_alloc_size);
  }
  uint64_t failed_count = 0;
  for (uint64_t i = 0; i < num_allocs; ++i) {
    if (allocs[i]) {
      free(allocs[i]);
    } else {
      failed_count++;
    }
  }
  free(allocs);

  params->PushByCopy<uint64_t>(failed_count);
  return PrimitiveStatus::OkStatus();
}

}  // namespace

// Implements the required enclave initialization function.
extern "C" PrimitiveStatus asylo_enclave_init() {
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      kAbortEnclaveSelector, EntryHandler{Abort}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      kTrustedFibonacci, EntryHandler{TrustedFibonacci}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      kTimesTwoSelector, EntryHandler{MultiplyByTwo}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      kAveragePerThreadSelector, EntryHandler{AveragePerThread}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      kTrustedMallocTest, EntryHandler{TrustedMallocTest}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      kUntrustedLocalAllocTest, EntryHandler{UntrustedLocalAllocTest}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      kCopyMultipleParamsSelector, EntryHandler{CopyMultipleParams}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      kStressMallocs, EntryHandler{StressMallocs}));
  return initialized
             ? PrimitiveStatus::OkStatus()
             : PrimitiveStatus{::asylo::error::GoogleError::FAILED_PRECONDITION,
                               "Enclave not initialized"};
}

// Implements the required enclave finalization function.
extern "C" PrimitiveStatus asylo_enclave_fini() {
  return PrimitiveStatus::OkStatus();
}

}  // namespace primitives
}  // namespace asylo
