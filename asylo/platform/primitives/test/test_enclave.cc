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
#include "asylo/platform/primitives/trusted_runtime.h"
#include "asylo/platform/primitives/util/message.h"
#include "asylo/util/status_macros.h"

using ::asylo::primitives::EntryHandler;
using ::asylo::primitives::PrimitiveStatus;
using ::asylo::primitives::TrustedPrimitives;

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
PrimitiveStatus Abort(void *context, MessageReader *in, MessageWriter *out) {
  ASYLO_RETURN_IF_READER_NOT_EMPTY(*in);
  TrustedPrimitives::BestEffortAbort("Aborting enclave");
  return PrimitiveStatus::OkStatus();
}

// Trivial example enclave message handler interpreting the only input item in
// `params` as an integer and returning two-times value as an output item pushed
// into `params`.
PrimitiveStatus MultiplyByTwo(void *context, MessageReader *in,
                              MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 1);
  out->Push(2 * in->next<int32_t>());
  return PrimitiveStatus::OkStatus();
}

// Message handler receiving incoming numbers and returning a running average,
// using thread-local storage.
PrimitiveStatus AveragePerThread(void *context, MessageReader *in,
                                 MessageWriter *out) {
  ABSL_CONST_INIT thread_local int64_t per_thread_sum = 0;
  ABSL_CONST_INIT thread_local int64_t per_thread_count = 0;
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 1);
  // No lock is needed, since these are thread-local variables.
  per_thread_sum += in->next<int64_t>();
  ++per_thread_count;
  out->Push(per_thread_sum / per_thread_count);
  return PrimitiveStatus::OkStatus();
}

// Message handler computing a Fibonacci number, recursing into untrusted code.
// Input and result are both passed through `params`.
PrimitiveStatus TrustedFibonacci(void *context, MessageReader *in,
                                 MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 1);
  const int32_t n = in->next<int32_t>();
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

  out->Push(n <= 1 ? n
                   : untrusted_fibonacci(n - 1) + untrusted_fibonacci(n - 2));
  return PrimitiveStatus::OkStatus();
}

// Tests whether buffers returned by malloc satisfy IsTrustedExtent().
// Parameter is a single OUT.
PrimitiveStatus TrustedMallocTest(void *context, MessageReader *in,
                                  MessageWriter *out) {
  ASYLO_RETURN_IF_READER_NOT_EMPTY(*in);
  bool passed = true;
  for (int i = 0; i < 20; i++) {
    size_t sz = 1 << i;
    void *buffer = malloc(sz);
    passed = passed && TrustedPrimitives::IsTrustedExtent(buffer, sz);
    free(buffer);
  }
  out->Push(passed);
  return PrimitiveStatus::OkStatus();
}

// Tests whether any buffer returned by UntrustedLocalAlloc does not satisfy
// IsTrustedExtent(). Parameter is a single OUT.
PrimitiveStatus UntrustedLocalAllocTest(void *context, MessageReader *in,
                                        MessageWriter *out) {
  ASYLO_RETURN_IF_READER_NOT_EMPTY(*in);
  bool passed = true;
  for (int i = 0; i < 20; i++) {
    size_t sz = 1 << i;
    void *buffer = TrustedPrimitives::UntrustedLocalAlloc(sz);
    passed = passed && !TrustedPrimitives::IsTrustedExtent(buffer, sz);
    TrustedPrimitives::UntrustedLocalFree(buffer);
  }
  out->Push(passed);
  return PrimitiveStatus::OkStatus();
}

// Tests multiple parameters handling: copies them from IN to OUT stack.
PrimitiveStatus CopyMultipleParams(void *context, MessageReader *in,
                                   MessageWriter *out) {
  // Retrieve IN parameters and copy them into OUT in the same order.
  while (in->hasNext()) {
    out->PushByCopy(in->next());
  }
  // Add one more parameter at the top of the stack.
  static constexpr char foo[] = "Foo";
  out->PushByCopy({foo, strlen(foo)});
  return PrimitiveStatus::OkStatus();
}

// Running multiple random malloc/frees.
PrimitiveStatus StressMallocs(void *context, MessageReader *in,
                              MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 2);
  uint64_t num_allocs = in->next<uint64_t>();
  uint64_t max_alloc_size = in->next<uint64_t>();
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
  out->Push(failed_count);
  return PrimitiveStatus::OkStatus();
}

}  // namespace
}  // namespace primitives
}  // namespace asylo

// Implements the required enclave initialization function.
extern "C" PrimitiveStatus asylo_enclave_init() {
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::primitives::kAbortEnclaveSelector,
      EntryHandler{asylo::primitives::Abort}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::primitives::kTrustedFibonacci,
      EntryHandler{asylo::primitives::TrustedFibonacci}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::primitives::kTimesTwoSelector,
      EntryHandler{asylo::primitives::MultiplyByTwo}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::primitives::kAveragePerThreadSelector,
      EntryHandler{asylo::primitives::AveragePerThread}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::primitives::kTrustedMallocTest,
      EntryHandler{asylo::primitives::TrustedMallocTest}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::primitives::kUntrustedLocalAllocTest,
      EntryHandler{asylo::primitives::UntrustedLocalAllocTest}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::primitives::kCopyMultipleParamsSelector,
      EntryHandler{asylo::primitives::CopyMultipleParams}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::primitives::kStressMallocs,
      EntryHandler{asylo::primitives::StressMallocs}));
  return asylo::primitives::initialized
             ? PrimitiveStatus::OkStatus()
             : PrimitiveStatus{::asylo::error::GoogleError::FAILED_PRECONDITION,
                               "Enclave not initialized"};
}

// Implements the required enclave finalization function.
extern "C" PrimitiveStatus asylo_enclave_fini() {
  return PrimitiveStatus::OkStatus();
}
