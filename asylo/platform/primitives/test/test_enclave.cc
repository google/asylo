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

#include "absl/status/status.h"
#include "asylo/platform/primitives/extent.h"
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
  MessageWriter init_input;
  constexpr char init_message[] = "InitConstructor";
  init_input.PushByReference(Extent{init_message, sizeof(init_message)});
  MessageReader init_output;
  const auto status = TrustedPrimitives::UntrustedCall(
      kUntrustedInit, &init_input, &init_output);
  TrustedPrimitives::DebugPuts("InitConstructor done: ");
  if (status.ok()) {
    if (init_output.size() == 1) {
      auto init_id = init_output.next();
      TrustedPrimitives::DebugPuts(
          reinterpret_cast<const char *>(init_id.data()));
      initialized = true;
    } else {
      TrustedPrimitives::DebugPuts("Wrong output by kUntrustedInit");
    }
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
    return {primitives::AbslStatusCode::kInvalidArgument,
            "TrustedFibonacci called with invalid input."};
  }

  auto untrusted_fibonacci =
      [](int32_t n, MessageReader *nested_output) -> PrimitiveStatus {
    MessageWriter nested_input;
    nested_input.Push(n);
    ASYLO_RETURN_IF_ERROR(TrustedPrimitives::UntrustedCall(
        kUntrustedFibonacci, &nested_input, nested_output));
    ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*nested_output, 1);
    return PrimitiveStatus::OkStatus();
  };

  if (n <= 1) {
    out->Push(n);
    return PrimitiveStatus::OkStatus();
  }

  MessageReader nested_output_1;
  MessageReader nested_output_2;
  ASYLO_RETURN_IF_ERROR(untrusted_fibonacci(n - 1, &nested_output_1));
  ASYLO_RETURN_IF_ERROR(untrusted_fibonacci(n - 2, &nested_output_2));
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(nested_output_1, 1);
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(nested_output_2, 1);
  out->Push(nested_output_1.next<int32_t>() + nested_output_2.next<int32_t>());
  return PrimitiveStatus::OkStatus();
}

// Tests whether buffers returned by malloc satisfy IsInsideEnclave().
// Parameter is a single OUT.
PrimitiveStatus TrustedMallocTest(void *context, MessageReader *in,
                                  MessageWriter *out) {
  ASYLO_RETURN_IF_READER_NOT_EMPTY(*in);
  bool passed = true;
  for (int i = 0; i < 20; i++) {
    size_t sz = 1 << i;
    void *buffer = malloc(sz);
    passed = passed && TrustedPrimitives::IsInsideEnclave(buffer, sz);
    free(buffer);
  }
  out->Push(passed);
  return PrimitiveStatus::OkStatus();
}

// Tests whether any buffer returned by UntrustedLocalAlloc does not satisfy
// IsOutsideEnclave(). Parameter is a single OUT.
PrimitiveStatus UntrustedLocalAllocTest(void *context, MessageReader *in,
                                        MessageWriter *out) {
  ASYLO_RETURN_IF_READER_NOT_EMPTY(*in);
  bool passed = true;
  for (int i = 0; i < 20; i++) {
    size_t sz = 1 << i;
    void *buffer = TrustedPrimitives::UntrustedLocalAlloc(sz);
    passed = passed && TrustedPrimitives::IsOutsideEnclave(buffer, sz);
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

PrimitiveStatus InsideOutsideTest(void *context, MessageReader *in,
                                  MessageWriter *out) {
  struct EnclaveMemoryLayout layout;
  enc_get_memory_layout(&layout);

  const size_t kIntervalSize = 4096;

  // Extent before the enclave.
  uint8_t *begin = static_cast<uint8_t *>(layout.base);
  if (!TrustedPrimitives::IsOutsideEnclave(nullptr, kIntervalSize) ||
      TrustedPrimitives::IsInsideEnclave(nullptr, kIntervalSize)) {
    out->PushString("Failed for extent before enclave");
    return PrimitiveStatus::OkStatus();
  }

  // Extent inside the enclave.
  begin = static_cast<uint8_t *>(layout.base);
  if (TrustedPrimitives::IsOutsideEnclave(begin, kIntervalSize) ||
      !TrustedPrimitives::IsInsideEnclave(begin, kIntervalSize)) {
    out->PushString("Failed for extent inside enclave");
    return PrimitiveStatus::OkStatus();
  }

  // Extent after the enclave.
  uint8_t *end = begin + layout.size;
  if (!TrustedPrimitives::IsOutsideEnclave(end, kIntervalSize) ||
      TrustedPrimitives::IsInsideEnclave(end, kIntervalSize)) {
    out->PushString("Failed for extent after enclave");
    return PrimitiveStatus::OkStatus();
  }

  // Extent covering the enclave.
  uint8_t *before = begin - kIntervalSize;
  uint8_t *after = end + kIntervalSize;
  if (TrustedPrimitives::IsOutsideEnclave(before, after - before) ||
      TrustedPrimitives::IsInsideEnclave(before, after - before)) {
    out->PushString("Failed for extent covering enclave");
    return PrimitiveStatus::OkStatus();
  }

  // Extent where address arithmetic might overflow.
  const size_t kLargeSize = ~UINT64_C(0) - kIntervalSize;
  if (TrustedPrimitives::IsOutsideEnclave(begin - kIntervalSize, kLargeSize) ||
      TrustedPrimitives::IsInsideEnclave(begin - kIntervalSize, kLargeSize)) {
    out->PushString("Failed for arithmetic overflow");
    return PrimitiveStatus::OkStatus();
  }

  // Extent covering enclave start.
  if (TrustedPrimitives::IsOutsideEnclave(begin - kIntervalSize,
                                          2 * kIntervalSize) ||
      TrustedPrimitives::IsInsideEnclave(begin - kIntervalSize,
                                         2 * kIntervalSize)) {
    out->PushString("Failed for extent spanning enclave start");
    return PrimitiveStatus::OkStatus();
  }

  // Extent covering enclave end.
  if (TrustedPrimitives::IsOutsideEnclave(end - kIntervalSize,
                                          2 * kIntervalSize) ||
      TrustedPrimitives::IsInsideEnclave(end - kIntervalSize,
                                         2 * kIntervalSize)) {
    out->PushString("Failed for extent spanning enclave end");
    return PrimitiveStatus::OkStatus();
  }

  out->PushString("pass");
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
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::primitives::kInsideOutsideTest,
      EntryHandler{asylo::primitives::InsideOutsideTest}));
  return asylo::primitives::initialized
             ? PrimitiveStatus::OkStatus()
             : PrimitiveStatus{
                   asylo::primitives::AbslStatusCode::kFailedPrecondition,
                   "Enclave not initialized"};
}

// Implements the required enclave finalization function.
extern "C" PrimitiveStatus asylo_enclave_fini() {
  return PrimitiveStatus::OkStatus();
}
