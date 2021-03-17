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
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "asylo/platform/primitives/extent.h"
#include "asylo/platform/primitives/long_living_test/long_living_test_selectors.h"
#include "asylo/platform/primitives/primitive_status.h"
#include "asylo/platform/primitives/trusted_primitives.h"
#include "asylo/platform/primitives/trusted_runtime.h"
#include "asylo/util/status_macros.h"

using asylo::primitives::EntryHandler;
using asylo::primitives::PrimitiveStatus;
using asylo::primitives::TrustedPrimitives;

namespace asylo {
namespace primitives {

namespace {

PrimitiveStatus GetCurrentTime(absl::Time *current_time) {
  MessageReader current_time_output;
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::UntrustedCall(
      kCurrentTimeExitCall, nullptr, &current_time_output));
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(current_time_output, 1);
  *current_time = current_time_output.next<absl::Time>();
  return PrimitiveStatus::OkStatus();
}

// Enclave message handler that takes a looooong time to return.
PrimitiveStatus LongEntryCall(void *context, MessageReader *input,
                              MessageWriter *output) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*input, 1);
  const auto duration = input->next<absl::Duration>();

  absl::Time start_time;
  ASYLO_RETURN_IF_ERROR(GetCurrentTime(&start_time));

  MessageWriter sleep_input;
  sleep_input.Push<absl::Duration>(duration);
  MessageReader sleep_output;
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::UntrustedCall(
      kSleepForExitCall, &sleep_input, &sleep_output));
  ASYLO_RETURN_IF_READER_NOT_EMPTY(sleep_output);

  absl::Time end_time;
  ASYLO_RETURN_IF_ERROR(GetCurrentTime(&end_time));

  output->Push<absl::Duration>(end_time - start_time);
  return PrimitiveStatus::OkStatus();
}

}  // namespace
}  // namespace primitives
}  // namespace asylo

// Implements the required enclave initialization function.
extern "C" PrimitiveStatus asylo_enclave_init() {
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::primitives::kLongCall,
      EntryHandler{asylo::primitives::LongEntryCall}));
  return PrimitiveStatus::OkStatus();
}

// Implements the required enclave finalization function.
extern "C" PrimitiveStatus asylo_enclave_fini() {
  return PrimitiveStatus::OkStatus();
}
