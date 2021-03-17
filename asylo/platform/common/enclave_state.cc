/*
 *
 * Copyright 2020 Asylo authors
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

#include "asylo/platform/common/enclave_state.h"

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "asylo/platform/core/trusted_spin_lock.h"
#include "asylo/util/lock_guard.h"
#include "asylo/util/status.h"

namespace asylo {
namespace {

// lock to protect enclave state.
TrustedSpinLock global_enclave_state_lock(/*is_recursive=*/false);

// Enclave state.
static EnclaveState global_enclave_state
    ABSL_GUARDED_BY(global_enclave_state_lock) = EnclaveState::kUninitialized;

}  // namespace

Status VerifyAndSetState(const EnclaveState &expected_state,
                         const EnclaveState &new_state)
    ABSL_LOCKS_EXCLUDED(global_enclave_state_lock) {
  LockGuard lock(&global_enclave_state_lock);
  if (global_enclave_state != expected_state) {
    return absl::FailedPreconditionError(
        ::absl::StrCat("Enclave is in state: ", global_enclave_state,
                       " expected state: ", expected_state));
  }
  global_enclave_state = new_state;
  return absl::OkStatus();
}

EnclaveState GetState() ABSL_LOCKS_EXCLUDED(global_enclave_state_lock) {
  LockGuard lock(&global_enclave_state_lock);
  return global_enclave_state;
}

void SetState(const EnclaveState &state)
    ABSL_LOCKS_EXCLUDED(global_enclave_state_lock) {
  LockGuard lock(&global_enclave_state_lock);
  global_enclave_state = state;
}

}  // namespace asylo
