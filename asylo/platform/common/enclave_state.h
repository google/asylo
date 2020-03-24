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

#ifndef ASYLO_PLATFORM_COMMON_ENCLAVE_STATE_H_
#define ASYLO_PLATFORM_COMMON_ENCLAVE_STATE_H_

#include "asylo/util/status.h"

namespace asylo {

/// An enumeration of possible enclave runtime states.
enum class EnclaveState {
  /// Enclave initialization has not started.
  kUninitialized,
  /// Asylo internals are initializing.
  kInternalInitializing,
  /// Asylo internals are initialized. User-defined initialization is
  /// in-progress.
  kUserInitializing,
  /// All initialization has completed. The enclave is running.
  kRunning,
  /// The enclave is finalizing.
  kFinalizing,
  /// The enclave has finalized.
  kFinalized,
};

/// Verifies the expected enclave state and sets a new one in thread-safe
/// manner. Returns error if the verification fails.
Status VerifyAndSetState(const EnclaveState &expected_state,
                         const EnclaveState &new_state);

/// Sets the enclave state in thread-safe manner.
void SetState(const EnclaveState &state);

/// Returns the enclave state in a thread-safe manner.
EnclaveState GetState();

}  // namespace asylo

#endif  // ASYLO_PLATFORM_COMMON_ENCLAVE_STATE_H_
