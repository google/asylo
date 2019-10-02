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

#ifndef ASYLO_PLATFORM_PRIMITIVES_SGX_SIGNAL_DISPATCHER_H_
#define ASYLO_PLATFORM_PRIMITIVES_SGX_SIGNAL_DISPATCHER_H_

#include <signal.h>

#include "absl/container/flat_hash_map.h"
#include "absl/synchronization/mutex.h"
#include "asylo/platform/primitives/sgx/untrusted_sgx.h"
#include "asylo/util/status.h"  // IWYU pragma: export
#include "asylo/util/statusor.h"

namespace asylo {
namespace primitives {

// Stores the mapping between signals and the enclave with a handler installed
// for that signal.
class EnclaveSignalDispatcher {
 public:
  static EnclaveSignalDispatcher *GetInstance();

  // Associates a signal with an enclave which registers a handler for it.
  // It's not supported for multiple enclaves to register the same signal. In
  // that case, the latter will overwrite the former.
  //
  // Returns the enclave client that previous registered |signum|, or nullptr if
  // no enclave has registered |signum| yet.
  const SgxEnclaveClient *RegisterSignal(int signum, SgxEnclaveClient *client)
      ABSL_LOCKS_EXCLUDED(signal_enclave_map_lock_);

  // Gets the enclave that registered a handler for |signum|.
  StatusOr<SgxEnclaveClient *> GetClientForSignal(int signum) const
      ABSL_LOCKS_EXCLUDED(signal_enclave_map_lock_);

  // Deregisters all the signals registered by |client|.
  Status DeregisterAllSignalsForClient(SgxEnclaveClient *client)
      ABSL_LOCKS_EXCLUDED(signal_enclave_map_lock_);

  // Looks for the enclave client that registered |signum|, and calls
  // EnterAndHandleSignal() with that enclave client. |signum|, |info| and
  // |ucontext| are passed into the enclave.
  Status EnterEnclaveAndHandleSignal(int signum, siginfo_t *info,
                                     void *ucontext);

 private:
  EnclaveSignalDispatcher() = default;  // Private to enforce singleton.
  EnclaveSignalDispatcher(EnclaveSignalDispatcher const &) = delete;
  void operator=(EnclaveSignalDispatcher const &) = delete;

  // Mapping of signal number to the enclave client that registered it.
  absl::flat_hash_map<int, SgxEnclaveClient *> signal_to_client_map_
      ABSL_GUARDED_BY(signal_enclave_map_lock_);

  // A mutex that guards signal_to_client_map_ and client_to_signal_map_.
  mutable absl::Mutex signal_enclave_map_lock_;
};

}  // namespace primitives
}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_SGX_SIGNAL_DISPATCHER_H_
