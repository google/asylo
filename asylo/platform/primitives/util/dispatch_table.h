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

#ifndef ASYLO_PLATFORM_PRIMITIVES_UTIL_DISPATCH_TABLE_H_
#define ASYLO_PLATFORM_PRIMITIVES_UTIL_DISPATCH_TABLE_H_

#include "absl/base/thread_annotations.h"
#include "absl/container/flat_hash_map.h"
#include "absl/synchronization/mutex.h"
#include "asylo/platform/primitives/parameter_stack.h"
#include "asylo/platform/primitives/untrusted_primitives.h"
#include "asylo/util/asylo_macros.h"

namespace asylo {
namespace primitives {

// Implementation of ExitCallProvider based on dispatch table (thread safe).
class DispatchTable : public EnclaveClient::ExitCallProvider {
 public:
  DispatchTable() = default;

  // Registers a callback as the handler routine for an enclave exit point
  // `untrusted_selector`. Returns an error code if a handler has already been
  // registered for `trusted_selector` or if an invalid selector value is
  // passed.
  Status RegisterExitHandler(uint64_t untrusted_selector,
                             const ExitHandler &handler) override
      ASYLO_MUST_USE_RESULT LOCKS_EXCLUDED(mutex_);

  // Finds and invokes an exit handler, setting an error status on failure.
  Status InvokeExitHandler(uint64_t untrusted_selector,
                           UntrustedParameterStack *params,
                           EnclaveClient *client) override ASYLO_MUST_USE_RESULT
      LOCKS_EXCLUDED(mutex_);

 private:
  absl::Mutex mutex_;
  absl::flat_hash_map<uint64_t, ExitHandler> exit_table_ GUARDED_BY(mutex_);
};

}  // namespace primitives
}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_UTIL_DISPATCH_TABLE_H_
