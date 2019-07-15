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

#include "asylo/platform/primitives/util/dispatch_table.h"

#include <memory>

#include "asylo/util/status.h"

namespace asylo {
namespace primitives {

// Registers a callback as the handler routine for an enclave exit point
// `untrusted_selector`. Returns an error code if a handler has already been
// registered for `trusted_selector` or if an invalid selector value is
// passed.
Status DispatchTable::RegisterExitHandler(uint64_t untrusted_selector,
                                          const ExitHandler &handler) {
  // Ensure no handler is installed for untrusted_selector.
  auto locked_exit_table = exit_table_.Lock();
  if (locked_exit_table->contains(untrusted_selector)) {
    return {error::GoogleError::ALREADY_EXISTS,
            "Invalid selector in RegisterExitHandler."};
  }
  locked_exit_table->emplace(untrusted_selector, handler);
  return Status::OkStatus();
}

// Finds and invokes an exit handler, setting an error status on failure.
Status DispatchTable::InvokeExitHandler(uint64_t untrusted_selector,
                                        NativeParameterStack *params,
                                        Client *client) {
  ExitHandler handler;
  {
    auto locked_exit_table = exit_table_.ReaderLock();
    auto it = locked_exit_table->find(untrusted_selector);
    if (it == locked_exit_table->end()) {
      return {error::GoogleError::OUT_OF_RANGE,
              "Invalid selector in enclave exit."};
    }
    handler = it->second;
  }
  return handler.callback(client->shared_from_this(), handler.context, params);
}

}  // namespace primitives
}  // namespace asylo
