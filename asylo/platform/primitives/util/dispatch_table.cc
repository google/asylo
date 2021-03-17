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

#include "absl/status/status.h"
#include "absl/types/optional.h"
#include "asylo/platform/primitives/util/message.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"

namespace asylo {
namespace primitives {

Status DispatchTable::RegisterExitHandler(uint64_t untrusted_selector,
                                          const ExitHandler &handler) {
  // Ensure no handler is installed for untrusted_selector.
  auto locked_exit_table = exit_table_.Lock();
  if (locked_exit_table->count(untrusted_selector)) {
    return absl::AlreadyExistsError("Invalid selector in RegisterExitHandler.");
  }
  locked_exit_table->emplace(untrusted_selector, handler);
  return absl::OkStatus();
}

Status DispatchTable::PerformUnknownExit(uint64_t untrusted_selector,
                                         MessageReader *input,
                                         MessageWriter *output,
                                         Client *client) {
  return absl::OutOfRangeError("Invalid selector in enclave exit.");
}

Status DispatchTable::PerformExit(uint64_t untrusted_selector,
                                  MessageReader *input, MessageWriter *output,
                                  Client *client) {
  absl::optional<ExitHandler> handler;
  {
    auto locked_exit_table = exit_table_.ReaderLock();
    auto it = locked_exit_table->find(untrusted_selector);
    if (it != locked_exit_table->end()) {
      handler = it->second;
    }
  }
  if (!handler.has_value()) {
    return PerformUnknownExit(untrusted_selector, input, output, client);
  }
  return handler.value().callback(client->shared_from_this(),
                                  handler.value().context, input, output);
}

// Finds and invokes an exit handler, setting an error status on failure.
Status DispatchTable::InvokeExitHandler(uint64_t untrusted_selector,
                                        MessageReader *input,
                                        MessageWriter *output, Client *client) {
  if (exit_hook_factory_) {
    auto hook = exit_hook_factory_->CreateExitHook();
    ASYLO_RETURN_IF_ERROR(hook->PreExit(untrusted_selector));
    return hook->PostExit(
        PerformExit(untrusted_selector, input, output, client));
  } else {
    return PerformExit(untrusted_selector, input, output, client);
  }
}

}  // namespace primitives
}  // namespace asylo
