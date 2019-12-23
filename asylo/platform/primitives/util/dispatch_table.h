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

#include <unordered_map>

#include "asylo/platform/primitives/untrusted_primitives.h"
#include "asylo/platform/primitives/util/message.h"
#include "asylo/util/asylo_macros.h"
#include "asylo/util/mutex_guarded.h"
#include "asylo/util/status.h"

namespace asylo {
namespace primitives {

// Implementation of ExitCallProvider based on dispatch table (thread safe).
class DispatchTable : public Client::ExitCallProvider {
 public:
  // A hook class which gives users a callback mechanism to inspect
  // exit calls.
  class ExitHook {
   public:
    // PreExit is called with the exit call selector before an exit
    // call is made. If it returns anything other than an OK status,
    // that exit call will NOT be made, and that non-ok status will be
    // returned back to the enclave.
    virtual Status PreExit(uint64_t untrusted_selector) = 0;

    // PostExit is called with the result of the external exit call,
    // after that call is made (but before returning to the
    // enclave). PostExit returns a status as well, which will be
    // returned to the enclave. It is expected that most
    // implementations will simply pass the argument status directly
    // through and return it.
    virtual Status PostExit(Status result) = 0;

    virtual ~ExitHook() = default;
  };

  // A factory for hook objects. The factory pattern is used here in
  // order to allow each hook object to store state between PreExit
  // and PostExit: for instance a timestamp corresponding to the
  // beginning and end of a host call.
  class ExitHookFactory {
   public:
    virtual std::unique_ptr<ExitHook> CreateExitHook() = 0;
    virtual ~ExitHookFactory() = default;
  };

  DispatchTable()
      : exit_table_(std::unordered_map<uint64_t, ExitHandler>()),
        exit_hook_factory_() {}

  explicit DispatchTable(std::unique_ptr<ExitHookFactory> exit_hook_factory)
      : exit_table_(std::unordered_map<uint64_t, ExitHandler>()),
        exit_hook_factory_(std::move(exit_hook_factory)) {}

  // Registers a callback as the handler routine for an enclave exit point
  // `untrusted_selector`. Returns an error code if a handler has already been
  // registered for `trusted_selector` or if an invalid selector value is
  // passed.
  Status RegisterExitHandler(uint64_t untrusted_selector,
                             const ExitHandler &handler) override;

  // Finds and invokes an exit handler, setting an error status on failure.
  Status InvokeExitHandler(uint64_t untrusted_selector, MessageReader *input,
                           MessageWriter *output,
                           Client *client) override ASYLO_MUST_USE_RESULT;

 private:
  // Internal helper to actually perform an exit call.
  Status PerformExit(uint64_t untrusted_selector, MessageReader *input,
                     MessageWriter *output, Client *client);

  // Internal helper to perform an exit call that has no registered handler.
  // In most cases will just return an error, but might be overridden to do
  // something else.
  virtual Status PerformUnknownExit(uint64_t untrusted_selector,
                                    MessageReader *input, MessageWriter *output,
                                    Client *client);

  // DispatchTable is used in trusted primitives layer where system calls might
  // not be available; avoid using absl based containers which may perform
  // system calls.
  MutexGuarded<std::unordered_map<uint64_t, ExitHandler>> exit_table_;
  const std::unique_ptr<ExitHookFactory> exit_hook_factory_;
};

}  // namespace primitives
}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_UTIL_DISPATCH_TABLE_H_
