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

#ifndef ASYLO_PLATFORM_PRIMITIVES_REMOTE_LOCAL_EXIT_CALLS_H_
#define ASYLO_PLATFORM_PRIMITIVES_REMOTE_LOCAL_EXIT_CALLS_H_

#include <vector>

#include "absl/types/optional.h"
#include "asylo/platform/primitives/remote/proxy_server.h"
#include "asylo/platform/primitives/util/dispatch_table.h"
#include "asylo/platform/primitives/util/exit_log.h"
#include "asylo/platform/primitives/util/message.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace primitives {

// Remote backend specific implementation of ExitCallProvider whose purpose is
// to forward majority of exit calls invoked by the enclave loaded by proxy
// server over the remote connector to the untrusted host. Registration of exit
// handlers is only needed for those exit calls that can be handled locally.
class LocalExitCallForwarder : public LoggingDispatchTable {
 public:
  // Base class for exit calls to be potentially handled by proxy server.
  // Each handler needs to be declared as follows:
  //
  //   class FooExitCallHandler
  //       : public LocalExitCallForwarder::LocalExitCallHandler {
  //    public:
  //     FooExitCallHandler(<optional parameters>,
  //                        LocalExitCallForwarder *forwarder)
  //         : LocalExitCallForwarder::LocalExitCallHandler(
  //               <Foo exit call selector>,
  //               forwarder),
  //           <store parameters into local class variables> {}
  //
  //     absl::optional<Status> AttemptExecute(MessageReader *input,
  //                                           MessageWriter *output) override {
  //       // Filter out the calls that need to be forwarded to the proxy
  //       // client.
  //       if (<Foo exit call cannot be handled locally>) {
  //         return absl::nullopt;
  //       }
  //
  //       // Process  locally.
  //       ... return OK or Status{error, "Error message"};
  //     }
  //
  //    private:
  //     <local class variables>
  //   };
  class LocalExitCallHandler {
   public:
    virtual ~LocalExitCallHandler() = default;

    // Attempts to execute the handler. If the handler returns Status (whether
    // it is OK or error), proxy server will pass it to the caller. If there is
    // no Status, proxy server will make a remote call to proxy client to handle
    // the exit call there.
    virtual absl::optional<Status> AttemptExecute(MessageReader *input,
                                                  MessageWriter *output) = 0;

    // Forwards the exit call to proxy, when AttemptExecute returns nullopt.
    Status Forward(MessageReader *input, MessageWriter *output,
                   Client *client) const {
      return forwarder_->server_->ExitCallForwarder(selector_, input, output,
                                                    client);
    }

    // Registers the handler with forwarder.
    Status Register() {
      return forwarder_->RegisterExitHandler(
          selector_,
          ExitHandler{&LocalExitCallForwarder::Run, static_cast<void *>(this)});
    }

   protected:
    explicit LocalExitCallHandler(uint64_t selector,
                                  LocalExitCallForwarder *forwarder)
        : selector_(selector), forwarder_(forwarder) {}

   private:
    const uint64_t selector_;
    LocalExitCallForwarder *const forwarder_;
  };

  // Factory method creates a forwarder associated with the server and
  // registers all local exit handlers. Should only be called once.
  // `exit_logging` parameter indicates whether enclave exit call logging is
  // to be enabled or not.
  static StatusOr<std::unique_ptr<Client::ExitCallProvider>> Create(
      bool exit_logging, const RemoteEnclaveProxyServer *server);

  // Runs exit call handler.
  static Status Run(const std::shared_ptr<Client> &client, void *context,
                    MessageReader *input, MessageWriter *output);

  // Handles an exit call that was not processed locally.
  Status PerformUnknownExit(uint64_t untrusted_selector, MessageReader *input,
                            MessageWriter *output, Client *client) override;

 private:
  LocalExitCallForwarder(bool exit_logging,
                         const RemoteEnclaveProxyServer *server);

  // Registered handlers.
  std::vector<std::unique_ptr<LocalExitCallHandler>> handlers_;
  // Associated server.
  const RemoteEnclaveProxyServer *const server_;
};

}  // namespace primitives
}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_REMOTE_LOCAL_EXIT_CALLS_H_
