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

#ifndef ASYLO_PLATFORM_PRIMITIVES_REMOTE_PROXY_SERVER_H_
#define ASYLO_PLATFORM_PRIMITIVES_REMOTE_PROXY_SERVER_H_

#include <stdint.h>

#include <functional>
#include <memory>
#include <string>
#include <utility>

#include "absl/container/flat_hash_map.h"
#include "absl/memory/memory.h"
#include "absl/strings/string_view.h"
#include "asylo/platform/primitives/extent.h"
#include "asylo/platform/primitives/primitive_status.h"
#include "asylo/platform/primitives/remote/communicator.h"
#include "asylo/platform/primitives/untrusted_primitives.h"
#include "asylo/platform/primitives/util/message.h"
#include "asylo/util/remote/remote_proxy_config.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"
#include "asylo/util/thread.h"
#include "include/grpcpp/security/credentials.h"
#include "include/grpcpp/security/server_credentials.h"
#include "include/grpcpp/support/channel_arguments.h"

namespace asylo {
namespace primitives {

// Remote backend target for the enclave loaded into a dedicated process,
// spawned dynamically by untrusted host remote loader.
// Implemented as a ProcessMainWrapper Activity.
//
// Proxy backend server provides the target process with the set of trusted
// primitives, allowing the enclave code run even though it is not loaded into
// the host process. Conversely, RemoteEnclaveProxyClient implements untrusted
// primitives for the host code and allows it to run even though the enclave is
// located outside of the host process.
//
// RemoteEnclaveProxyClient-RemoteEnclaveProxyServer pair encapsulates all
// communications between untrusted primitives in the host process and trusted
// primitives in the target process.
class RemoteEnclaveProxyServer {
 public:
  ~RemoteEnclaveProxyServer() = default;

  RemoteEnclaveProxyServer(const RemoteEnclaveProxyServer &other) = delete;
  RemoteEnclaveProxyServer &operator=(const RemoteEnclaveProxyServer &other) =
      delete;

  // Creates the RemoteEnclaveProxyServer instance, connecting
  // RemoteEnclaveProxyServer to the enclave proxy for the enclave
  // loaded locally, accessing it with local_enclave_client.
  //
  // Returns a non-OK status on error.
  //
  // Once Create() succeeded, Wait() needs to be called - it will run until
  // the communicator has been disconnected on a cue from the proxy client.
  // After disconnection EnclaveProxyServer releases the local enclave.
  static StatusOr<std::unique_ptr<RemoteEnclaveProxyServer>> Create(
      std::unique_ptr<RemoteProxyServerConfig> remote_proxy_config,
      std::function<StatusOr<std::shared_ptr<Client>>(
          MessageWriter *enclave_params,
          std::unique_ptr<Client::ExitCallProvider> exit_call_provider)>
          local_enclave_client_factory);

  // Enters the main loop of the communicator to accept messages from the
  // RemoteEnclaveProxyClient, created by the remote host process running
  // untrusted customer code. Waits for the communicator to disconnect.
  void Wait();

  // Handles a signal, received by proxy remote process, diconnecting
  // the communicator, if necessary.
  void Kill(int signum);

  // Makes a call to the counterpart connector to perform an exit call with
  // the given registered selector.
  Status ExitCallForwarder(uint64_t exit_call_selector, MessageReader *input,
                           MessageWriter *output, Client *client) const;

  // Target side communicator.
  Communicator *communicator() const { return communicator_.get(); }

 private:
  explicit RemoteEnclaveProxyServer(
      std::unique_ptr<RemoteProxyServerConfig> config);

  // Connects RemoteEnclaveProxyServer to the enclave proxy for the enclave
  // loaded locally. Returns a non-OK status on error.
  Status Start(
      std::function<StatusOr<std::shared_ptr<Client>>(
          MessageWriter *enclave_params,
          std::unique_ptr<Client::ExitCallProvider> exit_call_provider)>
          local_enclave_client_factory);

  // Loaded enclave client.
  std::shared_ptr<Client> local_enclave_client_;

  // Target side communicator.
  const std::unique_ptr<Communicator> communicator_;

  // Connection configuration.
  const std::unique_ptr<RemoteProxyServerConfig> config_;

  // Local enclave factory.
  std::function<StatusOr<std::shared_ptr<Client>>(
      MessageWriter *enclave_params,
      std::unique_ptr<Client::ExitCallProvider> exit_call_provider)>
      local_enclave_client_factory_;
};

}  // namespace primitives
}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_REMOTE_PROXY_SERVER_H_
