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

#ifndef ASYLO_PLATFORM_PRIMITIVES_REMOTE_PROXY_CLIENT_H_
#define ASYLO_PLATFORM_PRIMITIVES_REMOTE_PROXY_CLIENT_H_

#include <cstdint>
#include <functional>
#include <memory>
#include <string>

#include "absl/container/flat_hash_map.h"
#include "absl/strings/string_view.h"
#include "asylo/enclave.pb.h"
#include "asylo/platform/primitives/extent.h"
#include "asylo/platform/primitives/primitive_status.h"
#include "asylo/platform/primitives/remote/communicator.h"
#include "asylo/platform/primitives/remote/metrics/clients/opencensus_client.h"
#include "asylo/platform/primitives/untrusted_primitives.h"
#include "asylo/platform/primitives/util/message.h"
#include "asylo/util/remote/remote_loader.pb.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

// Remote Enclave Proxy Client
// ===========================
//
// The proxy client provides a framework for accessing an enclave loaded
// remotely. To establish connection with proxy server, the caller must assign
// or create a separate process from the host that would load the enclave, and
// then in the host process set up the proxy client:
//
//     std::shared_ptr<RemoteEnclaveProxyClient> client;
//     ASYLO_ASSIGN_OR_RETURN(client, RemoteEnclaveProxyClient::Create(
//                                        ::grpc::InsecureChannelCredentials(),
//                                        ::grpc::InsecureServerCredentials()),
//                                        [...]{...});  // finalization callback
//
//     // ... Assign or create a remote process, providing it with host address
//     // and client->communicator()->server_port(). That process would create
//     // an instance of RemoteEnclaveProxyServer.
//
//     // Connect the client to the RemoteEnclaveProxyServer instance.
//     ASYLO_RETURN_IF_ERROR(client->Connect());
//
// The host process owns RemoteEnclaveProxyClient and forwards all
// communications using Invoke() API from Comminicator. Both host and target
// processes create instances of Communicator; the target process owns only one
// instance, while the host process has as many instances as there are enclaves
// it connects to.

namespace asylo {
namespace primitives {

// Proxy backend implementation of Client provides the host process with
// the set of untrusted primitives, allowing the host code to run even though
// the enclave is located outside of the host process. Conversely,
// RemoteEnclaveProxyServer implements trusted primitives facing the loaded
// enclave, so that the enclave can act even though it is not loaded into the
// host process.
//
// RemoteEnclaveProxyClient-RemoteEnclaveProxyServer pair encapsulates all
// communications between untrusted primitives in the host process and trusted
// primitives in the target process.
class RemoteEnclaveProxyClient : public Client {
 public:
  // Prepares RemoteEnclaveProxyClient to connect to the remote process
  // running RemoteEnclaveProxyServer. Returned client is not yet connected;
  // the caller must locate or launch remote process to connect to, and then
  // call client->Connect(...).
  static StatusOr<std::shared_ptr<RemoteEnclaveProxyClient>> Create(
      const absl::string_view enclave_name,
      std::unique_ptr<RemoteProxyClientConfig> remote_proxy_config,
      std::unique_ptr<ExitCallProvider> exit_call_provider,
      RemoteLoadConfig::LoaderCase loader_case);

  ~RemoteEnclaveProxyClient() override;
  Status Destroy() override;
  Status EnclaveCallInternal(uint64_t selector, MessageWriter *in,
                             MessageReader *out) override;
  bool IsClosed() const override;

  // Establishes connection to the remote proxy server, running on another
  // process.
  Status Connect(const EnclaveLoadConfig &load_config);

  ASYLO_MUST_USE_RESULT Status RegisterExitHandlers() override;

  Communicator *communicator() const { return communicator_.get(); }

 private:
  // Constructor is private, so that it can only be called by the Create()
  // factory method.
  RemoteEnclaveProxyClient(
      const absl::string_view name, RemoteLoadConfig::LoaderCase loader_case,
      std::unique_ptr<RemoteProxyClientConfig> config,
      std::unique_ptr<ExitCallProvider> exit_call_provider);

  Status StartServer();

  // Configuration of RemoteEnclave
  std::unique_ptr<RemoteProxyClientConfig> config_;

  // Host-side instance of Communicator.
  const std::unique_ptr<Communicator> communicator_;

  // Loader type of the RemoteLoadConfig, eg. kSgxLoadConfig, kDlopenLoadConfig.
  const RemoteLoadConfig::LoaderCase loader_case_;
};

}  // namespace primitives
}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_REMOTE_PROXY_CLIENT_H_
