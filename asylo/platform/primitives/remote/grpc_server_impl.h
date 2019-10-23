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

#ifndef ASYLO_PLATFORM_PRIMITIVES_REMOTE_GRPC_SERVER_IMPL_H_
#define ASYLO_PLATFORM_PRIMITIVES_REMOTE_GRPC_SERVER_IMPL_H_

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <utility>

#include "absl/strings/string_view.h"
#include "asylo/util/logging.h"
#include "asylo/platform/primitives/remote/communicator.h"
#include "asylo/platform/primitives/remote/grpc_service.grpc.pb.h"
#include "asylo/platform/primitives/remote/metrics/proc_system_service.h"
#include "asylo/util/asylo_macros.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"
#include "asylo/util/thread.h"
#include "include/grpcpp/impl/codegen/completion_queue.h"
#include "include/grpcpp/security/server_credentials.h"
#include "include/grpcpp/server.h"

namespace asylo {
namespace primitives {

class Communicator::ServiceImpl
    : public CommunicatorService::AsyncService {
 public:
  static StatusOr<std::unique_ptr<ServiceImpl>> Create(
      int requested_port,  // If 0, port is assigned by gRPC.
      const std::shared_ptr<::grpc::ServerCredentials> &creds,
      Communicator *communicator);

  void StartInvocation(CommunicationMessagePtr wrapped_message);

  // Main loop that retrieves asynchronous RPC calls from completion queue and
  // dispatches them for processesing. It is expected that the host side of
  // the Communicator will create a dedicated thread to run ServerRpcLoop, while
  // the host side runs ServerRpcLoop on the main thread; as a result,
  // the host side will terminate only after the ServerRpcLoop receives and
  // processes an RPC with a disconnect request.
  void ServerRpcLoop();

  // Shuts down server and completion queue, joins ServerRpcLoop thread (thus
  // waiting for ServerRpcLoop to terminate). When WaitForDisconnect returns,
  // it is safe to destruct ServiceImpl instance.
  void WaitForDisconnect();

  // Waits for end point address to be received from the counterpart calling
  // SendEndPointAddress. Not mandatory, expected to be used only when gRPC
  // server port is assigned dynamically and not known to the counterpart.
  std::string WaitForEndPointAddress();

  ~ServiceImpl() override;

  int server_port() const { return server_port_; }
  void set_handler(
      std::function<void(std::unique_ptr<Invocation> invocation)> handler) {
    handler_ = std::move(handler);
  }

  ServiceImpl(const ServiceImpl &other) = delete;
  ServiceImpl &operator=(const ServiceImpl &other) = delete;

 private:
  // Server-side instance base of an RPC call.
  class RpcInstance;

  // Classes for all supported RPC calls.
  class CommunicationRpcInstance;
  class DisconnectRpcInstance;
  class DisposeOfThreadRpcInstance;
  class EndPointAddressRpcInstance;

  // Constructor is called by Create() factory only.
  explicit ServiceImpl(Communicator *communicator)
      : end_point_address_callback_(absl::optional<address_callback>()),
        communicator_(CHECK_NOTNULL(communicator)),
        address_state_(absl::optional<std::string>()) {}

  void RecordEndPointAddress(absl::string_view address);

  // Request handler provided by the caller.
  std::function<void(std::unique_ptr<Invocation> invocation)> handler_;

  // Support for end point address notification.
  typedef std::function<void(absl::string_view address)> address_callback;
  MutexGuarded<absl::optional<address_callback>> end_point_address_callback_;

  // ProcSystemService for serving enclave metrics.
  std::unique_ptr<ProcSystemServiceImpl> proc_system_service_;

  // Actual port gRPC server above is listening to, once started.
  // Set only once by CreateServer() and never changes after that.
  int server_port_ = 0;
  std::unique_ptr<::grpc::ServerCompletionQueue> completion_queue_;
  std::unique_ptr<::grpc::Server> server_;
  std::unique_ptr<Thread> rpc_thread_;
  Communicator *const communicator_;

  MutexGuarded<absl::optional<std::string>> address_state_;
};

}  // namespace primitives
}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_REMOTE_GRPC_SERVER_IMPL_H_
