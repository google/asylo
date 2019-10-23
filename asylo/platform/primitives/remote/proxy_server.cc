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

#include "asylo/platform/primitives/remote/proxy_server.h"

#include <cstdint>
#include <memory>

#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "asylo/util/logging.h"
#include "asylo/platform/primitives/extent.h"
#include "asylo/platform/primitives/primitive_status.h"
#include "asylo/platform/primitives/primitives.h"
#include "asylo/platform/primitives/remote/communicator.h"
#include "asylo/platform/primitives/remote/proxy_selectors.h"
#include "asylo/platform/primitives/untrusted_primitives.h"
#include "asylo/platform/primitives/util/message.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"
#include "asylo/util/thread.h"
#include "include/grpcpp/security/server_credentials.h"
#include "include/grpcpp/support/channel_arguments.h"

namespace asylo {
namespace primitives {

namespace {

// Remote backend specific implementation of ExitCallProvider, which sole
// purpose is to forward exit call invoked by the enclave loaded by proxy server
// over the remote connector to the untrusted host. Registration of exit
// handlers with this provider is not allowed: actual handler registration
// happens on the host and is not forwarded to the server. The server accepts
// and forwards any exit call; if `untrusted_selector` is not registered by the
// host, error status will be returned from there.
class LocalExitCallForwarder : public Client::ExitCallProvider {
 public:
  explicit LocalExitCallForwarder(const RemoteEnclaveProxyServer *server)
      : server_(CHECK_NOTNULL(server)) {}

  Status RegisterExitHandler(uint64_t untrusted_selector,
                             const ExitHandler &handler) override {
    return Status{error::GoogleError::INTERNAL,
                  "RegisterExitHandler should never be called by "
                  "RemoteEnclaveProxyServer"};
  };

  Status InvokeExitHandler(uint64_t untrusted_selector, MessageReader *input,
                           MessageWriter *output, Client *client) override {
    return server_->ExitCallForwarder(untrusted_selector, input, output,
                                      client);
  };

 private:
  const RemoteEnclaveProxyServer *const server_;
};

}  // namespace

StatusOr<std::unique_ptr<RemoteEnclaveProxyServer>>
RemoteEnclaveProxyServer::Create(
    std::unique_ptr<RemoteProxyServerConfig> remote_proxy_config,
    std::function<StatusOr<std::shared_ptr<Client>>(
        MessageWriter *enclave_params,
        std::unique_ptr<Client::ExitCallProvider> exit_call_provider)>
        local_enclave_client_factory) {
  // make_unique cannot be used, because constructor is private.
  auto server = absl::WrapUnique(
      new RemoteEnclaveProxyServer(std::move(remote_proxy_config)));
  ASYLO_RETURN_IF_ERROR(server->Start(std::move(local_enclave_client_factory)));

  // Loaded successfully. Wait() will create and run server until disconnected.
  return server;
}

void RemoteEnclaveProxyServer::Kill(int signum) {
  // For testing purposes, all signals trigger disconnect.
  if (communicator_) {
    communicator_->Disconnect();
  }
}

void RemoteEnclaveProxyServer::Wait() {
  // Runs Rpc Loop until disconnected.
  communicator_->ServerRpcLoop();
}

RemoteEnclaveProxyServer::RemoteEnclaveProxyServer(
    std::unique_ptr<RemoteProxyServerConfig> config)
    : communicator_(absl::make_unique<Communicator>(/*is_host=*/false)),
      config_(std::move(config)) {}

Status RemoteEnclaveProxyServer::Start(
    std::function<StatusOr<std::shared_ptr<Client>>(
        MessageWriter *enclave_params,
        std::unique_ptr<Client::ExitCallProvider> exit_call_provider)>
        local_enclave_client_factory) {
  // Create target server.
  ASYLO_RETURN_IF_ERROR(communicator_->StartServer(config_->server_creds()));

  // Establish connection to the host server.
  ASYLO_RETURN_IF_ERROR(
      communicator_->Connect(*config_, config_->host_address()));

  // Communicate target_address back to the host.
  communicator_->SendEndPointAddress(absl::StrCat(
      config_->local_address(), ":", communicator_->server_port()));

  // Attach dispatch routine.
  local_enclave_client_factory_ = std::move(local_enclave_client_factory);
  communicator_->set_handler(
      [this](std::unique_ptr<Communicator::Invocation> invocation) {
        // Handle remote backend specific selectors.
        switch (invocation->selector) {
          case kSelectorRemoteConnect: {
            // Load local client (exit calls possible during enclave loading).
            if (local_enclave_client_) {
              invocation->status = Status(error::GoogleError::ALREADY_EXISTS,
                                          "Local enclave already loaded");
              return;
            }
            MessageWriter in;
            while (invocation->reader.hasNext()) {
              in.PushByReference(invocation->reader.next());
            }
            auto local_enclave_client_result = local_enclave_client_factory_(
                &in, MakeLocalExitCallForwarder());
            invocation->status = local_enclave_client_result.status();
            if (invocation->status.ok()) {
              local_enclave_client_ =
                  std::move(local_enclave_client_result.ValueOrDie());
            }
            return;
          }
          case kSelectorRemoteDisconnect:
            // Unload local client.
            local_enclave_client_.reset();
            invocation->status = Status::OkStatus();
            return;
          default:
            // Invoke the entry point handler of the local enclave.
            if (!local_enclave_client_) {
              invocation->status = Status(error::GoogleError::NOT_FOUND,
                                          "Local enclave not loaded");
              return;
            }
            // Serialize invocation->params into MessageWriter for EnclaveCall.
            MessageWriter in;
            while (invocation->reader.hasNext()) {
              in.PushByReference(invocation->reader.next());
            }
            MessageReader out;
            invocation->status = local_enclave_client_->EnclaveCall(
                invocation->selector, &in, &out);
            if (invocation->status.ok()) {
              while (out.hasNext()) {
                invocation->writer.PushByCopy(out.next());
              }
            }
        }
      });

  // Ready to run ServerRpcLoop of the target communicator.
  return Status::OkStatus();
}

Status RemoteEnclaveProxyServer::ExitCallForwarder(uint64_t exit_call_selector,
                                                   MessageReader *input,
                                                   MessageWriter *output,
                                                   Client *client) const {
  // Invoke the exit handler, passing the registered handler.
  Status status;
  communicator_->Invoke(
      exit_call_selector,
      [input](Communicator::Invocation *invocation) {
        if (input) {
          while (input->hasNext()) {
            invocation->writer.PushByReference(input->next());
          }
        }
      },
      [&status, output](std::unique_ptr<Communicator::Invocation> invocation) {
        if (!invocation->status.ok()) {
          status = invocation->status;
        }
        if (status.ok()) {
          while (invocation->reader.hasNext()) {
            output->PushByCopy(invocation->reader.next());
          }
        }
      });
  return status;
}

std::unique_ptr<Client::ExitCallProvider>
RemoteEnclaveProxyServer::MakeLocalExitCallForwarder() const {
  return absl::make_unique<LocalExitCallForwarder>(this);
}

}  // namespace primitives
}  // namespace asylo
