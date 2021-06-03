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
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "asylo/enclave.pb.h"
#include "asylo/util/logging.h"
#include "asylo/platform/host_call/exit_handler_constants.h"
#include "asylo/platform/primitives/extent.h"
#include "asylo/platform/primitives/primitive_status.h"
#include "asylo/platform/primitives/primitives.h"
#include "asylo/platform/primitives/remote/communicator.h"
#include "asylo/platform/primitives/remote/local_exit_calls.h"
#include "asylo/platform/primitives/remote/proxy_selectors.h"
#include "asylo/platform/primitives/untrusted_primitives.h"
#include "asylo/platform/primitives/util/dispatch_table.h"
#include "asylo/platform/primitives/util/exit_log.h"
#include "asylo/platform/primitives/util/message.h"
#include "asylo/platform/system_call/type_conversions/generated_types.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"
#include "asylo/util/thread.h"
#include "include/grpcpp/security/server_credentials.h"
#include "include/grpcpp/support/channel_arguments.h"

namespace asylo {
namespace primitives {

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
              invocation->status = Status{absl::StatusCode::kAlreadyExists,
                                          "Local enclave already loaded"};
              return;
            }
            // Retrieve enclave load config from the only input.
            if (invocation->reader.size() != 1) {
              invocation->status =
                  Status{absl::StatusCode::kFailedPrecondition,
                         "Remote connect must have 1 parameter only "
                         "(serialized EnclaveLoadConfig)"};
              return;
            }
            auto in_config = invocation->reader.next();
            EnclaveLoadConfig provisioned_load_config;
            if (!provisioned_load_config.ParseFromArray(in_config.data(),
                                                        in_config.size())) {
              invocation->status =
                  Status{absl::StatusCode::kInternal,
                         "Unable to parse Remote Config from input parameter"};
              return;
            }

            // Create local exit forwarder for the local enclave.
            auto exit_call_forwarder_result = LocalExitCallForwarder::Create(
                provisioned_load_config.exit_logging(), this);
            if (!exit_call_forwarder_result.ok()) {
              invocation->status = exit_call_forwarder_result.status();
              return;
            }

            // Create local enclave client by calling factory. Both factory and
            // exit call forwarder rely on provisioned load config.
            MessageWriter in;
            in.PushByReference(in_config);
            auto local_enclave_client_result = local_enclave_client_factory_(
                &in, std::move(exit_call_forwarder_result.value()));
            if (!local_enclave_client_result.ok()) {
              invocation->status = local_enclave_client_result.status();
              return;
            }
            local_enclave_client_ =
                std::move(local_enclave_client_result.value());
            return;
          }
          case kSelectorRemoteDisconnect:
            // Unload local client.
            local_enclave_client_.reset();
            invocation->status = absl::OkStatus();
            return;
          default:
            // Invoke the entry point handler of the local enclave.
            if (!local_enclave_client_) {
              invocation->status = Status(absl::StatusCode::kNotFound,
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
  return absl::OkStatus();
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

}  // namespace primitives
}  // namespace asylo
