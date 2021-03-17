/*
 *
 * Copyright 2017 Asylo authors
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

#include "asylo/platform/primitives/remote/proxy_client.h"

#include <functional>
#include <memory>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "asylo/util/logging.h"
#include "asylo/platform/primitives/dlopen/loader.pb.h"
#include "asylo/platform/primitives/primitives.h"
#include "asylo/platform/primitives/remote/communicator.h"
#include "asylo/platform/primitives/remote/proxy_selectors.h"
#include "asylo/platform/primitives/sgx/exit_handlers.h"
#include "asylo/platform/primitives/sgx/loader.pb.h"
#include "asylo/platform/primitives/untrusted_primitives.h"
#include "asylo/platform/primitives/util/message.h"
#include "asylo/util/remote/remote_proxy_config.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace primitives {

RemoteEnclaveProxyClient::RemoteEnclaveProxyClient(
    const absl::string_view name, RemoteLoadConfig::LoaderCase loader_case,
    std::unique_ptr<RemoteProxyClientConfig> remote_proxy_config,
    std::unique_ptr<ExitCallProvider> exit_call_provider)
    : Client(name, std::move(exit_call_provider)),
      config_(std::move(remote_proxy_config)),
      communicator_(absl::make_unique<Communicator>(/*is_host=*/true)),
      loader_case_(loader_case) {}

RemoteEnclaveProxyClient::~RemoteEnclaveProxyClient() {
  if (IsClosed()) {
    return;
  }
  Destroy();
}

Status RemoteEnclaveProxyClient::Destroy() {
  if (IsClosed()) {
    return absl::OkStatus();
  }
  MessageReader disconnect_out;
  const auto status =
      EnclaveCall(kSelectorRemoteDisconnect, nullptr, &disconnect_out);
  LOG_IF(WARNING, !status.ok())
      << "EnclaveCall(kSelectorRemoteDisconnect) failed with status=" << status;
  communicator_->Disconnect();
  config_->RunFinalize();
  return absl::OkStatus();
}

Status RemoteEnclaveProxyClient::EnclaveCallInternal(uint64_t selector,
                                                     MessageWriter *in,
                                                     MessageReader *out) {
  if (IsClosed()) {
    return Status{absl::StatusCode::kFailedPrecondition,
                  "No connection to remote proxy server"};
  }

  Status status;
  // Both callbacks are dispatched to this_thread.
  communicator_->Invoke(
      selector,
      [in](Communicator::Invocation *invocation) {
        if (in) {
          invocation->writer = std::move(*in);
        }
      },
      [&status, out](std::unique_ptr<Communicator::Invocation> invocation) {
        if (!invocation->status.ok()) {
          status = invocation->status;
        }
        if (status.ok()) {
          *out = std::move(invocation->reader);
        }
      });
  return status;
}

bool RemoteEnclaveProxyClient::IsClosed() const {
  return !communicator_->IsConnected();
}

Status RemoteEnclaveProxyClient::Connect(const EnclaveLoadConfig &load_config) {
  if (!IsClosed()) {
    return Status{absl::StatusCode::kAlreadyExists,
                  "Client is already connected to server"};
  }

  // Make a copy of load configuration, because enclave_path may need to change:
  // for example, if the remote proxy is going to run on a different machine,
  // enclave_path would need to refer to a copy of the enclave binary
  // provisioned there.
  EnclaveLoadConfig provisioned_load_config = load_config;

  // Provision remote enclave proxy process to load the Enclave.
  if (!provisioned_load_config.HasExtension(remote_load_config)) {
    return Status{absl::StatusCode::kAlreadyExists,
                  absl::StrCat("No SGX extension in load config found, config=",
                               provisioned_load_config.ShortDebugString())};
  }

  std::string *enclave_path;
  switch (
      provisioned_load_config.GetExtension(remote_load_config).loader_case()) {
    case RemoteLoadConfig::kSgxLoadConfig:
      if (!provisioned_load_config.GetExtension(remote_load_config)
               .sgx_load_config()
               .has_file_enclave_config()) {
        return Status{absl::StatusCode::kAlreadyExists,
                      absl::StrCat("No file_enclave_config in sgx extension in "
                                   "load config found, config=",
                                   load_config.ShortDebugString())};
      }
      enclave_path =
          provisioned_load_config.MutableExtension(remote_load_config)
              ->mutable_sgx_load_config()
              ->mutable_file_enclave_config()
              ->mutable_enclave_path();
      break;
    case RemoteLoadConfig::kDlopenLoadConfig:
      enclave_path =
          provisioned_load_config.MutableExtension(remote_load_config)
              ->mutable_dlopen_load_config()
              ->mutable_enclave_path();
      break;
    default:
      return Status{
          absl::StatusCode::kAlreadyExists,
          absl::StrCat("No SGX extension in load config found, config=",
                       provisioned_load_config.ShortDebugString())};
  }
  ASYLO_ASSIGN_OR_RETURN(
      *enclave_path,
      config_->RunProvision(communicator()->server_port(), *enclave_path));

  // Receive address of the target server, which client will need to connect to.
  const std::string target_address = communicator_->WaitForEndPointAddress();

  // Establish connection to the target server.
  ASYLO_RETURN_IF_ERROR(communicator_->Connect(*config_, target_address));

  // Set up dispatch of ExitCalls calls from remote Enclave server.
  communicator_->set_handler(
      [this](std::unique_ptr<Communicator::Invocation> invocation) {
        if (invocation->selector >= kSelectorRemote &&
            invocation->selector < kSelectorUser) {
          invocation->status = Status{absl::StatusCode::kFailedPrecondition,
                                      "Invalid selector received from proxy"};
          return;
        }
        if (!exit_call_provider()) {
          invocation->status = Status{absl::StatusCode::kFailedPrecondition,
                                      "Exit call provider not set yet."};
          return;
        }
        invocation->status = exit_call_provider()->InvokeExitHandler(
            invocation->selector, &invocation->reader, &invocation->writer,
            this);
      });

  std::string buffer;
  if (!provisioned_load_config.SerializeToString(&buffer)) {
    return Status(absl::StatusCode::kInternal,
                  "Unable to serialize Remote Config to string");
  }

  MessageWriter load_in;
  load_in.PushByCopy(Extent(buffer.c_str(), buffer.size()));

  // Request proxy server to load the enclave.
  MessageReader load_out;
  ASYLO_RETURN_IF_ERROR(
      EnclaveCall(kSelectorRemoteConnect, &load_in, &load_out));

  // Ready to forward EnclaveCalls to remote server and receive ExitCalls back.
  return absl::OkStatus();
}

Status RemoteEnclaveProxyClient::StartServer() {
  return communicator()->StartServer(config_->server_creds());
}

StatusOr<std::shared_ptr<RemoteEnclaveProxyClient>>
RemoteEnclaveProxyClient::Create(
    const absl::string_view enclave_name,
    std::unique_ptr<RemoteProxyClientConfig> remote_proxy_config,
    std::unique_ptr<ExitCallProvider> exit_call_provider,
    RemoteLoadConfig::LoaderCase loader_case) {
  std::shared_ptr<RemoteEnclaveProxyClient> client(new RemoteEnclaveProxyClient(
      enclave_name, loader_case, std::move(remote_proxy_config),
      std::move(exit_call_provider)));
  ASYLO_RETURN_IF_ERROR(client->RegisterExitHandlers());

  // Start host server.
  ASYLO_RETURN_IF_ERROR(
      client->communicator()->StartServer(client->config_->server_creds()));

  return client;
}

Status RemoteEnclaveProxyClient::RegisterExitHandlers() {
  if (loader_case_ == RemoteLoadConfig::LoaderCase::kSgxLoadConfig) {
    ASYLO_RETURN_IF_ERROR(RegisterSgxExitHandlers(exit_call_provider()));
  }
  return absl::OkStatus();
}

}  // namespace primitives
}  // namespace asylo
