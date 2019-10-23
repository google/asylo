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

#include "asylo/platform/primitives/test/remote_test_backend.h"

#include <memory>
#include <string>

#include "absl/flags/flag.h"
#include "absl/strings/str_cat.h"
#include "asylo/enclave.pb.h"
#include "asylo/util/logging.h"
#include "asylo/platform/primitives/remote/proxy_client.h"
#include "asylo/platform/primitives/test/test_backend.h"
#include "asylo/platform/primitives/untrusted_primitives.h"
#include "asylo/platform/primitives/util/dispatch_table.h"
#include "asylo/util/path.h"
#include "asylo/util/remote/provision.h"
#include "asylo/util/remote/remote_loader.pb.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"
#include "include/grpcpp/security/credentials.h"
#include "include/grpcpp/security/server_credentials.h"
#include "include/grpcpp/support/channel_arguments.h"

ABSL_FLAG(std::string, enclave_binary, "",
          "Path to the enclave binary to be loaded remotely");

namespace asylo {
namespace primitives {
namespace test {

void RemoteTestBackend::PrepareLoaderParameters(
    EnclaveLoadConfig *load_config) const {
  const std::string enclave_binary = absl::GetFlag(FLAGS_enclave_binary);

  RemoteLoadConfig *remote_config =
      load_config->MutableExtension(remote_load_config);

  PrepareBackendLoaderParameters(remote_config, enclave_binary);
}

StatusOr<std::shared_ptr<Client>> RemoteTestBackend::LoadTestEnclave(
    const absl::string_view enclave_name,
    std::unique_ptr<Client::ExitCallProvider> exit_call_provider) {
  std::unique_ptr<RemoteProxyClientConfig> config;
  ASYLO_ASSIGN_OR_RETURN(config, RemoteProxyClientConfig::DefaultsWithProvision(
                                     RemoteProvision::Instantiate()));

  EnclaveLoadConfig load_config;
  PrepareLoaderParameters(&load_config);
  load_config.set_name(enclave_name.data(), enclave_name.size());
  RemoteLoadConfig *remote_config =
      load_config.MutableExtension(asylo::remote_load_config);

  std::shared_ptr<RemoteEnclaveProxyClient> client;
  ASYLO_ASSIGN_OR_RETURN(
      client, RemoteEnclaveProxyClient::Create(enclave_name, std::move(config),
                                               std::move(exit_call_provider),
                                               remote_config->loader_case()));

  // Connect the client to the remote Enclave server running remotely.
  ASYLO_RETURN_IF_ERROR(client->Connect(load_config));

  // Client is ready, return it.
  return client;
}

}  // namespace test
}  // namespace primitives
}  // namespace asylo
