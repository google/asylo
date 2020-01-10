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

#include "asylo/platform/primitives/enclave_loader.h"

#include "absl/memory/memory.h"
#include "asylo/enclave.pb.h"
#include "asylo/platform/primitives/remote/proxy_client.h"
#include "asylo/platform/primitives/untrusted_primitives.h"
#include "asylo/platform/primitives/util/dispatch_table.h"
#include "asylo/platform/primitives/util/exit_log.h"
#include "asylo/util/remote/remote_loader.pb.h"
#include "asylo/util/remote/remote_proxy_config.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace primitives {

StatusOr<std::shared_ptr<Client>> LoadEnclave(
    const EnclaveLoadConfig &load_config) {
  const std::string &enclave_name = load_config.name();
  const auto &remote_config = load_config.GetExtension(remote_load_config);

  auto client_config =
      absl::WrapUnique(reinterpret_cast<RemoteProxyClientConfig *>(
          remote_config.remote_proxy_config()));

  std::shared_ptr<primitives::RemoteEnclaveProxyClient> primitive_client;
  ASYLO_ASSIGN_OR_RETURN(primitive_client,
                         primitives::RemoteEnclaveProxyClient::Create(
                             enclave_name, std::move(client_config),
                             absl::make_unique<LoggingDispatchTable>(
                                 /*enable_logging=*/load_config.exit_logging()),
                             remote_config.loader_case()));
  ASYLO_RETURN_IF_ERROR(primitive_client->Connect(load_config));
  return std::move(primitive_client);
}

}  // namespace primitives
}  // namespace asylo
