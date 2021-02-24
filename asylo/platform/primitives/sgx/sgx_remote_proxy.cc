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

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "asylo/enclave.pb.h"
#include "asylo/util/logging.h"
#include "asylo/platform/primitives/extent.h"
#include "asylo/platform/primitives/primitives.h"
#include "asylo/platform/primitives/remote/util/remote_proxy_lib.h"
#include "asylo/platform/primitives/sgx/loader.pb.h"
#include "asylo/platform/primitives/sgx/untrusted_sgx.h"
#include "asylo/platform/primitives/untrusted_primitives.h"
#include "asylo/platform/primitives/util/message.h"
#include "asylo/util/error_codes.h"
#include "asylo/util/remote/remote_loader.pb.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace primitives {

StatusOr<std::shared_ptr<Client>> LocalEnclaveFactory::Get(
    MessageWriter *enclave_params,
    std::unique_ptr<Client::ExitCallProvider> exit_call_provider) {
  EnclaveLoadConfig load_config;
  ASYLO_ASSIGN_OR_RETURN(load_config, ParseEnclaveLoadConfig(enclave_params));

  // Parse and verify the EnclaveLoadConfig
  if (!load_config.HasExtension(remote_load_config)) {
    return absl::InvalidArgumentError("Expected RemoteLoadConfig.");
  }
  const auto &remote_config = load_config.GetExtension(remote_load_config);

  const auto &config = load_config.config();

  const std::string enclave_name = load_config.name();
  if (enclave_name.empty()) {
    return absl::InvalidArgumentError("EnclaveLoadConfig.name was empty");
  }

  // Parse and verify the SgxLoadConfig
  if (remote_config.loader_case() !=
      RemoteLoadConfig::LoaderCase::kSgxLoadConfig) {
    return absl::InvalidArgumentError(
        "Expected SgxLoadConfig held by RemoteLoadConfig.");
  }
  const auto &sgx_config = remote_config.sgx_load_config();

  if (sgx_config.has_embedded_enclave_config()) {
    return absl::InvalidArgumentError(
        "Expected no EmbededEnclaveConfig: RemoteBackend does not "
        "support embedded enclaves.");
  }

  const std::string enclave_path =
      sgx_config.file_enclave_config().enclave_path();
  if (enclave_path.empty()) {
    return absl::InvalidArgumentError(
        "SgxLoadConfig.FileConfig.enclave_path was empty");
  }

  // Defaults to false.
  const bool debug = sgx_config.debug();

  // Parse and verify the SgxLoadConfig.ForkConfig
  const auto &fork_config = sgx_config.fork_config();

  void *const base_address =
      reinterpret_cast<void *>(fork_config.base_address());
  const size_t enclave_size = fork_config.enclave_size();

  if (base_address != nullptr && enclave_size == 0) {
    return absl::InvalidArgumentError(
        "SgxLoadConfig.ForkConfig.base_address was set"
        " but SgxLoadConfig.ForkConfig.enclave_size was 0");
  }
  if (enclave_size > 0 && base_address == nullptr) {
    return absl::InvalidArgumentError(
        "SgxLoadConfig.ForkConfig.enclave_size was set"
        " but SgxLoadConfig.ForkConfig.base_address was null");
  }

  return LoadEnclave<SgxBackend>(enclave_name, base_address, enclave_path,
                                 enclave_size, config, debug,
                                 std::move(exit_call_provider));
}

}  // namespace primitives
}  // namespace asylo
