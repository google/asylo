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

#include <memory>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "asylo/enclave.pb.h"
#include "asylo/util/logging.h"
#include "asylo/platform/primitives/dlopen/loader.pb.h"
#include "asylo/platform/primitives/dlopen/untrusted_dlopen.h"
#include "asylo/platform/primitives/extent.h"
#include "asylo/platform/primitives/primitives.h"
#include "asylo/platform/primitives/remote/util/remote_proxy_lib.h"
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

  const std::string enclave_name = load_config.name();
  if (enclave_name.empty()) {
    return absl::InvalidArgumentError("EnclaveLoadConfig.name was empty");
  }

  // Parse and verify the DlopenLoadConfig
  if (remote_config.loader_case() !=
      RemoteLoadConfig::LoaderCase::kDlopenLoadConfig) {
    return absl::InvalidArgumentError(
        "Expected DlopenLoadConfig held by RemoteLoadConfig.");
  }
  const auto &dlopen_config = remote_config.dlopen_load_config();

  const std::string enclave_path = dlopen_config.enclave_path();
  if (enclave_path.empty()) {
    return absl::InvalidArgumentError(
        "DlopenLoadConfig.enclave_path was empty");
  }

  // Load dlopen()ed enclave to be proxied.
  return LoadEnclave<DlopenBackend>(enclave_name, enclave_path,
                                    std::move(exit_call_provider));
}

}  // namespace primitives
}  // namespace asylo
