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

#include "absl/status/status.h"
#include "asylo/enclave.pb.h"
#include "asylo/platform/primitives/sgx/loader.pb.h"
#include "asylo/platform/primitives/sgx/untrusted_sgx.h"
#include "asylo/platform/primitives/untrusted_primitives.h"
#include "asylo/platform/primitives/util/dispatch_table.h"
#include "asylo/platform/primitives/util/exit_log.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace primitives {

StatusOr<std::shared_ptr<Client>> LoadEnclave(
    const EnclaveLoadConfig &load_config) {
  const std::string enclave_name = load_config.name();
  const auto &enclave_config = load_config.config();

  const auto &sgx_config = load_config.GetExtension(sgx_load_config);

  std::shared_ptr<primitives::Client> primitive_client;
  void *base_address = nullptr;
  uint64_t enclave_size = 0;
  if (sgx_config.has_fork_config()) {
    SgxLoadConfig::ForkConfig fork_config = sgx_config.fork_config();
    base_address = reinterpret_cast<void *>(fork_config.base_address());
    enclave_size = fork_config.enclave_size();
  }

  bool debug = sgx_config.debug();
  bool is_embedded_enclave = sgx_config.has_embedded_enclave_config();
  bool is_file_enclave = sgx_config.has_file_enclave_config();
  auto exit_call_provider = absl::make_unique<LoggingDispatchTable>(
      /*enable_logging=*/load_config.exit_logging());

  if (is_embedded_enclave) {
    std::string section_name =
        sgx_config.embedded_enclave_config().section_name();
    ASYLO_ASSIGN_OR_RETURN(
        primitive_client,
        LoadEnclave<SgxEmbeddedBackend>(
            enclave_name, base_address, section_name, enclave_size,
            enclave_config, debug, std::move(exit_call_provider)));
  } else if (is_file_enclave) {
    std::string enclave_path = sgx_config.file_enclave_config().enclave_path();
    ASYLO_ASSIGN_OR_RETURN(
        primitive_client,
        LoadEnclave<SgxBackend>(enclave_name, base_address, enclave_path,
                                enclave_size, enclave_config, debug,
                                std::move(exit_call_provider)));
  } else {
    return absl::InvalidArgumentError("SGX enclave source not set");
  }
  return std::move(primitive_client);
}

}  // namespace primitives
}  // namespace asylo
