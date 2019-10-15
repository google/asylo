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

#include "asylo/enclave.pb.h"
#include "asylo/platform/primitives/fortanix_edp/loader.pb.h"
#include "asylo/platform/primitives/fortanix_edp/untrusted_edp.h"
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
  const auto &edp_config = load_config.GetExtension(fortanix_edp_load_config);

  std::string enclave_path = edp_config.enclave_path();
  std::shared_ptr<primitives::Client> primitive_client;
  ASYLO_ASSIGN_OR_RETURN(
      primitive_client,
      LoadEnclave<FortanixEdpBackend>(enclave_name, enclave_path, enclave_config,
                                      absl::make_unique<DispatchTable>()));
  return std::move(primitive_client);
}

}  // namespace primitives
}  // namespace asylo
