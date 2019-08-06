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

#include "asylo/platform/arch/sgx/untrusted/sgx_client.h"

#include <cstdint>
#include <string>

#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "asylo/util/logging.h"
#include "asylo/platform/arch/sgx/untrusted/generated_bridge_u.h"
#include "asylo/platform/common/bridge_functions.h"
#include "asylo/platform/common/bridge_types.h"
#include "asylo/platform/primitives/sgx/sgx_error_space.h"
#include "asylo/platform/primitives/sgx/untrusted_sgx.h"
#include "asylo/platform/primitives/untrusted_primitives.h"
#include "asylo/platform/primitives/util/dispatch_table.h"
#include "asylo/util/elf_reader.h"
#include "asylo/util/file_mapping.h"
#include "asylo/util/posix_error_space.h"
#include "asylo/util/status_macros.h"

namespace asylo {


StatusOr<std::unique_ptr<EnclaveClient>> SgxLoader::LoadEnclave(
    const std::string &name, void *base_address, const size_t enclave_size,
    const EnclaveConfig &config) const {
  auto client = absl::make_unique<SgxClient>(name);

  ASYLO_ASSIGN_OR_RETURN(
      client->primitive_client_,
      primitives::LoadEnclave<primitives::SgxBackend>(
          name, base_address, enclave_path_, enclave_size, config, debug_,
          absl::make_unique<primitives::DispatchTable>()));

  return std::unique_ptr<EnclaveClient>(std::move(client));
}

StatusOr<std::unique_ptr<EnclaveLoader>> SgxLoader::Copy() const {
  std::unique_ptr<SgxLoader> loader(new SgxLoader(*this));
  if (!loader) {
    return Status(error::GoogleError::INTERNAL, "Failed to create self loader");
  }
  return std::unique_ptr<EnclaveLoader>(loader.release());
}

StatusOr<std::unique_ptr<EnclaveClient>> SgxEmbeddedLoader::LoadEnclave(
    const std::string &name, void *base_address, const size_t enclave_size,
    const EnclaveConfig &config) const {
  auto client = absl::make_unique<SgxClient>(name);

  ASYLO_ASSIGN_OR_RETURN(
      client->primitive_client_,
      primitives::LoadEnclave<primitives::SgxEmbeddedBackend>(
          name, base_address, section_name_, enclave_size, config, debug_,
          absl::make_unique<primitives::DispatchTable>()));

  return std::unique_ptr<EnclaveClient>(std::move(client));
}

StatusOr<std::unique_ptr<EnclaveLoader>> SgxEmbeddedLoader::Copy() const {
  std::unique_ptr<SgxEmbeddedLoader> loader(new SgxEmbeddedLoader(*this));
  if (!loader) {
    return Status(error::GoogleError::INTERNAL, "Failed to create self loader");
  }
  return std::unique_ptr<EnclaveLoader>(loader.release());
}
}  //  namespace asylo
