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

#include "asylo/test/util/fake_enclave_loader.h"

namespace asylo {

FakeEnclaveLoader::FakeEnclaveLoader(
    std::unique_ptr<EnclaveClient> destination_client)
    : client_(std::move(destination_client)) {}

StatusOr<std::unique_ptr<EnclaveClient>> FakeEnclaveLoader::LoadEnclave(
    absl::string_view name, void *base_address, const size_t enclave_size,
    const EnclaveConfig &config) const {
  return std::move(client_);
}

}  // namespace asylo
