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

#ifndef ASYLO_TEST_UTIL_FAKE_ENCLAVE_LOADER_H_
#define ASYLO_TEST_UTIL_FAKE_ENCLAVE_LOADER_H_

#include <memory>

#include "absl/strings/string_view.h"
#include "asylo/client.h"
#include "asylo/enclave.pb.h"
#include "asylo/enclave_manager.h"
#include "asylo/util/statusor.h"

namespace asylo {

/// A fake `EnclaveLoader` that loads a given `EnclaveClient`.
class FakeEnclaveLoader : public EnclaveLoader {
 public:
  /// Creates a `FakeEnclaveLoader` that will load a given client.
  ///
  /// \param client The `EnclaveClient` to be loaded.
  explicit FakeEnclaveLoader(std::unique_ptr<EnclaveClient> client);

 private:
  // From EnclaveLoader.
  StatusOr<std::unique_ptr<EnclaveClient>> LoadEnclave(
      absl::string_view name, void *base_address, const size_t enclave_size,
      const EnclaveConfig &config) const override;

  EnclaveLoadConfig GetEnclaveLoadConfig() const override {
    EnclaveLoadConfig loader_config;
    return loader_config;
  }

  // The client to be loaded.
  mutable std::unique_ptr<EnclaveClient> client_;
};

}  // namespace asylo

#endif  // ASYLO_TEST_UTIL_FAKE_ENCLAVE_LOADER_H_
