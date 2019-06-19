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

#ifndef ASYLO_PLATFORM_PRIMITIVES_TEST_SGX_TEST_BACKEND_H_
#define ASYLO_PLATFORM_PRIMITIVES_TEST_SGX_TEST_BACKEND_H_

#include "asylo/enclave.pb.h"  // IWYU pragma: export
#include "gflags/gflags.h"
#include "asylo/platform/primitives/sgx/untrusted_sgx.h"
#include "asylo/platform/primitives/test/test_backend.h"
#include "asylo/util/statusor.h"

DEFINE_string(enclave_binary, "",
              "Path to the SGX enclave binary to be loaded");

namespace asylo {
namespace primitives {
namespace test {

extern void *loader_config;

class SgxTestBackend : public TestBackend {
 public:
  SgxTestBackend();

  // Loads an instance of a SGX test enclave, aborting on failure.
  StatusOr<std::shared_ptr<Client>> LoadTestEnclave(
      const absl::string_view enclave_name,
      std::unique_ptr<Client::ExitCallProvider> exit_call_provider) override {
    LoadEnclaveConfig *config =
        reinterpret_cast<LoadEnclaveConfig *>(loader_config);
    return LoadEnclave<SgxBackend>(enclave_name, config->base_address,
                                   FLAGS_enclave_binary, config->enclave_size,
                                   config->config, config->debug,
                                   std::move(exit_call_provider));
  }

  // Configuration to load an instance of a SGX test enclave.
  struct LoadEnclaveConfig {
    void *base_address;
    absl::string_view enclave_path;
    size_t enclave_size;
    EnclaveConfig config;
    bool debug;
  };
};

}  // namespace test
}  // namespace primitives
}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_TEST_SGX_TEST_BACKEND_H_
