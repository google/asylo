/*
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
 */

#ifndef ASYLO_PLATFORM_PRIMITIVES_FORTANIX_EDP_UNTRUSTED_EDP_H_
#define ASYLO_PLATFORM_PRIMITIVES_FORTANIX_EDP_UNTRUSTED_EDP_H_

#include <cstdint>
#include <memory>
#include <string>

#include "absl/container/flat_hash_map.h"
#include "asylo/enclave.pb.h"  // IWYU pragma: export
#include "asylo/platform/primitives/untrusted_primitives.h"
#include "asylo/platform/primitives/util/message.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace primitives {

// Fortanix EDP implementation of the generic "EnclaveBackend" concept.
struct FortanixEdpBackend {
  // Loads an enclave from an SGXS file system path for the untrusted
  // application. Returns a client to the loaded enclave or an error status on
  // failure.
  static StatusOr<std::shared_ptr<Client>> Load(
      const absl::string_view enclave_name,
      const std::string &enclave_path,
      const EnclaveConfig &config,
      std::unique_ptr<Client::ExitCallProvider> exit_call_provider);
};

// Fortanix EDP implementation of Client.
class FortanixEdpEnclaveClient : public Client {
 public:
  ~FortanixEdpEnclaveClient() override;
  Status Destroy() override;
  Status EnclaveCallInternal(uint64_t selector, MessageWriter *input,
                             MessageReader *output) override;
  bool IsClosed() const override;

 private:
  // Allow the loader to create client instances directly.
  friend FortanixEdpBackend;

  // Constructor.
  FortanixEdpEnclaveClient(absl::string_view name,
                           std::unique_ptr<ExitCallProvider> exit_call_provider)
      : Client(name, std::move(exit_call_provider)), enclave_(nullptr) {}

  // pointer to the Rust object holding the enclave state
  void* enclave_;
};

}  // namespace primitives
}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_FORTANIX_EDP_UNTRUSTED_EDP_H_
