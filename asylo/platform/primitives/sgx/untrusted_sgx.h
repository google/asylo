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

#ifndef ASYLO_PLATFORM_PRIMITIVES_SGX_UNTRUSTED_SGX_H_
#define ASYLO_PLATFORM_PRIMITIVES_SGX_UNTRUSTED_SGX_H_

#include <string>

#include "asylo/enclave.pb.h"  // IWYU pragma: export
#include "asylo/platform/primitives/untrusted_primitives.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace primitives {

// SGX implementation of the generic "EnclaveBackend" concept.
struct SgxBackend {
  // Loads an SGX enclave and returns a client to the loaded enclave or an
  // error status on failure.
  static StatusOr<std::shared_ptr<EnclaveClient>> Load(
      const std::string &name,
      void *base_address,
      size_t enclave_size,
      const EnclaveConfig &config,
      std::unique_ptr<EnclaveClient::ExitCallProvider> exit_call_provider);
};

// SGX implementation of EnclaveClient.
class SgxEnclaveClient : public EnclaveClient {
 public:
  ~SgxEnclaveClient() override;
  void Destroy() override;
  Status EnclaveCallInternal(uint64_t selector,
                             UntrustedParameterStack *params) override;
};

}  // namespace primitives
}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_SGX_UNTRUSTED_SGX_H_
