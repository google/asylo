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

#ifndef ASYLO_PLATFORM_PRIMITIVES_REMOTE_UTIL_REMOTE_PROXY_LIB_H_
#define ASYLO_PLATFORM_PRIMITIVES_REMOTE_UTIL_REMOTE_PROXY_LIB_H_

#include <memory>

#include "asylo/enclave.pb.h"
#include "asylo/platform/primitives/untrusted_primitives.h"
#include "asylo/platform/primitives/util/message.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace primitives {

// Factory class declaration, which needs to be implemented with each
// backend to be used as a local enclave client in remote proxy process.
class LocalEnclaveFactory {
 public:
  LocalEnclaveFactory() = delete;

  static StatusOr<std::shared_ptr<Client>> Get(
      MessageWriter *enclave_params,
      std::unique_ptr<Client::ExitCallProvider> exit_call_provider);

 private:
  static StatusOr<EnclaveLoadConfig> ParseEnclaveLoadConfig(
      MessageWriter *enclave_params);
};

}  // namespace primitives
}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_REMOTE_UTIL_REMOTE_PROXY_LIB_H_
