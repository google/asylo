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

#ifndef ASYLO_PLATFORM_PRIMITIVES_ENCLAVE_LOADER_H_
#define ASYLO_PLATFORM_PRIMITIVES_ENCLAVE_LOADER_H_

#include "asylo/enclave.pb.h"
#include "asylo/platform/primitives/untrusted_primitives.h"

namespace asylo {
namespace primitives {

// Loads an enclave by redirecting enclave load requests to the primitive
// backend indicated by the extension set in the |load_config|.
StatusOr<std::shared_ptr<primitives::Client>> LoadEnclave(
    const EnclaveLoadConfig &load_config);

}  // namespace primitives
}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_ENCLAVE_LOADER_H_
