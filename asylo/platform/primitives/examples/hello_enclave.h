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

#ifndef ASYLO_PLATFORM_PRIMITIVES_EXAMPLES_HELLO_ENCLAVE_H_
#define ASYLO_PLATFORM_PRIMITIVES_EXAMPLES_HELLO_ENCLAVE_H_

#include <cstdint>

#include "asylo/platform/primitives/primitives.h"

namespace asylo {
namespace primitives {

// Entry call selectors: must be distinct from each other
static constexpr uint64_t kAbortEnclaveSelector = kSelectorUser + 1;
static constexpr uint64_t kHelloEnclaveSelector = kSelectorUser + 2;

// Exit call selectors: must be distinct from each other, but can
// overlap with Entry selectors
static constexpr uint64_t kExternalHelloHandler = kSelectorUser + 1;

}  // namespace primitives
}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_EXAMPLES_HELLO_ENCLAVE_H_
