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

#ifndef ASYLO_PLATFORM_CORE_ENTRY_SELECTORS_H_
#define ASYLO_PLATFORM_CORE_ENTRY_SELECTORS_H_

#include <cstddef>
#include <cstdint>

#include "asylo/platform/primitives/primitives.h"

namespace asylo {

// Enclave initialization entry point selector.
static constexpr uint64_t kSelectorAsyloInit = primitives::kSelectorUser;

// Enclave run entry point selector.
static constexpr uint64_t kSelectorAsyloRun = primitives::kSelectorUser + 1;

// Enclave finalization entry point selector.
static constexpr uint64_t kSelectorAsyloFini = primitives::kSelectorUser + 2;

}  // namespace asylo

#endif  // ASYLO_PLATFORM_CORE_ENTRY_SELECTORS_H_
