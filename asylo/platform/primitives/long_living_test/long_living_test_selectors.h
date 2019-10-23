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

#ifndef ASYLO_PLATFORM_PRIMITIVES_LONG_LIVING_TEST_LONG_LIVING_TEST_SELECTORS_H_
#define ASYLO_PLATFORM_PRIMITIVES_LONG_LIVING_TEST_LONG_LIVING_TEST_SELECTORS_H_

#include <cstdint>

#include "asylo/platform/primitives/primitives.h"

namespace asylo {
namespace primitives {

// Entry points registered by the enclave.
constexpr uint64_t kLongCall = kSelectorUser + 1;

// Exit points registered by untrusted code.
constexpr uint64_t kSleepForExitCall = kSelectorUser + 1;
constexpr uint64_t kCurrentTimeExitCall = kSelectorUser + 2;

}  // namespace primitives
}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_LONG_LIVING_TEST_LONG_LIVING_TEST_SELECTORS_H_
