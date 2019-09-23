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

#ifndef ASYLO_PLATFORM_PRIMITIVES_TEST_TEST_SELECTORS_H_
#define ASYLO_PLATFORM_PRIMITIVES_TEST_TEST_SELECTORS_H_

#include <cstdint>

#include "asylo/platform/primitives/primitives.h"

namespace asylo {
namespace primitives {

// Entry points registered by the enclave.
constexpr uint64_t kAbortEnclaveSelector = kSelectorUser + 1;
constexpr uint64_t kTimesTwoSelector = kSelectorUser + 2;
constexpr uint64_t kTrustedFibonacci = kSelectorUser + 3;
constexpr uint64_t kTrustedMallocTest = kSelectorUser + 4;
constexpr uint64_t kUntrustedLocalAllocTest = kSelectorUser + 5;
constexpr uint64_t kAveragePerThreadSelector = kSelectorUser + 6;
constexpr uint64_t kCopyMultipleParamsSelector = kSelectorUser + 7;
constexpr uint64_t kStressMallocs = kSelectorUser + 8;
constexpr uint64_t kInsideOutsideTest = kSelectorUser + 9;

// Entry point with no registered handler.
constexpr uint64_t kNotRegisteredSelector = kSelectorUser + 100;

// Exit points registered by untrusted code.
constexpr uint64_t kUntrustedInit = kSelectorUser + 1;
constexpr uint64_t kUntrustedFibonacci = kSelectorUser + 2;

}  // namespace primitives
}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_TEST_TEST_SELECTORS_H_
