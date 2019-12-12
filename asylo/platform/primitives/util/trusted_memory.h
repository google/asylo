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

#ifndef ASYLO_PLATFORM_PRIMITIVES_UTIL_TRUSTED_MEMORY_H_
#define ASYLO_PLATFORM_PRIMITIVES_UTIL_TRUSTED_MEMORY_H_

#include <memory>

#include "asylo/platform/primitives/trusted_primitives.h"

namespace asylo {
namespace primitives {

// Checks whether |pointer| is not nullptr and points to an object located in
// memory inside the enclave. Returns true if the pointer is valid; false if
// not.
template <typename T>
bool IsValidEnclaveAddress(const T *pointer) {
  return pointer != nullptr &&
         primitives::TrustedPrimitives::IsInsideEnclave(pointer, sizeof(T));
}

// Checks whether |pointer| is not nullptr and points to an object located in
// memory outside the enclave. Returns true if the pointer is valid; false if
// not.
template <typename T>
bool IsValidUntrustedAddress(const T *pointer) {
  return pointer != nullptr &&
         primitives::TrustedPrimitives::IsOutsideEnclave(pointer, sizeof(T));
}

}  // namespace primitives
}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_UTIL_TRUSTED_MEMORY_H_
