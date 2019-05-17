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

#ifndef ASYLO_PLATFORM_PRIMITIVES_SGX_TRUSTED_SGX_H_
#define ASYLO_PLATFORM_PRIMITIVES_SGX_TRUSTED_SGX_H_

// This file declares the trusted runtime interface for SGX.

#include <cstdint>

namespace asylo {
namespace primitives {

// Invokes the registered handler with pointer to parameter stack |params| for
// the trusted entry point designated by |selector|. Returns a non-zero error
// code on failure.
int asylo_enclave_call(uint64_t selector, void *params);

}  // namespace primitives
}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_SGX_TRUSTED_SGX_H_
