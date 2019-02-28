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

#ifndef ASYLO_PLATFORM_PRIMITIVES_SIM_SHARED_SIM_H_
#define ASYLO_PLATFORM_PRIMITIVES_SIM_SHARED_SIM_H_

#include <cstddef>
#include <cstdint>
#include <type_traits>

#include "asylo/platform/primitives/parameter_stack.h"
#include "asylo/platform/primitives/primitive_status.h"

namespace asylo {
namespace primitives {

extern "C" {
// Prototype of the user-defined enclave initialization function.
PrimitiveStatus asylo_enclave_init();

// Prototype of the user-defined enclave finalization function.
PrimitiveStatus asylo_enclave_fini();
}

}  // namespace primitives
}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_SIM_SHARED_SIM_H_
