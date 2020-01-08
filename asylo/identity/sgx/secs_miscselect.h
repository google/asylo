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

#ifndef ASYLO_IDENTITY_SGX_SECS_MISCSELECT_H_
#define ASYLO_IDENTITY_SGX_SECS_MISCSELECT_H_

#include <cstddef>
#include <cstdint>

#include "asylo/identity/platform/sgx/architecture_bits.h"

namespace asylo {
namespace sgx {

// Masks for various MISCSELECT bits.
constexpr uint32_t kMiscselectExinfoMask =
    static_cast<uint32_t>(1) << static_cast<size_t>(MiscselectBit::EXINFO);

// MISCSELECT bit groupings.
constexpr uint32_t kMiscselectAllBits = kMiscselectExinfoMask;
constexpr uint32_t kMiscselectReservedBits = ~kMiscselectAllBits;

}  // namespace sgx
}  // namespace asylo

#endif  // ASYLO_IDENTITY_SGX_SECS_MISCSELECT_H_
