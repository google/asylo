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

#include <cstdint>
#include <string>
#include <vector>

#include "absl/strings/string_view.h"
#include "asylo/identity/platform/sgx/architecture_bits.h"
#include "asylo/identity/sgx/miscselect.pb.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace sgx {

// Masks for various MISCSELECT bits.
constexpr uint32_t kMiscselectExinfoMask =
    static_cast<uint32_t>(1) << static_cast<size_t>(MiscselectBit::EXINFO);

// MISCSELECT bit groupings.
constexpr uint32_t kMiscselectAllBits = kMiscselectExinfoMask;
constexpr uint32_t kMiscselectReservedBits = ~kMiscselectAllBits;

// Tests if |miscselect_bit| is set in the |miscselect| bit vector
// representation of MISCSELECT.
StatusOr<bool> TestMiscselectBit(MiscselectBit miscselect_bit,
                                 uint32_t miscselect);

// Tests if |miscselect_bit| is set in the |miscselect| proto representation of
// MISCSELECT.
StatusOr<bool> TestMiscselectBit(MiscselectBit miscselect_bit,
                                 const Miscselect &miscselect);

// Returns a printable list of MISCSELECT bits from the given |miscselect| bit
// vector representation of MISCSELECT.
std::vector<absl::string_view> GetPrintableMiscselectList(uint32_t miscselect);

// Returns a printable list of MISCSELECT bits from the given |miscselect| proto
// representation of MISCSELECT.
std::vector<absl::string_view> GetPrintableMiscselectList(
    const Miscselect &miscselect);

}  // namespace sgx
}  // namespace asylo

#endif  // ASYLO_IDENTITY_SGX_SECS_MISCSELECT_H_
